"""Fixtures for sending in OAuth mode (WP 3f): the real app on a loopback port, the in-memory
store, Dovecot for the mailboxes and the SMTP sink for the outgoing side."""

from __future__ import annotations

import socket
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
from mcp import Client
from mcp.types import ElicitResult

from tests.http_util import mcp_client, running
from tests.integration.conftest import (  # pyright: ignore[reportPrivateUsage]
    ImapServer,
    Mailbox,
    _msg,
)
from tests.integration.test_drafts import seed
from tests.oauth_util import PASSWORD, FakeLogin, operator
from tests.smtp_sink import SmtpSink
from universal_email_mcp.config import Policy, Settings
from universal_email_mcp.models import TlsSettings
from universal_email_mcp.oauth.app import build_oauth_app
from universal_email_mcp.store import (
    Identity,
    KeyRing,
    MailAccount,
    MemoryBackend,
    SessionPolicy,
    Store,
)

SEND_SCOPE = "mail.read mail.drafts mail.organize mail.send"
SMTP_USER = "smtp-user"
NEW: dict[str, Any] = {"to": ["alice@example.org"], "subject": "Hallo Alice", "body": "Guten Tag!"}


@dataclass
class Answers:
    """Scripted user: what the client's elicitation callback answers, and what it saw."""

    action: str = "accept"
    send: bool = True
    prompts: list[str] = field(default_factory=list[str])

    async def __call__(self, _context: Any, params: Any) -> ElicitResult:
        self.prompts.append(params.message)
        content = {"send": self.send} if self.action == "accept" else None
        return ElicitResult(action=self.action, content=content)  # pyright: ignore[reportArgumentType]


class Clock:
    def __init__(self) -> None:
        self.offset = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset


@dataclass
class User:
    name: str
    id: str
    box: Mailbox
    account: MailAccount
    identity: Identity


@dataclass
class Remote:
    store: Store
    url: str
    server: ImapServer
    sink: SmtpSink
    clock: Clock
    pool: Any
    users: dict[str, User] = field(default_factory=dict[str, User])

    async def user(
        self,
        name: str = "alice",
        *,
        send: bool = True,
        address: str = "me@example.org",
        history: tuple[str, ...] = (),
    ) -> User:
        """A user with a seeded mailbox (Drafts/Sent/INBOX), one account and one identity
        that sends through the sink. ``history``: addresses already written to."""
        box = Mailbox(self.server, f"w{uuid.uuid4().hex[:10]}@example.org")
        seed(box)
        for who in (
            "Anna <anna@huber-bau.at>",
            "alice@example.org",
            "oliver.grant@firma.example",
            *history,
        ):
            sent_to(box, who)
        uid = "u_" + uuid.uuid4().hex[:12]
        await self.store.get_or_create_user(uid, f"{name}@example.org")
        account = await self.store.create(
            MailAccount(
                id="a_" + uuid.uuid4().hex[:12],
                user_id=uid,
                name="Work",
                host=self.server.host,
                preset=self.server.host,
                port=self.server.imaps_port,
                username=box.user,
                password=self.server.password,
                permissions=("read", "drafts", "organize"),
                created_at=datetime.now(UTC),
            )
        )
        identity = await self.store.create(
            Identity(
                id="i_" + uuid.uuid4().hex[:12],
                user_id=uid,
                addresses=(address,),
                display_name="Max Müller",
                smtp_host="localhost",
                smtp_account_id=account.id,
                smtp_port=self.sink.port,
                smtp_tls="starttls",
                smtp_username=SMTP_USER,
                smtp_password=self.server.password,
                copies_account_id=account.id,
                send=send,
                is_default=True,
                created_at=datetime.now(UTC),
            )
        )
        user = User(name, uid, box, account, identity)
        self.users[name] = user
        return user

    async def token(
        self,
        user: User,
        *,
        scope: str = SEND_SCOPE,
        identities: bool = True,
        client: str = "Test Client",
    ) -> tuple[str, str]:
        grant = await self.store.create_grant(
            user_id=user.id,
            client_id="test-client",
            client_name=client,
            account_ids=[user.account.id],
            account_scopes={user.account.id: "read drafts organize"},
            identity_ids=[user.identity.id] if identities else [],
            scope=scope,
        )
        issued = await self.store.issue_tokens(grant, resource=self.url + "/mcp")
        return issued.access_token, grant.id

    def client(
        self,
        token: str,
        mode: str = "auto",
        answers: Answers | None = None,
        transport: Any = None,
    ) -> Client:
        return mcp_client(
            self.url + "/mcp", token, mode=mode, elicitation_callback=answers, transport=transport
        )

    async def portal(self, user: User, *, fresh: bool = True) -> httpx2.AsyncClient:
        """A signed-in browser for the user (session created through the store)."""
        raw, _rec = await self.store.create_portal_session(user.id, fresh_login=fresh)
        client = httpx2.AsyncClient(base_url=self.url, timeout=60)
        client.cookies.set("uem_session", raw)
        client.cookies.set("uem_csrf", "c" * 40)
        return client


def sent_to(mb: Mailbox, to: str) -> None:
    c = mb.admin()
    try:
        raw = _msg("Früher", "me@example.org", "x").replace(
            b"To: alice@example.org", f"To: {to}".encode()
        )
        c.append("Sent", raw, flags=[b"\\Seen"])
    finally:
        c.logout()


def post(client: httpx2.AsyncClient, path: str, **data: str) -> Any:
    return client.post(path, data={"csrf_token": "c" * 40, **data})


@asynccontextmanager
async def remote(
    imap_server: ImapServer,
    *,
    policy: Policy | None = None,
    approval_ttl: timedelta | None = None,
) -> AsyncIterator[Remote]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    clock = Clock()
    store = Store(
        MemoryBackend(),
        KeyRing({"k1": b"k" * 32}),
        clock=clock,
        policy=SessionPolicy(approval_ttl=approval_ttl or timedelta(minutes=10)),
    )
    op = operator(
        public_url=f"http://127.0.0.1:{port}",
        allowed_hosts=("127.0.0.1",),
        allowed_origins=(f"http://127.0.0.1:{port}",),
        settings=Settings(allow_private_networks=True, connect_timeout=5, read_timeout=15),
        policy=policy or Policy(send="confirm", send_fallback="portal"),
    )
    with SmtpSink(user=SMTP_USER, password=imap_server.password) as sink:
        app = await build_oauth_app(
            op, store=store, login=FakeLogin(), mail_tls=TlsSettings(verify=False)
        )
        async with running(app, sock) as url:
            yield Remote(store, url, imap_server, sink, clock, app.state.user_pool)


__all__ = [
    "NEW",
    "PASSWORD",
    "SEND_SCOPE",
    "Answers",
    "Remote",
    "User",
    "post",
    "remote",
    "sent_to",
]
