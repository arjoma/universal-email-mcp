"""Record types of the store (design section 10).

All records are frozen dataclasses. ``version`` is the optimistic-concurrency counter: 0 on a
record that was never stored, 1 after ``create()``, +1 on every ``update()``; an update with a
stale version raises ``StoreConflict``. ``KIND`` is the collection name; ``SEALED`` lists the
fields that are stored encrypted (one AES-GCM blob per record, bound to user, kind, id).
Fields that hold secrets or personal data are ``repr=False`` so they never reach logs.

Nothing here holds mail content. Bearer tokens (portal session, authorization code, access
and refresh token) are never stored: the record id is the SHA-256 digest of the token.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar


@dataclass(frozen=True, slots=True, kw_only=True)
class Record:
    KIND: ClassVar[str]
    SEALED: ClassVar[tuple[str, ...]] = ()
    EXPORT_EXCLUDE: ClassVar[tuple[str, ...]] = ()
    """Fields left out of ``export_user`` (credentials, token digests)."""

    id: str
    version: int = 0

    @property
    def owner(self) -> str:
        """The user this record belongs to ("" for shared records such as OAuth clients)."""
        return getattr(self, "user_id", "")


@dataclass(frozen=True, slots=True, kw_only=True)
class User(Record):
    """``id`` is the pseudonym (HMAC of the normalised primary address, see design section 9)."""

    KIND: ClassVar[str] = "users"
    SEALED: ClassVar[tuple[str, ...]] = ("primary_address", "settings")

    primary_address: str = field(repr=False)
    settings: dict[str, Any] = field(default_factory=dict[str, Any], repr=False)
    default_identity_id: str = ""
    created_at: datetime

    @property
    def owner(self) -> str:
        return self.id


@dataclass(frozen=True, slots=True, kw_only=True)
class MailAccount(Record):
    """One incoming mailbox. Server profile is plain, login name and password are sealed."""

    KIND: ClassVar[str] = "accounts"
    SEALED: ClassVar[tuple[str, ...]] = ("username", "password")
    EXPORT_EXCLUDE: ClassVar[tuple[str, ...]] = ("password",)

    user_id: str
    name: str
    protocol: str = "imap"
    """``imap`` or ``pop3``."""
    host: str
    port: int
    tls: str = "implicit"
    """``implicit`` or ``starttls``."""
    preset: str = ""
    username: str = field(repr=False)
    password: str = field(repr=False)
    permissions: tuple[str, ...] = ("read",)
    display_name: str = ""
    created_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class Identity(Record):
    """A sender. Everything personal and the SMTP login are sealed; host and port are plain."""

    KIND: ClassVar[str] = "identities"
    SEALED: ClassVar[tuple[str, ...]] = (
        "addresses",
        "display_name",
        "signature",
        "smtp_username",
        "smtp_password",
    )
    EXPORT_EXCLUDE: ClassVar[tuple[str, ...]] = ("smtp_password",)

    user_id: str
    addresses: tuple[str, ...] = field(repr=False)
    display_name: str = field(default="", repr=False)
    signature: str = field(default="", repr=False)
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_tls: str = "implicit"
    smtp_username: str = field(default="", repr=False)
    smtp_password: str = field(default="", repr=False)
    copies_account_id: str = ""
    """Account that receives this identity's Drafts and Sent copies ("" = none)."""
    is_default: bool = False
    created_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class PortalSession(Record):
    """Browser session of the portal. ``id`` is the SHA-256 digest of the cookie value."""

    KIND: ClassVar[str] = "portal_sessions"
    EXPORT_EXCLUDE: ClassVar[tuple[str, ...]] = ("id",)

    user_id: str
    created_at: datetime
    last_seen: datetime
    reauth_at: datetime | None = None
    """Last password re-entry (for sensitive actions)."""
    expires_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class OAuthClient(Record):
    """An MCP client: ``id`` is the CIMD URL or the DCR client id. Expires when unused."""

    KIND: ClassVar[str] = "oauth_clients"

    name: str = ""
    redirect_uris: tuple[str, ...] = ()
    registration: str = "cimd"
    """``cimd`` or ``dcr``."""
    created_at: datetime
    last_used: datetime
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class AuthCode(Record):
    """Authorization code, single use. ``id`` is the SHA-256 digest of the code."""

    KIND: ClassVar[str] = "auth_codes"
    EXPORT_EXCLUDE: ClassVar[tuple[str, ...]] = ("id",)

    user_id: str
    client_id: str
    grant_id: str
    redirect_uri: str
    code_challenge: str
    resource: str = ""
    scope: str = ""
    expires_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class Grant(Record):
    """A connected AI client ("session" of design section 10): what it may use.

    ``expires_at`` is the sliding expiry (refresh lifetime, capped by
    ``absolute_expires_at``); a freshly created grant lives only a few minutes until tokens
    are issued for it. ``last_used`` is None until then.
    """

    KIND: ClassVar[str] = "grants"

    user_id: str
    client_id: str
    client_name: str = ""
    account_ids: tuple[str, ...] = ()
    identity_ids: tuple[str, ...] = ()
    scope: str = ""
    created_at: datetime
    last_used: datetime | None = None
    absolute_expires_at: datetime | None = None
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Token(Record):
    """Access or refresh token. ``id`` is the SHA-256 digest of the token."""

    KIND: ClassVar[str] = "tokens"
    EXPORT_EXCLUDE: ClassVar[tuple[str, ...]] = ("id",)

    user_id: str
    grant_id: str
    client_id: str
    token_type: str
    """``access`` or ``refresh``."""
    resource: str = ""
    scope: str = ""
    consumed: bool = False
    """A rotated refresh token stays (until its expiry) to detect replay."""
    created_at: datetime
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class PendingApproval(Record):
    """A send waiting for browser approval (design section 8). Short-lived."""

    KIND: ClassVar[str] = "approvals"
    SEALED: ClassVar[tuple[str, ...]] = ("draft_ref",)

    user_id: str
    grant_id: str
    identity_id: str
    content_hash: str
    draft_ref: str = field(repr=False)
    """Sealed reference to the draft (never the mail text)."""
    status: str = "pending"
    """``pending``, ``approved`` or ``declined``."""
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ActivityEntry(Record):
    """One event of the own-activity feed (design section 9). Counts and names, no mail data."""

    KIND: ClassVar[str] = "activity"
    SEALED: ClassVar[tuple[str, ...]] = ("event", "client", "tool", "account", "outcome", "counts")

    user_id: str
    at: datetime
    event: str = field(repr=False)
    client: str = field(default="", repr=False)
    tool: str = field(default="", repr=False)
    account: str = field(default="", repr=False)
    """Account *name* the user chose, never an address."""
    outcome: str = field(default="", repr=False)
    counts: dict[str, int] = field(default_factory=dict[str, int], repr=False)
    expires_at: datetime


ALL_RECORDS: tuple[type[Record], ...] = (
    User,
    MailAccount,
    Identity,
    PortalSession,
    OAuthClient,
    AuthCode,
    Grant,
    Token,
    PendingApproval,
    ActivityEntry,
)
USER_OWNED: tuple[type[Record], ...] = tuple(r for r in ALL_RECORDS if r not in (User, OAuthClient))
"""Record types carrying a ``user_id`` field."""
