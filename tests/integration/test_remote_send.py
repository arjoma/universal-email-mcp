"""Sending in OAuth mode (WP 3f), end to end: the real app, Dovecot, the SMTP sink.

Covers the tool surface per grant, confirmation by elicitation (2026-07-28), forged / replayed
/ expired / foreign ``requestState``, the three fallbacks, the shared rate limit, the audit
trail and the pending-approvals page (approve, reject, expired, changed draft, another user's
approval, re-authentication, CSRF).
"""

from __future__ import annotations

import email
import email.policy
import itertools
import json
import logging
import re
import types
from datetime import timedelta
from email.message import EmailMessage
from typing import Any

import httpx2
import pytest

from tests.integration.conftest import ImapServer, Mailbox
from tests.integration.remote_send_util import (
    NEW,
    Answers,
    Remote,
    User,
    post,
    remote,
)
from universal_email_mcp.audit import LOGGER_NAME
from universal_email_mcp.config import Policy
from universal_email_mcp.store import PendingApproval

pytestmark = pytest.mark.integration

MODERN = "2026-07-28"
LOOKALIKE = "oliver.grnat@firma.example"
STRANGER = "stranger@nowhere.example"


# ---------------------------------------------------------------- helpers


def text(result: Any) -> str:
    return "\n".join(b.text for b in result.content if hasattr(b, "text"))


def folder(mb: Mailbox, name: str) -> list[tuple[tuple[str, ...], EmailMessage]]:
    c = mb.admin()
    try:
        try:
            c.select_folder(name, readonly=True)
        except Exception:  # noqa: BLE001
            return []
        uids = c.search("ALL")
        got: dict[int, dict[bytes, Any]] = (
            c.fetch(uids, ["FLAGS", "BODY.PEEK[]"]) if uids else {}  # pyright: ignore[reportAssignmentType]
        )
        out: list[tuple[tuple[str, ...], EmailMessage]] = []
        for uid in sorted(got):
            msg = email.message_from_bytes(got[uid][b"BODY[]"], policy=email.policy.default)
            assert isinstance(msg, EmailMessage)
            out.append((tuple(f.decode() for f in got[uid][b"FLAGS"]), msg))
        return out
    finally:
        c.logout()


def subjects(mb: Mailbox, name: str) -> list[str]:
    return [str(m["Subject"]) for _f, m in folder(mb, name)]


async def send(r: Remote, token: str, args: dict[str, Any] | None = None, **kw: Any) -> Any:
    answers = kw.pop("answers", None)
    mode = kw.pop("mode", MODERN)
    async with r.client(token, mode, answers) as c:
        res = await c.call_tool("send_message", args or NEW)
    return res


def data_of(res: Any) -> dict[str, Any]:
    assert not res.is_error, text(res)
    assert res.structured_content is not None
    return res.structured_content


class Raw:
    """Hand-made 2026-07-28 requests, to forge, replay and mix up ``requestState``."""

    def __init__(self, url: str, token: str) -> None:
        self.url, self.token = url + "/mcp", token
        self.ids = itertools.count(1)

    async def call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        state: str | None = None,
        answers: dict[str, Any] | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "name": name,
            "arguments": arguments,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MODERN,
                "io.modelcontextprotocol/clientInfo": {"name": "raw", "version": "1"},
                "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
            },
        }
        if state is not None:
            params["requestState"] = state
        if answers is not None:
            params["inputResponses"] = answers
        body = {"jsonrpc": "2.0", "id": next(self.ids), "method": "tools/call", "params": params}
        headers = {
            "Authorization": f"Bearer {token or self.token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MODERN,
            "MCP-Method": "tools/call",
            "MCP-Name": name,
        }
        async with httpx2.AsyncClient(timeout=60) as http:
            resp = await http.post(self.url, json=body, headers=headers)
        raw = resp.text
        if resp.headers.get("content-type", "").startswith("text/event-stream"):
            raw = next(ln[5:] for ln in raw.splitlines() if ln.startswith("data:"))
        return json.loads(raw)

    async def ask(self, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        """Round one: the question and the sealed state that comes with it."""
        first = await self.call("send_message", arguments)
        result = first["result"]
        assert result["resultType"] == "input_required", first
        return result["requestState"], result["inputRequests"]

    @staticmethod
    def accept(requests: dict[str, Any]) -> dict[str, Any]:
        return {k: {"action": "accept", "content": {"send": True}} for k in requests}


def tweak(token: str) -> str:
    """The same token with one character changed in the middle."""
    mid = len(token) // 2
    return token[:mid] + ("A" if token[mid] != "A" else "B") + token[mid + 1 :]


# ---------------------------------------------------------------- tool surface


async def refused(c: Any, tool: str, args: dict[str, Any]) -> bool:
    try:
        res = await c.call_tool(tool, args)
    except Exception:  # noqa: BLE001
        return True
    return bool(res.is_error)


async def test_send_follows_grant_identity_and_policy(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        full, _ = await r.token(u)
        no_send_scope, _ = await r.token(u, scope="mail.read mail.drafts", identities=False)
        scope_but_no_identity, _ = await r.token(u, identities=False)
        async with r.client(full) as c:
            assert "send_message" in {t.name for t in (await c.list_tools()).tools}
            assert "send_message" in (c.instructions or "")
        for token in (no_send_scope, scope_but_no_identity):
            async with r.client(token) as c:
                assert "send_message" not in {t.name for t in (await c.list_tools()).tools}
                assert "save_draft" in {t.name for t in (await c.list_tools()).tools}
                assert "send_message" not in (c.instructions or "")
                assert await refused(c, "send_message", NEW)
        assert r.sink.messages == []
        # the identity itself must allow sending
        quiet = await r.user("quiet", send=False)
        token, _ = await r.token(quiet)
        async with r.client(token) as c:
            assert "send_message" not in {t.name for t in (await c.list_tools()).tools}
            assert await refused(c, "send_message", NEW)
        assert r.sink.messages == []


@pytest.mark.parametrize("policy", [Policy(send="off"), Policy(read_only=True)])
async def test_operator_policy_switches_sending_off(imap_server: ImapServer, policy: Policy):
    async with remote(imap_server, policy=policy) as r:
        u = await r.user()
        token, _ = await r.token(u)
        async with r.client(token) as c:
            assert "send_message" not in {t.name for t in (await c.list_tools()).tools}
            assert await refused(c, "send_message", NEW)
        assert r.sink.messages == []


async def test_a_changed_identity_takes_effect_on_the_next_call(imap_server: ImapServer):
    from dataclasses import replace

    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        async with r.client(token) as c:
            assert "send_message" in {t.name for t in (await c.list_tools()).tools}
            await r.store.update(replace(u.identity, send=False))
            assert "send_message" not in {t.name for t in (await c.list_tools()).tools}
            assert await refused(c, "send_message", NEW)
        assert r.sink.messages == []


# ---------------------------------------------------------------- confirmation by elicitation


async def test_accepted_confirmation_sends_and_files_the_mail(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        answers = Answers()
        d = data_of(await send(r, token, answers=answers))
        assert d["status"] == "sent" and d["confirmation"] == "asked" and d["draft_id"] is None
        (got,) = r.sink.messages
        assert got.mail_from == "me@example.org" and got.rcpt_to == ["alice@example.org"]
        assert got.authenticated and got.encrypted
        (prompt,) = answers.prompts
        assert "To: alice@example.org  [written to before]" in prompt
        assert re.search(r"Content fingerprint [0-9a-f]{16}\b", prompt)
        assert "Hallo Alice" in subjects(u.box, "Sent") and subjects(u.box, "Drafts") == []


async def test_declined_cancelled_or_unticked_confirmation_sends_nothing(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        for action, tick in (("decline", True), ("cancel", True), ("accept", False)):
            d = data_of(await send(r, token, answers=Answers(action=action, send=tick)))
            assert d["status"] == "declined" and d["sent"] is False and d["draft_id"]
        assert r.sink.messages == []
        assert subjects(u.box, "Drafts").count("Hallo Alice") == 3


async def test_a_legacy_http_client_cannot_be_asked_and_gets_the_fallback(imap_server: ImapServer):
    """Legacy protocol over stateless HTTP has no back channel: even a client that
    declares elicitation is never asked; the fallback decides (here: the portal)."""
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        answers = Answers()
        d = data_of(await send(r, token, mode="legacy", answers=answers))
        assert d["status"] == "pending_approval" and d["confirmation"] == "unavailable"
        assert answers.prompts == [] and r.sink.messages == []


# ---------------------------------------------------------------- request state


async def test_a_forged_confirmation_state_is_refused(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        raw = Raw(r.url, token)
        state, requests = await raw.ask(NEW)
        answers = raw.accept(requests)
        forged = [
            tweak(state),  # one flipped character
            state[:-8],  # truncated
            "v1." + "A" * 60,  # well-formed prefix, no seal
            "plain",  # not a token at all
            json.dumps({"s": {"outcomes": {}}}),  # the SDK's inner format, unsealed
        ]
        for bad in forged:
            reply = await raw.call("send_message", NEW, state=bad, answers=answers)
            assert reply["error"]["message"] == "Invalid or expired requestState", bad
        assert r.sink.messages == []
        # the genuine state works - proving the attempts above failed because of the seal
        ok = await raw.call("send_message", NEW, state=state, answers=answers)
        assert ok["result"]["structuredContent"]["status"] == "sent"
        assert len(r.sink.messages) == 1


async def test_an_answer_without_a_state_does_not_send(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        raw = Raw(r.url, token)
        _state, requests = await raw.ask(NEW)
        # claim "accepted" without ever having been asked: the server asks again
        reply = await raw.call("send_message", NEW, answers=raw.accept(requests))
        assert reply["result"]["resultType"] == "input_required"
        assert r.sink.messages == []


async def test_a_replayed_state_sends_only_once(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        raw = Raw(r.url, token)
        state, requests = await raw.ask(NEW)
        answers = raw.accept(requests)
        first = await raw.call("send_message", NEW, state=state, answers=answers)
        assert first["result"]["structuredContent"]["status"] == "sent"
        again = await raw.call("send_message", NEW, state=state, answers=answers)
        assert again["result"]["isError"] is True
        assert "ALREADY_SENT" in json.dumps(again)
        assert len(r.sink.messages) == 1


async def test_a_state_for_other_arguments_is_refused(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        raw = Raw(r.url, token)
        state, requests = await raw.ask(NEW)
        other = {**NEW, "to": [STRANGER], "subject": "Something else"}
        reply = await raw.call("send_message", other, state=state, answers=raw.accept(requests))
        assert reply["error"]["message"] == "Invalid or expired requestState"
        assert r.sink.messages == []


async def test_an_expired_state_is_refused(
    imap_server: ImapServer, monkeypatch: pytest.MonkeyPatch
):
    import time as real_time

    import mcp.server.request_state as rs

    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        raw = Raw(r.url, token)
        state, requests = await raw.ask(NEW)
        later = types.SimpleNamespace(time=lambda: real_time.time() + 3_600)
        monkeypatch.setattr(rs, "time", later)
        reply = await raw.call("send_message", NEW, state=state, answers=raw.accept(requests))
        assert reply["error"]["message"] == "Invalid or expired requestState"
        assert r.sink.messages == []
        monkeypatch.undo()  # control: within its lifetime the very same state is good
        ok = await raw.call("send_message", NEW, state=state, answers=raw.accept(requests))
        assert ok["result"]["structuredContent"]["status"] == "sent"


async def test_a_state_of_another_user_or_grant_is_refused(imap_server: ImapServer):
    async with remote(imap_server) as r:
        alice = await r.user("alice")
        bob = await r.user("bob")
        t_alice, _ = await r.token(alice)
        t_alice_2, _ = await r.token(alice, client="Other app")  # same user, other grant
        t_bob, _ = await r.token(bob)
        state, requests = await Raw(r.url, t_alice).ask(NEW)
        for stolen in (t_bob, t_alice_2):
            reply = await Raw(r.url, stolen).call(
                "send_message", NEW, state=state, answers=Raw.accept(requests)
            )
            assert reply["error"]["message"] == "Invalid or expired requestState"
        assert r.sink.messages == []
        own = Raw(r.url, t_alice)  # control: the owner's own client can use it
        ok = await own.call("send_message", NEW, state=state, answers=Raw.accept(requests))
        assert ok["result"]["structuredContent"]["status"] == "sent"


async def test_a_draft_that_changes_between_the_rounds_asks_again(imap_server: ImapServer):
    """The answer counts for the question that was shown: the question names the content."""
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        raw = Raw(r.url, token)
        async with r.client(token) as c:
            saved = (await c.call_tool("save_draft", NEW)).structured_content
            assert saved is not None
            first_id = saved["id"]
            state, requests = await raw.ask({"draft_id": first_id})
            # the user's mail client replaces the draft with other text (new UID, new id)
            body = {**NEW, "body": "Ganz anderer Text", "draft_id": first_id}
            changed = await c.call_tool("save_draft", body)
            assert changed.structured_content is not None
            new_id = changed.structured_content["id"]
        # the old id is gone: nothing to send
        answers = raw.accept(requests)
        reply = await raw.call("send_message", {"draft_id": first_id}, state=state, answers=answers)
        assert r.sink.messages == [] and reply["result"]["isError"] is True
        # a state minted for one draft id is no good for another
        again = await raw.call("send_message", {"draft_id": new_id}, state=state, answers=answers)
        assert again["error"]["message"] == "Invalid or expired requestState"
        assert r.sink.messages == []


# ---------------------------------------------------------------- fallbacks


async def waiting(r: Remote, u: User) -> list[PendingApproval]:
    """The user's approvals (not the replay markers that share the collection)."""
    rows = await r.store.list_for_user(PendingApproval, u.id)
    return [a for a in rows if a.status != "sent"]


def policy(send: str = "confirm", fallback: str = "portal", **kw: Any) -> Policy:
    return Policy(send=send, send_fallback=fallback, **kw)  # pyright: ignore[reportArgumentType]


async def test_fallback_draft_keeps_the_draft(imap_server: ImapServer):
    async with remote(imap_server, policy=policy(fallback="draft")) as r:
        u = await r.user()
        token, _ = await r.token(u)
        d = data_of(await send(r, token, mode="legacy"))
        assert d["status"] == "draft_kept" and d["confirmation"] == "unavailable"
        assert d["approval_url"] is None and d["draft_id"]
        assert r.sink.messages == [] and subjects(u.box, "Drafts") == ["Hallo Alice"]
        assert await waiting(r, u) == []


async def test_fallback_portal_always_waits_for_the_user(imap_server: ImapServer):
    async with remote(imap_server, policy=policy(fallback="portal")) as r:
        u = await r.user()
        token, grant_id = await r.token(u)
        links: list[str] = []
        for mode in ("legacy", MODERN):  # modern but without elicitation: same
            res = await send(r, token, mode=mode)
            d = data_of(res)
            assert d["status"] == "pending_approval" and d["sent"] is False
            assert d["approval_url"].startswith(r.url + "/portal/approvals/a_")
            assert d["approval_expires_minutes"] == 10 and d["draft_id"]
            assert "NOT sent yet" in text(res) and d["approval_url"] in text(res)
            links.append(d["approval_url"])
        assert r.sink.messages == []
        # the same message asked for again is the same approval
        assert links[0] == links[1]
        (approval,) = await waiting(r, u)
        assert approval.grant_id == grant_id and approval.status == "pending"
        assert approval.identity_id == u.identity.id
        assert subjects(u.box, "Drafts").count("Hallo Alice") == 2


async def test_a_client_cannot_flood_the_approvals(
    imap_server: ImapServer, monkeypatch: pytest.MonkeyPatch
):
    import universal_email_mcp.service.remote_send as rsend

    monkeypatch.setattr(rsend, "MAX_PENDING_APPROVALS", 2)
    async with remote(imap_server, policy=policy(fallback="portal")) as r:
        u = await r.user()
        token, _ = await r.token(u)
        for n in (1, 2):
            d = data_of(await send(r, token, {**NEW, "subject": f"Nr {n}"}, mode="legacy"))
            assert d["status"] == "pending_approval"
        res = await send(r, token, {**NEW, "subject": "Nr 3"}, mode="legacy")
        assert res.is_error and "RATE_LIMITED" in json.dumps(res.structured_content or text(res))
        assert len(await waiting(r, u)) == 2 and r.sink.messages == []


async def test_fallback_send_unless_flagged(imap_server: ImapServer):
    pol = policy(send="on", fallback="send-unless-flagged")
    async with remote(imap_server, policy=pol) as r:
        u = await r.user(history=("bob@example.com",))
        token, _ = await r.token(u)
        # a known recipient goes out directly
        d = data_of(await send(r, token, mode="legacy"))
        assert d["status"] == "sent" and d["confirmation"] == "not_needed"
        # policy "confirm" + known recipient + a client that cannot ask: sent by the fallback
    pol = policy(send="confirm", fallback="send-unless-flagged")
    async with remote(imap_server, policy=pol) as r:
        u = await r.user()
        token, _ = await r.token(u)
        d = data_of(await send(r, token, mode="legacy"))
        assert d["status"] == "sent" and d["confirmation"] == "fallback"
        assert len(r.sink.messages) == 1
        # a new address is flagged: the portal, nothing sent
        d = data_of(await send(r, token, {**NEW, "to": [STRANGER]}, mode="legacy"))
        assert d["status"] == "pending_approval" and d["recipients"][0]["class"] == "new"
        # a look-alike of a known address is flagged as well - never sent without a human
        d = data_of(await send(r, token, {**NEW, "to": [LOOKALIKE]}, mode="legacy"))
        assert d["status"] == "pending_approval" and d["recipients"][0]["class"] == "lookalike"
        assert len(r.sink.messages) == 1
        assert len(await waiting(r, u)) == 2


async def test_a_lookalike_is_never_sent_unasked_even_when_the_policy_is_on(
    imap_server: ImapServer,
):
    async with remote(imap_server, policy=policy(send="on", fallback="send-unless-flagged")) as r:
        u = await r.user()
        token, _ = await r.token(u)
        args = {**NEW, "to": [LOOKALIKE]}
        answers = Answers()
        d = data_of(await send(r, token, args, answers=answers))  # a client that can be asked
        assert d["status"] == "sent" and len(answers.prompts) == 1
        assert "LOOK-ALIKE" in answers.prompts[0]
        d = data_of(await send(r, token, {**args, "subject": "Zwei"}, mode="legacy"))
        assert d["status"] == "pending_approval"
        assert len(r.sink.messages) == 1


# ---------------------------------------------------------------- rate limit and audit


async def test_send_rate_limit_is_per_user_and_shared_by_all_grants(imap_server: ImapServer):
    async with remote(imap_server, policy=policy(max_sends_per_hour=1)) as r:
        u = await r.user()
        t1, _ = await r.token(u)
        t2, _ = await r.token(u, client="Second app")
        other = await r.user("other")
        t3, _ = await r.token(other)
        assert data_of(await send(r, t1, answers=Answers()))["status"] == "sent"
        res = await send(r, t2, {**NEW, "subject": "Zwei"}, answers=Answers())
        assert res.is_error and "RATE_LIMITED" in json.dumps(res.structured_content or text(res))
        assert data_of(await send(r, t3, answers=Answers()))["status"] == "sent"  # other user
        assert len(r.sink.messages) == 2
        r.clock.offset = timedelta(hours=1, minutes=1)
        t4, _ = await r.token(u)  # the old tokens ran out with the clock
        assert data_of(await send(r, t4, {**NEW, "subject": "Drei"}, answers=Answers()))["sent"]


async def test_audit_events_carry_no_addresses_or_subjects(
    imap_server: ImapServer, caplog: pytest.LogCaptureFixture
):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        args = {**NEW, "subject": "GEHEIMBETREFF", "body": "GEHEIMTEXT"}
        await send(r, token, args, answers=Answers())
        await send(r, token, {**args, "to": [STRANGER]}, mode="legacy")
        approval = (await waiting(r, u))[0]
        browser = await r.portal(u)
        await post(browser, f"/portal/approvals/{approval.id}", action="reject")
    audit_text = "\n".join(rec.getMessage() for rec in caplog.records if rec.name == LOGGER_NAME)
    assert '"event":"send.sent"' in audit_text and '"event":"send.approval_requested"' in audit_text
    assert '"event":"approval.rejected"' in audit_text
    for secret in ("alice@", "example.org", "stranger", "GEHEIM", "Hallo", u.box.user, "Max"):
        assert secret not in audit_text, secret
    assert approval.id in audit_text


# ---------------------------------------------------------------- the approvals page


async def pending(
    r: Remote, u: User, token: str, args: dict[str, Any] | None = None
) -> tuple[str, str]:
    """Park a send in the portal; returns (approval id, URL path)."""
    d = data_of(await send(r, token, args, mode="legacy"))
    assert d["status"] == "pending_approval", d
    url = d["approval_url"]
    return url.rsplit("/", 1)[1], url.removeprefix(r.url)


async def test_the_page_shows_the_message_and_approving_sends_exactly_it(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        args = {
            **NEW,
            "to": ["alice@example.org", STRANGER],
            "subject": "Angebot <b>fett</b>",
            "body": "Zeile 1\n<script>alert(1)</script>\nhttp://evil.example/x",
        }
        aid, path = await pending(r, u, token, args)
        browser = await r.portal(u)
        listing = await browser.get("/portal/approvals")
        assert listing.status_code == 200 and f"/portal/approvals/{aid}" in listing.text
        assert "Waiting for you" in listing.text
        page = await browser.get(path)
        assert page.status_code == 200
        html = page.text
        assert "me@example.org" in html and "alice＠" not in html
        assert "alice@example.org" in html and "NEW - never written to" in html
        assert STRANGER in html and "written to before" in html
        # escaped, never live markup; links defanged
        assert "<script" not in html and "‹script›alert(1)" in html
        assert "Angebot &lt;b&gt;fett&lt;/b&gt;" in html
        assert "http://evil.example/x" not in html
        assert r.sink.messages == []
        # approve (fresh session from the helper): the stored draft goes out
        res = await post(browser, path, action="approve")
        assert res.status_code == 200 and "The message was sent" in res.text
        (got,) = r.sink.messages
        assert got.rcpt_to == ["alice@example.org", STRANGER]
        msg = email.message_from_bytes(got.data, policy=email.policy.default)
        assert msg["Subject"] == "Angebot <b>fett</b>" and "Zeile 1" in msg.get_content()
        assert "Angebot <b>fett</b>" in subjects(u.box, "Sent")
        assert subjects(u.box, "Drafts") == []
        # single use: a second approve (double click, replay) neither sends nor errors out
        again = await post(browser, path, action="approve")
        assert again.status_code in (404, 409) and len(r.sink.messages) == 1
        assert await waiting(r, u) == []  # consumed


async def test_a_reply_draft_shows_the_new_text_and_folds_the_quote(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        async with r.client(token) as c:
            found = await c.call_tool(
                "find_messages", {"accounts": ["Work"], "folders": ["INBOX"], "since": "2000-01-01"}
            )
            assert found.structured_content is not None
            mid = next(
                m["id"] for m in found.structured_content["messages"] if m["subject"] == "Angebot"
            )
        aid, path = await pending(r, u, token, {"reply_to_id": mid, "body": "Gerne, anbei."})
        page = (await (await r.portal(u)).get(path)).text
        assert "Gerne, anbei." in page
        assert "<details>" in page and "Quoted text" in page


async def test_reject_leaves_the_draft_and_sends_nothing(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        aid, path = await pending(r, u, token)
        browser = await r.portal(u)
        res = await post(browser, path, action="reject")
        assert res.status_code == 303 and res.headers["location"].startswith("/portal/approvals")
        assert r.sink.messages == [] and subjects(u.box, "Drafts") == ["Hallo Alice"]
        page = (await browser.get(path)).text
        assert "You rejected this message" in page and "Send this message" not in page
        # a rejected approval can no longer be approved
        late = await post(browser, path, action="approve")
        assert late.status_code == 409 and r.sink.messages == []


async def test_an_expired_approval_is_shown_as_expired_and_cannot_be_approved(
    imap_server: ImapServer,
):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        aid, path = await pending(r, u, token)
        r.clock.offset = timedelta(minutes=11)
        browser = await r.portal(u)
        assert "Expired" in (await browser.get("/portal/approvals")).text
        page = await browser.get(path)
        assert page.status_code == 200 and "has expired" in page.text
        assert "Send this message" not in page.text
        res = await post(browser, path, action="approve")
        assert res.status_code == 409 and r.sink.messages == []


async def test_an_approval_of_another_user_does_not_exist(imap_server: ImapServer):
    async with remote(imap_server) as r:
        alice, bob = await r.user("alice"), await r.user("bob")
        token, _ = await r.token(alice)
        aid, path = await pending(r, alice, token)
        mallory = await r.portal(bob)
        assert (await mallory.get(path)).status_code == 404
        assert (await post(mallory, path, action="approve")).status_code == 404
        assert (await post(mallory, path, action="reject")).status_code == 404
        assert aid not in (await mallory.get("/portal/approvals")).text
        assert r.sink.messages == []
        # still pending for the owner
        (rec,) = await waiting(r, alice)
        assert rec.status == "pending"


async def test_approving_needs_a_recent_password_entry_and_the_csrf_token(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        aid, path = await pending(r, u, token)
        stale = await r.portal(u, fresh=False)
        # the page itself can be read, approving needs the password again
        assert (await stale.get(path)).status_code == 200
        res = await post(stale, path, action="approve")
        assert res.status_code == 303 and res.headers["location"].startswith("/portal/reauth")
        assert r.sink.messages == []
        # rejecting needs no re-entry
        # (not done here: the approval is still needed below)
        # no CSRF token: refused
        nocsrf = await stale.post(path, data={"action": "approve"})
        assert nocsrf.status_code == 403 and r.sink.messages == []
        # after the password entry the same page sends
        raw, _rec = await r.store.create_portal_session(u.id, fresh_login=True)
        fresh = await r.portal(u)
        assert (await post(fresh, path, action="approve")).status_code == 200
        assert len(r.sink.messages) == 1


async def test_a_draft_that_was_replaced_cannot_be_approved(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        aid, path = await pending(r, u, token)
        # the user's mail client edits the draft: a new message with a new UID replaces it
        c = u.box.admin()
        try:
            c.select_folder("Drafts")
            c.delete_messages(c.search("ALL"))
            c.expunge()
            raw = folder(u.box, "Sent")  # any content will do; use a fresh draft text
            _ = raw
            c.append(
                "Drafts",
                b"From: me@example.org\r\nTo: stranger@nowhere.example\r\nSubject: Umgeschrieben\r\n"
                b"Date: Fri, 09 Oct 2026 10:00:00 +0000\r\nMessage-ID: <x@example.org>\r\n\r\nNeu",
                flags=[b"\\Draft"],
            )
        finally:
            c.logout()
        browser = await r.portal(u)
        page = await browser.get(path)
        assert "no longer exists" in page.text or "has changed" in page.text
        assert "Send this message" not in page.text
        res = await post(browser, path, action="approve")
        assert res.status_code == 409 and r.sink.messages == []


async def test_an_approval_with_a_wrong_content_hash_is_refused(imap_server: ImapServer):
    from dataclasses import replace

    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        aid, path = await pending(r, u, token)
        rec = await r.store.get(PendingApproval, aid)
        assert rec is not None
        await r.store.update(replace(rec, content_hash="0" * 64))
        browser = await r.portal(u)
        assert "has changed" in (await browser.get(path)).text
        res = await post(browser, path, action="approve")
        assert res.status_code == 409 and r.sink.messages == []
        assert subjects(u.box, "Drafts") == ["Hallo Alice"]


async def test_disconnecting_the_application_voids_its_approvals(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, grant_id = await r.token(u)
        aid, path = await pending(r, u, token)
        await r.store.revoke_grant(grant_id)
        browser = await r.portal(u)
        page = await browser.get(path)
        assert "application was disconnected" in page.text and "Send this message" not in page.text
        assert (await post(browser, path, action="approve")).status_code == 409
        assert r.sink.messages == []


async def test_pages_need_a_session(imap_server: ImapServer):
    async with remote(imap_server) as r:
        u = await r.user()
        token, _ = await r.token(u)
        aid, path = await pending(r, u, token)
        anon = httpx2.AsyncClient(base_url=r.url, timeout=30)
        for p in ("/portal/approvals", path):
            res = await anon.get(p)
            assert res.status_code == 303 and res.headers["location"].startswith("/portal/signin")
        res = await anon.post(path, data={"action": "approve", "csrf_token": "x" * 40})
        assert res.status_code in (303, 403) and r.sink.messages == []
