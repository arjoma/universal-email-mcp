"""Pending approvals: sends that wait for the user's decision in the browser (WP 3f).

When a client cannot ask the user to confirm a send (no elicitation) the operator's
``SEND_FALLBACK`` parks the message here: the draft stays in the user's Drafts folder, the
store holds a short-lived :class:`~universal_email_mcp.store.PendingApproval` (user, grant,
identity, content hash, sealed draft reference - never mail text), and the tool result
carries the link to this page. Nothing is sent until the signed-in owner approves:

* the page re-reads the draft from the mailbox through the grant's own service, so what is
  shown is what would be sent: sender, every recipient with its class and warnings, subject,
  attachment names and the text (same truncation rules as the elicitation prompt; the quoted
  original of a reply is folded, never dropped). Mail text is untrusted: escaped by the
  template, defanged and stripped of control characters by the service layer;
* **approve** needs a password entry within the re-authentication window and the CSRF token,
  then sends exactly the draft whose content hash matches the stored one (a changed draft is
  refused: the assistant has to create it again), once (``take``), with Sent copy, draft
  removal and ``\\Answered`` as in local mode;
* **reject** leaves the draft where it is;
* an approval older than its lifetime is shown as expired; an approval of another user does
  not exist for this one (404).

Audit events carry pseudonymous ids and random approval ids only.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import Response

from universal_email_mcp import audit
from universal_email_mcp.errors import MailError
from universal_email_mcp.mail.mime import sanitize_line
from universal_email_mcp.oauth.bearer import Principal
from universal_email_mcp.oauth.clients import clean_text
from universal_email_mcp.oauth.identity import short_id
from universal_email_mcp.server import render
from universal_email_mcp.service.send import (
    SHOW_ATTACHMENTS,
    Prepared,
    SendResult,
    address_text,
    class_tag,
    content_hash,
    split_quoted,
    text_excerpt,
)
from universal_email_mcp.store import Grant, PendingApproval
from universal_email_mcp.store.backend import StoreConflict

if TYPE_CHECKING:
    from universal_email_mcp.portal.pages import Auth, PortalEndpoints
    from universal_email_mcp.service.userpool import UserContext, UserPool

log = logging.getLogger(__name__)

_APPROVAL_ID = re.compile(r"^a_[0-9a-f]{24}$")
MAX_LISTED = 50


@dataclass(slots=True)
class Loaded:
    """One of the user's approvals and what can be said about it right now."""

    rec: PendingApproval
    state: str
    """``pending``, ``expired``, ``rejected``, ``void`` (the application was disconnected)."""
    grant: Grant | None


def view_of(p: Prepared) -> dict[str, Any]:
    """What the user must see before a message leaves, as plain (still untrusted) strings -
    the template escapes them."""
    out = p.out
    recipients = [
        {
            "label": {"to": "To", "cc": "Cc", "bcc": "Bcc"}[c.field],
            "address": address_text(c.address),
            "tag": class_tag(c),
            "flagged": c.klass in ("new", "lookalike"),
            "notes": [sanitize_line(n)[:200] for n in c.notes if c.klass in ("new", "lookalike")],
        }
        for c in p.classified
    ]
    new_text, quoted = split_quoted(out.preview)
    shown, note = text_excerpt(new_text)
    q_shown, q_note = text_excerpt(quoted)
    return {
        "sender": address_text(out.sender),
        "identity": sanitize_line(p.ident.name)[:40],
        "recipients": recipients,
        "has_bcc": any(c.field == "bcc" for c in p.classified),
        "subject": sanitize_line(out.subject)[:200],
        "attachments": [
            f"{sanitize_line(n)[:80]} ({render.fmt_size(z)})"
            for n, z in out.attachments[:SHOW_ATTACHMENTS]
        ],
        "more_attachments": max(0, len(out.attachments) - SHOW_ATTACHMENTS),
        "text": shown,
        "text_note": note,
        "has_text": out.has_text_body,
        "quoted": q_shown,
        "quoted_note": q_note,
        "reasons": list(p.reasons),
        "warnings": [sanitize_line(w)[:200] for w in p.warnings][:10],
    }


class ApprovalPages:
    def __init__(self, ep: PortalEndpoints) -> None:
        self.ep = ep
        self.store = ep.store
        self.svc = ep.svc

    # ------------------------------------------------------------------ loading

    async def _load(self, auth: Auth, approval_id: str) -> Loaded | None:
        """The user's own approval (``None``: no such thing for this user)."""
        if not _APPROVAL_ID.match(approval_id):
            return None
        rec = await self.store.get_any(PendingApproval, approval_id)
        if rec is None or rec.user_id != auth.user.id or rec.status == "sent":
            return None
        grant = await self.store.get(Grant, rec.grant_id)
        if grant is not None and grant.user_id != rec.user_id:
            grant = None
        if rec.status == "declined":
            state = "rejected"
        elif rec.expires_at <= self.store.now():
            state = "expired"
        elif grant is None:
            state = "void"
        else:
            state = "pending" if rec.status == "pending" else "approved"
        return Loaded(rec, state, grant)

    def _pool(self) -> UserPool:
        pool = self.ep.ps.pool
        assert pool is not None, "approvals need the per-user service"
        return pool

    async def _context(self, loaded: Loaded) -> UserContext:
        assert loaded.grant is not None
        return await self._pool().lease(Principal.of_grant(loaded.grant))

    async def _prepare(self, loaded: Loaded) -> tuple[Prepared, UserContext]:
        """Re-read the draft through the grant's service; the caller releases the context.
        Raises ``MailError`` (draft gone, mailbox down, policy) or ``Changed``."""
        ctx = await self._context(loaded)
        try:
            prepared = await ctx.service.sender.prepare_draft(loaded.rec.draft_ref)
            if content_hash(prepared.out.raw) != loaded.rec.content_hash:
                raise Changed
            # The approval names the identity the send was requested for.
            if prepared.ident.ref != loaded.rec.identity_id:
                raise Changed
        except BaseException:
            self._pool().release(ctx)
            raise
        return prepared, ctx

    # ------------------------------------------------------------------ pages

    async def index(self, request: Request) -> Response:
        auth = await self.ep._get(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(auth, Response):
            return auth
        rows = await self.store.list_for_user(PendingApproval, auth.user.id, include_expired=True)
        now = self.store.now()
        items: list[dict[str, Any]] = []
        for rec in reversed(rows):
            if rec.status == "sent":
                continue
            grant = await self.store.get(Grant, rec.grant_id)
            if rec.status == "declined":
                state = "rejected"
            elif rec.expires_at <= now:
                state = "expired"
            elif grant is None:
                state = "void"
            else:
                state = "pending" if rec.status == "pending" else "approved"
            items.append(
                {
                    "id": rec.id,
                    "state": state,
                    "client": clean_text(grant.client_name, 80) if grant else "",
                    "created": _fmt(rec.created_at),
                    "expires": _fmt(rec.expires_at),
                }
            )
        return self.ep._page(  # pyright: ignore[reportPrivateUsage]
            request,
            "approvals.html",
            section="approvals",
            auth=auth,
            approvals=items[:MAX_LISTED],
            pending=sum(1 for i in items if i["state"] == "pending"),
        )

    async def detail(self, request: Request) -> Response:
        auth = await self.ep._get(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(auth, Response):
            return auth
        loaded = await self._load(auth, request.path_params["approval_id"])
        if loaded is None:
            return self.ep._not_found(request, auth)  # pyright: ignore[reportPrivateUsage]
        return await self._detail_page(request, auth, loaded)

    async def _detail_page(
        self, request: Request, auth: Auth, loaded: Loaded, *, status: int = 200, **extra: Any
    ) -> Response:
        view: dict[str, Any] | None = None
        problem = ""
        if loaded.state == "pending":
            try:
                prepared, ctx = await self._prepare(loaded)
            except Changed:
                problem = "changed"
            except MailError as e:
                problem = _problem_code(e)
            else:
                self._pool().release(ctx)
                view = view_of(prepared)
                if prepared.keep_reason is not None:
                    problem = "policy_draft"
        return self.ep._page(  # pyright: ignore[reportPrivateUsage]
            request,
            "approval.html",
            status=status,
            section="approvals",
            auth=auth,
            approval={
                "id": loaded.rec.id,
                "state": loaded.state,
                "client": clean_text(loaded.grant.client_name, 80) if loaded.grant else "",
                "created": _fmt(loaded.rec.created_at),
                "expires": _fmt(loaded.rec.expires_at),
            },
            view=view,
            problem=problem,
            **extra,
        )

    # ------------------------------------------------------------------ decisions

    async def decide(self, request: Request) -> Response:
        got = await self.ep._post(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(got, Response):
            return got
        auth, form = got
        loaded = await self._load(auth, request.path_params["approval_id"])
        if loaded is None:
            return self.ep._not_found(request, auth)  # pyright: ignore[reportPrivateUsage]
        action = str(form.get("action", ""))
        if loaded.state != "pending" or action not in ("approve", "reject"):
            if loaded.state == "expired":
                audit.event("approval.expired_use", approval=loaded.rec.id)
            return await self._detail_page(request, auth, loaded, status=409)
        who = {"user": short_id(auth.user.id), "approval": loaded.rec.id}
        if action == "reject":
            try:
                done = await self.store.decide_approval(loaded.rec.id, auth.user.id, False)
            except StoreConflict:
                done = None
            audit.event("approval.rejected", **who, done=done is not None)
            return self.ep._redirect("/portal/approvals", "approval_rejected")  # pyright: ignore[reportPrivateUsage]
        if not self.ep._fresh(auth):  # pyright: ignore[reportPrivateUsage]
            return self.ep._to_reauth(f"/portal/approvals/{loaded.rec.id}")  # pyright: ignore[reportPrivateUsage]
        return await self._approve(request, auth, loaded, who)

    async def _approve(
        self, request: Request, auth: Auth, loaded: Loaded, who: Mapping[str, str]
    ) -> Response:
        rec = loaded.rec
        try:
            prepared, ctx = await self._prepare(loaded)
        except Changed:
            audit.event("approval.refused", **who, reason="changed")
            return await self._detail_page(request, auth, loaded, status=409)
        except MailError as e:
            audit.event("approval.refused", **who, reason=e.code)
            return await self._detail_page(request, auth, loaded, status=409)
        if prepared.keep_reason is not None:  # policy "draft": nothing to approve, keep it
            self._pool().release(ctx)
            return await self._detail_page(request, auth, loaded, status=409)
        pool = self._pool()
        try:
            # The decision is the gate: of two parallel approvals only one gets through,
            # and a consumed approval can never send again.
            try:
                decided = await self.store.decide_approval(rec.id, auth.user.id, True)
            except StoreConflict:
                decided = None
            consumed = (
                await self.store.consume_approval(rec.id, auth.user.id, rec.content_hash)
                if decided is not None
                else None
            )
            if consumed is None:
                audit.event("approval.refused", **who, reason="already_decided")
                return await self._detail_page(request, auth, loaded, status=409)
            audit.event("approval.approved", **who)
            try:
                result = await ctx.service.sender.execute(prepared, "accepted")
            except MailError as e:
                audit.event("approval.send_failed", **who, code=e.code)
                return self.ep._page(  # pyright: ignore[reportPrivateUsage]
                    request,
                    "approval_result.html",
                    status=502,
                    section="approvals",
                    auth=auth,
                    outcome="failed",
                    code=e.code,
                    detail=sanitize_line(e.message)[:200],
                    steps=[],
                )
        finally:
            pool.release(ctx)
        return self.ep._page(  # pyright: ignore[reportPrivateUsage]
            request,
            "approval_result.html",
            section="approvals",
            auth=auth,
            outcome=_outcome(result),
            code="",
            detail="",
            steps=[sanitize_line(s)[:200] for s in (*result.steps, *result.warnings)],
        )


class Changed(Exception):
    """The draft is not the one that was submitted for approval."""


def _outcome(result: SendResult) -> str:
    return "sent" if result.status == "sent" else "not_sent"


def _problem_code(e: MailError) -> str:
    return "gone" if e.code in ("INVALID_ARGUMENT", "MESSAGE_NOT_FOUND", "INVALID_REF") else "error"


def _fmt(dt: Any) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else ""


__all__ = ["ApprovalPages", "Loaded", "view_of"]
