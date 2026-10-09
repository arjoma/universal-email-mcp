"""The portal's "Privacy" page: what is stored, export of everything, delete everything.

* The page lists the record kinds, their retention (read from the store policy and the
  server configuration, never hard-coded) and live counts of the signed-in user's own records.
* The export (``POST``, CSRF-protected) is one JSON document with the user's own records in
  readable form. It never contains passwords, token or session digests, key material, request
  state, draft references or message hashes, and it never touches another user's records.
  Mail content is not stored, so it is not in the export either.
* "Delete everything" needs a recent password entry (the same re-authentication as other
  sensitive actions) plus the typed primary address, then calls ``Store.delete_user`` (see
  its docstring for the order) and closes the user's pooled mail connections.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import Response

from universal_email_mcp.store import (
    ActivityEntry,
    Grant,
    Identity,
    MailAccount,
    PendingApproval,
    PortalSession,
    Store,
    Token,
    User,
)

if TYPE_CHECKING:
    from universal_email_mcp.portal.pages import PortalEndpoints

EXPORT_FORMAT = "universal-email-mcp-export"
EXPORT_VERSION = 1
EXPORT_FILENAME = "universal-email-mcp-data.json"
LOG_PSEUDONYM_LEN = 14
"""Characters of the user id that appear in the operator's logs (see ``audit.py``)."""


def duration_view(td: timedelta) -> dict[str, Any]:
    """A policy duration as ``{"n": 3, "unit": "day"}`` for the template; ``unit`` is
    ``"none"`` for a zero duration (the policy's "unlimited")."""
    seconds = int(td.total_seconds())
    if seconds <= 0:
        return {"n": 0, "unit": "none"}
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds % size == 0:
            return {"n": seconds // size, "unit": unit}
    return {"n": max(1, seconds // 60), "unit": "minute"}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


async def build_export(store: Store, user: User, now: datetime) -> dict[str, Any]:
    """The export document of one user: only records keyed to ``user.id``."""
    data = await store.export_user(user.id)
    approvals = [
        a
        for a in await store.list_for_user(PendingApproval, user.id)
        if a.status != "sent"  # send markers are replay guards, not the user's data
    ]
    sessions = await store.list_for_user(PortalSession, user.id)
    tokens = await store.list_for_user(Token, user.id)
    return {
        "format": EXPORT_FORMAT,
        "version": EXPORT_VERSION,
        "exported_at": now.isoformat(),
        "user": {
            "primary_address": user.primary_address,
            "created_at": _iso(user.created_at),
            "default_identity_id": user.default_identity_id,
            "log_pseudonym": user.id[:LOG_PSEUDONYM_LEN],
        },
        "mail_accounts": data["accounts"],
        "sender_identities": data["identities"],
        "connected_applications": data["grants"],
        "activity": data["activity"],
        "pending_approvals": [
            {
                "id": a.id,
                "grant_id": a.grant_id,
                "identity_id": a.identity_id,
                "status": a.status,
                "created_at": _iso(a.created_at),
                "expires_at": _iso(a.expires_at),
            }
            for a in approvals
        ],
        "not_exported": {
            "note": (
                "Passwords, token and session digests and encryption keys are never exported. "
                "Mail content is not stored. The counts below are records kept only for "
                "operation (sign-in sessions, access and refresh tokens)."
            ),
            "portal_sessions": len(sessions),
            "tokens": len(tokens),
        },
    }


class PrivacyPages:
    def __init__(self, ep: PortalEndpoints) -> None:
        self.ep = ep
        self.store = ep.store
        self.svc = ep.svc

    def _retention(self) -> dict[str, dict[str, Any]]:
        p, cfg = self.store.policy, self.svc.cfg
        return {
            "session_max": duration_view(cfg.portal_max),
            "session_idle": duration_view(cfg.portal_idle),
            "access": duration_view(p.access_ttl),
            "refresh": duration_view(p.refresh_ttl),
            "absolute": duration_view(p.absolute_max),
            "activity": duration_view(p.activity_ttl),
            "approval": duration_view(p.approval_ttl),
        }

    async def index(self, request: Request) -> Response:
        auth = await self.ep._get(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(auth, Response):
            return auth
        uid = auth.user.id
        approvals = [
            a for a in await self.store.list_for_user(PendingApproval, uid) if a.status == "pending"
        ]
        counts = {
            "accounts": len(await self.store.list_for_user(MailAccount, uid)),
            "identities": len(await self.store.list_for_user(Identity, uid)),
            "grants": len(await self.store.list_for_user(Grant, uid)),
            "activity": len(await self.store.list_for_user(ActivityEntry, uid)),
            "approvals": len(approvals),
        }
        return self.ep._page(  # pyright: ignore[reportPrivateUsage]
            request,
            "privacy.html",
            section="privacy",
            auth=auth,
            counts=counts,
            retention=self._retention(),
        )

    async def export(self, request: Request) -> Response:
        got = await self.ep._post(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(got, Response):
            return got
        auth, _ = got
        doc = await build_export(self.store, auth.user, self.store.now())
        await self.svc.audit(
            "portal.export",
            user=auth.user.id,
            accounts=len(doc["mail_accounts"]),
            identities=len(doc["sender_identities"]),
            grants=len(doc["connected_applications"]),
        )
        body = json.dumps(doc, indent=2, ensure_ascii=True)
        return Response(
            body,
            media_type="application/json",
            headers={
                "content-disposition": f'attachment; filename="{EXPORT_FILENAME}"',
                "x-content-type-options": "nosniff",
                "cache-control": "no-store",
                "pragma": "no-cache",
                "content-security-policy": "default-src 'none'; sandbox",
            },
        )

    async def delete_get(self, request: Request) -> Response:
        auth = await self.ep._get(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(auth, Response):
            return auth
        if not self.ep._fresh(auth):  # pyright: ignore[reportPrivateUsage]
            return self.ep._to_reauth(request.url.path)  # pyright: ignore[reportPrivateUsage]
        return self.ep._page(  # pyright: ignore[reportPrivateUsage]
            request,
            "privacy_delete.html",
            section="privacy",
            auth=auth,
            address=auth.user.primary_address,
            error="",
        )

    async def delete_post(self, request: Request) -> Response:
        got = await self.ep._post(request)  # pyright: ignore[reportPrivateUsage]
        if isinstance(got, Response):
            return got
        auth, form = got
        if not self.ep._fresh(auth):  # pyright: ignore[reportPrivateUsage]
            return self.ep._to_reauth("/portal/privacy/delete")  # pyright: ignore[reportPrivateUsage]
        typed = form.get("confirm")
        expected = auth.user.primary_address.strip().casefold()
        if not isinstance(typed, str) or typed.strip().casefold() != expected:
            return self.ep._page(  # pyright: ignore[reportPrivateUsage]
                request,
                "privacy_delete.html",
                status=400,
                section="privacy",
                auth=auth,
                address=auth.user.primary_address,
                error="confirm",
            )
        uid = auth.user.id
        counts = await self.store.delete_user(uid)
        pool = self.ep.ps.pool
        if pool is not None:
            pool.forget_user(uid)
        # no feed entry: the feed is gone with the user; the log keeps the counts only
        await self.svc.audit("portal.delete_all", user=uid, deleted=counts)
        response = self.ep._page(  # pyright: ignore[reportPrivateUsage]
            request, "privacy_deleted.html", csrf=False
        )
        self.ep.web.delete_cookie(response, "session")
        self.ep.web.rotate_csrf(response)
        return response
