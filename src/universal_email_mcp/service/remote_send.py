"""What remote mode adds to a send (WP 3f): shared rate limit, replay guard, approvals.

One :class:`StoreRemoteSend` per per-user context (user + grant). Everything it keeps lives
in the store, not in the process, so several instances agree:

* **Rate limit** - sends per hour and per day *per user* (policy ``max_sends_per_hour`` /
  ``max_sends_per_day``), counted from the user's own activity feed: each completed send
  writes an ``ActivityEntry`` (event ``send``, no address, no subject). Two instances
  checking at the same moment can overshoot by one send; the limit is a brake, not a ledger.
* **Replay guard** - a send claims ``user + content hash`` for a few minutes before the mail
  server is contacted (:meth:`Store.claim_send`). A replayed ``requestState``, a double click
  on "approve" or a second instance racing the first cannot send the same content twice.
* **Approvals** - a send that must wait for the user in the portal becomes a
  ``PendingApproval`` (draft reference sealed, no mail text) and a link to the portal page.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import timedelta
from typing import Any

from universal_email_mcp.config import Policy
from universal_email_mcp.errors import RateLimited
from universal_email_mcp.models import Identity, MessageRef
from universal_email_mcp.oauth.identity import short_id
from universal_email_mcp.service.send import ApprovalTicket
from universal_email_mcp.store import ActivityEntry, PendingApproval, Store

log = logging.getLogger(__name__)

CLAIM_TTL = timedelta(minutes=10)
"""How long a sent message's content stays claimed (at least the request-state lifetime)."""
SEND_EVENT = "send"
MAX_PENDING_APPROVALS = 20
"""Sends of one user waiting in the portal at once (a client cannot flood the page)."""


def approval_url(public_url: str | None, approval_id: str) -> str:
    base = (public_url or "").rstrip("/")
    return f"{base}/portal/approvals/{approval_id}"


class StoreRemoteSend:
    def __init__(
        self,
        store: Store,
        policy: Policy,
        *,
        user_id: str,
        grant_id: str,
        public_url: str | None,
    ) -> None:
        self.store = store
        self.policy = policy
        self.user_id = user_id
        self.grant_id = grant_id
        self.public_url = public_url

    # ------------------------------------------------------------ rate limit

    async def check_rate(self) -> None:
        pol = self.policy
        now = self.store.now()
        rows = await self.store.list_for_user(ActivityEntry, self.user_id)
        times = sorted(r.at for r in rows if r.event == SEND_EVENT)
        day = [t for t in times if t > now - timedelta(hours=24)]
        hour = [t for t in day if t > now - timedelta(hours=1)]
        if len(hour) >= pol.max_sends_per_hour:
            wait = int((hour[0] + timedelta(hours=1) - now).total_seconds() / 60) + 1
            raise RateLimited(
                f"{len(hour)} messages were sent in the last hour; the limit is "
                f"{pol.max_sends_per_hour}",
                hint=f"Try again in about {wait} minute(s).",
            )
        if len(day) >= pol.max_sends_per_day:
            raise RateLimited(
                f"{len(day)} messages were sent in the last 24 hours; the limit is "
                f"{pol.max_sends_per_day}",
                hint="Try again later.",
            )

    async def record_send(self) -> None:
        await self.store.record_activity(
            self.user_id, SEND_EVENT, tool="send_message", outcome="sent"
        )

    # ------------------------------------------------------------ replay guard

    async def claim(self, content_hash: str) -> bool:
        return await self.store.claim_send(self.user_id, content_hash, CLAIM_TTL)

    async def release(self, content_hash: str) -> None:
        await self.store.release_send(self.user_id, content_hash)

    # ------------------------------------------------------------ approvals

    async def request_approval(
        self, *, identity: Identity, content_hash: str, draft: MessageRef
    ) -> ApprovalTicket:
        now = self.store.now()
        live = [
            a
            for a in await self.store.list_for_user(PendingApproval, self.user_id)
            if a.status == "pending" and a.expires_at > now
        ]
        minutes = max(1, int(self.store.policy.approval_ttl.total_seconds() // 60))
        for a in live:  # the same message asked for again: the same link
            if a.grant_id == self.grant_id and a.content_hash == content_hash:
                return ApprovalTicket(a.id, approval_url(self.public_url, a.id), minutes)
        if len(live) >= MAX_PENDING_APPROVALS:
            raise RateLimited(
                f"{len(live)} sends are waiting for the user's approval already",
                hint="The user has to approve or reject some of them in the portal first.",
            )
        rec = await self.store.create_approval(
            user_id=self.user_id,
            grant_id=self.grant_id,
            identity_id=identity.ref,
            content_hash=content_hash,
            draft_ref=draft.encode(),
        )
        return ApprovalTicket(
            id=rec.id, url=approval_url(self.public_url, rec.id), expires_in_minutes=minutes
        )

    def audit_fields(self) -> Mapping[str, Any]:
        return {"user": short_id(self.user_id), "grant": self.grant_id}
