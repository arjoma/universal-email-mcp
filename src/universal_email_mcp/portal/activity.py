"""The portal's "Activity" page: what the user's applications (and the user) did lately.

The entries come from the user's own feed in the store (``Store.list_activity``, written by
:func:`universal_email_mcp.audit.record`; retention is the store policy, 30 days by default).
They hold only short labels, counts and ids - never mail data. Names are resolved here, at
render time, from the user's own records: the grant id in ``client`` becomes the
application's name, an account id in ``account`` the account's current name. What no
longer exists shows as "(removed ...)" in the template. Only the signed-in user's entries
are ever read (the store lists by ``user_id``), so another user's activity cannot appear.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import Response

from universal_email_mcp.oauth.clients import clean_text
from universal_email_mcp.store import Grant, MailAccount

if TYPE_CHECKING:
    from universal_email_mcp.portal.pages import PortalEndpoints

PAGE_SIZE = 200
_ID = re.compile(r"[a-z]{1,3}_[0-9a-f]{12,}")


class ActivityPages:
    def __init__(self, ep: PortalEndpoints) -> None:
        self.ep = ep
        self.store = ep.store

    async def index(self, request: Request) -> Response:
        auth = await self.ep.get_auth(request)
        if isinstance(auth, Response):
            return auth
        entries = await self.store.list_activity(auth.user.id, PAGE_SIZE)
        grants = {g.id: g for g in await self.store.list_for_user(Grant, auth.user.id)}
        accounts = {a.id: a.name for a in await self.store.list_for_user(MailAccount, auth.user.id)}
        from universal_email_mcp.portal.pages import fmt_time

        rows: list[dict[str, Any]] = []
        for e in entries:
            grant = grants.get(e.client) if e.client else None
            if e.account in accounts:
                account = accounts[e.account]
            elif e.account and not _ID.fullmatch(e.account):
                account = e.account  # a name recorded as it was (e.g. of a removed account)
            else:
                account = ""
            rows.append(
                {
                    "when": fmt_time(e.at),
                    "event": e.event,
                    "client": clean_text(grant.client_name, 80) if grant else "",
                    "has_client": bool(e.client),
                    "tool": e.tool,
                    "account": clean_text(account, 80),
                    "failed": e.outcome not in ("", "ok", "approved", "accepted", "sent"),
                    "counts": dict(e.counts),
                    "calls": e.counts.get("calls", 1),
                }
            )
        days = max(1, int(self.store.policy.activity_ttl.total_seconds() // 86400))
        return self.ep.page(
            request, "activity.html", section="activity", auth=auth, rows=rows, days=days
        )
