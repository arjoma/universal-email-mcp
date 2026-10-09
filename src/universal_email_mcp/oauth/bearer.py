"""Bearer verification for ``/mcp`` in OAuth mode.

Access tokens are opaque; the store keeps only their SHA-256 digest. A token is accepted when
it is a live (unexpired) access token, its grant still exists, and it was issued for **this**
resource (RFC 8707: the audience is the MCP endpoint, a token minted for another server is
refused). Nothing about a refused token is logged except the reason.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.oauth.config import OAuthConfig
from universal_email_mcp.store import Store

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is calling ``/mcp``: the user, the connected client and what it was granted."""

    user_id: str
    grant_id: str
    client_id: str
    client_name: str
    scopes: tuple[str, ...]
    account_scopes: dict[str, str]
    identity_ids: tuple[str, ...]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


class StoreTokenVerifier:
    """``TokenCheck`` for :func:`universal_email_mcp.server.http.create_app`."""

    def __init__(self, store: Store, cfg: OAuthConfig) -> None:
        self._store = store
        self._cfg = cfg

    async def __call__(self, raw: str) -> Principal | None:
        if not 20 <= len(raw) <= 200:
            return None
        found = await self._store.authenticate_access_token(raw)
        if found is None:
            return None
        token, grant = found
        if token.resource.rstrip("/") != self._cfg.resource.rstrip("/"):
            log_event(log, logging.WARNING, "token for another resource refused", event="bearer")
            return None
        return Principal(
            user_id=grant.user_id,
            grant_id=grant.id,
            client_id=grant.client_id,
            client_name=grant.client_name,
            scopes=tuple(grant.scope.split()),
            account_scopes=dict(grant.account_scopes),
            identity_ids=grant.identity_ids,
        )
