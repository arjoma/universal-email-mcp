"""Bearer verification for ``/mcp`` in OAuth mode.

Access tokens are opaque; the store keeps only their SHA-256 digest. A token is accepted when
it is a live (unexpired) access token, its grant still exists, and it was issued for **this**
resource (RFC 8707: the audience is the MCP endpoint, a token minted for another server is
refused). Nothing about a refused token is logged except the reason.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.oauth.config import OAuthConfig
from universal_email_mcp.store import Grant, Store

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

    @classmethod
    def of_grant(cls, grant: Grant) -> Principal:
        """The principal a stored grant stands for (the portal acts for it when the user
        approves a send; the grant is checked for expiry by the caller)."""
        return cls(
            user_id=grant.user_id,
            grant_id=grant.id,
            client_id=grant.client_id,
            client_name=grant.client_name,
            scopes=tuple(grant.scope.split()),
            account_scopes=dict(grant.account_scopes),
            identity_ids=grant.identity_ids,
        )


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
        # A refresh with a narrower scope issued a token with less than the grant's scope.
        granted = grant.scope.split()
        scopes = tuple(w for w in token.scope.split() if w in granted)
        return replace(Principal.of_grant(grant), scopes=scopes)
