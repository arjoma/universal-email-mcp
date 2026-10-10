"""Shared state of the portal pages (on top of the OAuth service)."""

from __future__ import annotations

from dataclasses import dataclass, replace

from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import ServerProfile
from universal_email_mcp.oauth.service import OAuthService
from universal_email_mcp.portal.connect import ConnectionTester
from universal_email_mcp.presets import PRESETS
from universal_email_mcp.service.userpool import UserPool

CUSTOM_PORTS = frozenset({993, 995, 465, 587})
"""Ports a server the *user* named may use (design section 5); servers the operator listed
are trusted and may use any port."""
CONNECT_TIMEOUT = 10.0
READ_TIMEOUT = 20.0


@dataclass(slots=True)
class PortalService:
    oauth: OAuthService
    mail_servers: tuple[ServerProfile, ...]
    """``MAIL_SERVERS``: one entry = fixed, several = a choice, none = free entry."""
    tester: ConnectionTester
    net: NetPolicy
    """Policy for operator-listed servers (private addresses only if the operator allows)."""
    pool: UserPool | None = None
    """Reads mail for the message viewer (``None``: no viewer routes answer)."""
    max_download_bytes: int = 100 * 1024 * 1024
    content_origin: str | None = None
    """Separate origin that serves the sandboxed HTML of mail (``CONTENT_ORIGIN``), if any."""

    @property
    def custom_allowed(self) -> bool:
        return not self.mail_servers

    @property
    def custom_net(self) -> NetPolicy:
        """Free entry: a host a user typed in is public-only, whatever the operator allows
        for the servers they listed (``UEM_ALLOW_PRIVATE_NETWORKS``)."""
        return replace(self.net, allow_private=False, allowed_ports=CUSTOM_PORTS)

    def known_profiles(self) -> tuple[ServerProfile, ...]:
        """Server profiles an account's ``preset`` can refer to."""
        seen: dict[str, ServerProfile] = {}
        for p in (*self.mail_servers, *self.oauth.login_domains.values(), *PRESETS.values()):
            seen.setdefault(p.name, p)
        return tuple(seen.values())
