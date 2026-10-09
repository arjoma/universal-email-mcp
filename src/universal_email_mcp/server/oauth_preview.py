"""The MCP server of OAuth mode until the per-user service exists (WP 3e).

Authentication is complete (OAuth, per-user grants), but the mail tools still run on the
local TOML configuration, which has no meaning for a signed-in user. So the server offers
exactly one honest tool, ``account_info``, which tells the caller who is connected and what
the connected client was granted, and says that the mail tools are not available yet.
"""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from universal_email_mcp import __version__
from universal_email_mcp.oauth.bearer import Principal
from universal_email_mcp.server.http import principal_var

SERVER_NAME = "universal-email-mcp"

INSTRUCTIONS = (
    "This server is in a preview stage: sign-in and authorization work, the mail tools are "
    "not available yet. Call account_info to see what this connection is allowed to do."
)


def describe(principal: Principal) -> str:
    scopes = ", ".join(principal.scopes) or "none"
    accounts = len(principal.account_scopes)
    identities = len(principal.identity_ids)
    return "\n".join(
        [
            "Connection: authorized.",
            f"Client: {principal.client_name or 'unnamed application'}",
            f"Granted: {scopes} (mailboxes: {accounts}, sender identities: {identities}).",
            "",
            "The mail tools (find_messages, get_message, ...) are not implemented for "
            "signed-in users yet; this preview only confirms the authorization.",
        ]
    )


def build_preview_server() -> MCPServer:
    mcp = MCPServer(
        SERVER_NAME,
        title="Universal e-mail (IMAP)",
        instructions=INSTRUCTIONS,
        version=__version__,
    )

    @mcp.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, open_world_hint=False, idempotent_hint=True
        )
    )
    def account_info() -> str:  # pyright: ignore[reportUnusedFunction]
        """Show who is connected and what this connection may do."""
        principal = principal_var.get()
        if not isinstance(principal, Principal):
            return "Not authenticated."
        return describe(principal)

    return mcp
