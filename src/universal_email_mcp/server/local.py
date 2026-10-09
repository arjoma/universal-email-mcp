"""``universal-email-mcp local``: the MCP server over stdio for one user.

Accounts come from the config file; passwords from the environment or the OS
keyring. stdout carries the MCP protocol, so all logging goes to stderr. Unless
``[downloads] enabled = false``, a loopback listener serves attachment download
links for as long as the server runs.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from mcp.server.mcpserver import MCPServer

from universal_email_mcp.config import Config
from universal_email_mcp.server.app import build_server
from universal_email_mcp.server.downloads import LocalDownloads
from universal_email_mcp.service.folder_map import STARTUP_TIMEOUT
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter

log = logging.getLogger(__name__)


@dataclass(slots=True)
class LocalServer:
    """The assembled local server and what has to be closed with it."""

    server: MCPServer
    service: MailService
    downloads: LocalDownloads | None

    async def aclose(self) -> None:
        if self.downloads is not None:
            await self.downloads.stop()
        await self.service.aclose()


async def build_local(config: Config, *, folder_timeout: float = STARTUP_TIMEOUT) -> LocalServer:
    """Router, download listener, service and server. The folder lists of all
    accounts are read first (in parallel, ``folder_timeout`` seconds overall) so the
    instructions carry the mailbox structure; failures never stop the startup."""
    router = AccountRouter(config)
    downloads = LocalDownloads(router, config.downloads) if config.downloads.enabled else None
    status = "off (disabled in the config)"
    if downloads is not None:
        started = await downloads.start()
        status = downloads.status()
        if not started:
            log.warning("attachment download links are %s", status)
            downloads = None
    service = MailService(config, router=router, download_links=downloads, download_status=status)
    try:
        maps = await service.startup_folder_maps(folder_timeout)
        server = build_server(service, maps)
    except BaseException:
        if downloads is not None:
            await downloads.stop()
        await service.aclose()
        raise
    return LocalServer(server, service, downloads)


async def serve_stdio(config: Config) -> None:
    local = await build_local(config)
    log.info("serving %d account(s) over stdio", len(config.accounts))
    try:
        await local.server.run_stdio_async()
    finally:
        await local.aclose()


def run_local(config: Config) -> None:
    asyncio.run(serve_stdio(config))
