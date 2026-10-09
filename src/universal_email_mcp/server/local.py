"""``universal-email-mcp local``: the MCP server over stdio for one user.

Accounts come from the config file; passwords from the environment or the OS
keyring. stdout carries the MCP protocol, so all logging goes to stderr. Unless
``[downloads] enabled = false``, a loopback listener serves attachment download
links for as long as the server runs.
"""

from __future__ import annotations

import asyncio
import logging

from universal_email_mcp.config import Config
from universal_email_mcp.server.app import build_server
from universal_email_mcp.server.downloads import LocalDownloads
from universal_email_mcp.service.mail import MailService
from universal_email_mcp.service.router import AccountRouter

log = logging.getLogger(__name__)


async def serve_stdio(config: Config) -> None:
    router = AccountRouter(config)
    downloads = LocalDownloads(router, config.downloads) if config.downloads.enabled else None
    if downloads is not None and not await downloads.start():
        downloads = None
    service = MailService(config, router=router, download_links=downloads)
    server = build_server(service)
    log.info("serving %d account(s) over stdio", len(config.accounts))
    try:
        await server.run_stdio_async()
    finally:
        if downloads is not None:
            await downloads.stop()
        await service.aclose()


def run_local(config: Config) -> None:
    asyncio.run(serve_stdio(config))
