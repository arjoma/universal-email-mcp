"""``universal-email-mcp local``: the MCP server over stdio for one user.

Accounts come from the config file; passwords from the environment or the OS
keyring. stdout carries the MCP protocol, so all logging goes to stderr.
"""

from __future__ import annotations

import asyncio
import logging

from universal_email_mcp.config import Config
from universal_email_mcp.server.app import build_server
from universal_email_mcp.service.mail import MailService

log = logging.getLogger(__name__)


async def serve_stdio(config: Config) -> None:
    service = MailService(config)
    server = build_server(service)
    log.info("serving %d account(s) over stdio", len(config.accounts))
    try:
        await server.run_stdio_async()
    finally:
        await service.aclose()


def run_local(config: Config) -> None:
    asyncio.run(serve_stdio(config))
