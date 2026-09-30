"""universal-email-mcp — vendor-neutral MCP server for IMAP, POP3 and SMTP mailboxes."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("universal-email-mcp")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"
