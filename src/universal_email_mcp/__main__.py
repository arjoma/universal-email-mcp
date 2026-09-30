"""Command-line entry point (``universal-email-mcp`` / ``python -m universal_email_mcp``)."""

import sys

from universal_email_mcp.cli import main as _cli_main


def main() -> None:
    sys.exit(_cli_main())


if __name__ == "__main__":
    main()
