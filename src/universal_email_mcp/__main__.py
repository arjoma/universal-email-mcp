"""Command-line entry point."""

import sys

from universal_email_mcp import __version__


def main() -> None:
    print(
        f"universal-email-mcp {__version__} — under development, not usable yet.\n"
        "See https://github.com/arjoma/universal-email-mcp",
        file=sys.stderr,
    )
    sys.exit(1)


if __name__ == "__main__":
    main()
