"""Login credentials on their way to a server: validation and IMAP quoting.

A login name or password comes from configuration or from a sign-in form, so it is
not trusted either: a control character (CR, LF, NUL ...) could end the command line
and start a second command, or shift the fields of ``AUTH PLAIN``. Every backend runs
:func:`check_credentials` first; :func:`imap_quote` makes the IMAP ``LOGIN`` arguments
safe (``imaplib`` quotes the password but sends the user name verbatim).
"""

from __future__ import annotations

from universal_email_mcp.errors import AuthFailed


def check_credentials(username: str, password: str) -> None:
    """Refuse credentials that cannot be sent safely (:class:`AuthFailed`)."""
    if not username:
        raise AuthFailed("no user name configured")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in username + password):
        raise AuthFailed("user name or password contains control characters")


def imap_quote(value: str) -> str:
    """``value`` as an IMAP quoted string (RFC 3501 section 4.3): ``\\`` and ``"``
    escaped. Call :func:`check_credentials` first; a quoted string cannot carry CR/LF."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
