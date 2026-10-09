"""Validation of folder names the assistant is asked to create.

A new folder name comes from the user or the model (never from a mail), but it
still ends up in IMAP commands and in the user's mail client, so it is held to a
strict rule set: plain printable text, no IMAP wildcards, quotes, backslashes,
control or invisible characters, no ``.``/``..`` levels, no whitespace at the
ends, and not the server's own hierarchy delimiter inside a level.

Error messages name the problem, never echo the offending text.
"""

from __future__ import annotations

import unicodedata

from universal_email_mcp.errors import InvalidFolderName

MAX_LEVEL_CHARS = 100
"""Longest single folder level."""
MAX_NEW_LEVELS = 5
"""Most levels one ``create_folder`` call creates (or names)."""
MAX_PATH_CHARS = 255
"""Longest full folder path as given by the caller."""
_FORBIDDEN_IN_LEVEL = frozenset('*%"\\/')
"""IMAP wildcards, quote, backslash and the user-facing level separator."""
_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
"""Control, format (bidi, zero-width), surrogate, private use, unassigned, separators."""


def split_new_path(name: str, delimiter: str | None) -> list[str]:
    """Split a user-given folder path (``/`` separates levels) into validated levels.

    ``delimiter`` is the server's hierarchy delimiter, which must not appear
    inside a level. Raises :class:`InvalidFolderName`.
    """
    if not name:
        raise InvalidFolderName("the folder name is empty")
    if len(name) > MAX_PATH_CHARS:
        raise InvalidFolderName(f"the folder path is longer than {MAX_PATH_CHARS} characters")
    levels = name.split("/")
    if len(levels) > MAX_NEW_LEVELS:
        raise InvalidFolderName(f"more than {MAX_NEW_LEVELS} levels in one call")
    for level in levels:
        check_level(level, delimiter)
    return levels


def check_level(level: str, delimiter: str | None) -> None:
    """Validate one folder level (see the module docstring)."""
    if not level:
        raise InvalidFolderName("a folder level is empty (leading, trailing or double '/')")
    if level != level.strip() or level != level.strip(" 　"):
        raise InvalidFolderName("a folder level starts or ends with whitespace")
    if len(level) > MAX_LEVEL_CHARS:
        raise InvalidFolderName(f"a folder level is longer than {MAX_LEVEL_CHARS} characters")
    if set(level) == {"."}:
        raise InvalidFolderName("'.' and '..' are not folder names")
    if level.startswith(("#", "~")):
        raise InvalidFolderName("a folder level must not start with '#' or '~'")
    if any(unicodedata.category(c) in _BAD_CATEGORIES for c in level):
        raise InvalidFolderName("a folder level contains control or invisible characters")
    if any(c in _FORBIDDEN_IN_LEVEL for c in level):
        raise InvalidFolderName("a folder level contains one of * % \" \\ (or '/')")
    if delimiter and delimiter in level:
        raise InvalidFolderName(f"a folder level contains the server's separator {delimiter!r}")
    if not unicodedata.is_normalized("NFC", level):
        raise InvalidFolderName("a folder level is not NFC-normalised text")
