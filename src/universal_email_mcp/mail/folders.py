"""Folder names and special-folder role detection.

Precedence for each role: explicit override (operator preset or user config) →
RFC 6154 SPECIAL-USE flag → name heuristics (English + German). The heuristics
only look at top-level folders and direct children of INBOX, so a user folder like
``Projects/Archive`` is not mistaken for the archive. Folders in other users' or
shared namespaces never get a role from flags or names (a shared ``\\Sent`` folder
is not the user's Sent).
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from imapclient.imap_utf7 import decode as _utf7_decode

from universal_email_mcp.models import FolderRole

ROLE_FLAGS: dict[str, FolderRole] = {
    "\\sent": "sent",
    "\\drafts": "drafts",
    "\\trash": "trash",
    "\\junk": "junk",
    "\\archive": "archive",
}

# Ordered by preference within a role.
ROLE_NAMES: dict[FolderRole, tuple[str, ...]] = {
    "sent": (
        "sent",
        "sent items",
        "sent messages",
        "sent mail",
        "gesendet",
        "gesendete objekte",
        "gesendete elemente",
        "gesendete nachrichten",
    ),
    "drafts": ("drafts", "draft", "entwürfe", "entwurf", "entwuerfe"),
    "trash": (
        "trash",
        "deleted items",
        "deleted messages",
        "papierkorb",
        "gelöschte elemente",
        "gelöschte objekte",
        "gelöschte nachrichten",
        "bin",
    ),
    "junk": ("junk", "spam", "junk e-mail", "junk email", "junk-e-mail", "bulk mail"),
    "archive": ("archive", "archives", "archiv"),
}


def decode_folder_name(wire: str) -> str:
    """Decode an IMAP modified-UTF-7 folder name; returns ``wire`` unchanged if invalid
    (also when the result would hold a lone UTF-16 surrogate)."""
    if "&" not in wire:
        return wire
    try:
        decoded = _utf7_decode(wire.encode("ascii"))
    except (UnicodeError, ValueError):
        return wire
    if not isinstance(decoded, str):
        return wire
    try:
        decoded.encode("utf-8")  # a lone surrogate (``&2D0-``) would kill the JSON writer
    except UnicodeEncodeError:
        return wire
    return decoded


def _norm(s: str) -> str:
    return unicodedata.normalize("NFC", s).casefold().strip()


@dataclass(frozen=True, slots=True)
class RawFolder:
    """Minimal folder data needed for role assignment."""

    name: str  # wire name
    display_name: str
    delimiter: str | None
    flags: tuple[str, ...]


def _heuristic_leaf(folder: RawFolder) -> str | None:
    """Leaf name if the folder is top-level or a direct child of INBOX, else None."""
    parts = (
        folder.display_name.split(folder.delimiter) if folder.delimiter else [folder.display_name]
    )
    if len(parts) >= 2 and parts[0].upper() == "INBOX":
        parts = parts[1:]
    if len(parts) != 1:
        return None
    return _norm(parts[0])


def _is_selectable(folder: RawFolder) -> bool:
    lowered = {f.lower() for f in folder.flags}
    return "\\noselect" not in lowered and "\\nonexistent" not in lowered


def assign_roles(
    folders: Iterable[RawFolder],
    *,
    overrides: Mapping[FolderRole, str] | None = None,
    use_special_use: bool = True,
    foreign_prefixes: Iterable[str] = (),
) -> tuple[dict[str, FolderRole], list[str]]:
    """Return ``({wire_name: role}, warnings)``; each role goes to at most one folder.

    ``foreign_prefixes``: wire-name prefixes of the other-users and shared
    namespaces; folders under them are only eligible through an explicit override.
    """
    items = [f for f in folders if _is_selectable(f)]
    foreign = tuple(p for p in foreign_prefixes if p)
    own = [f for f in items if not f.name.startswith(foreign)] if foreign else items
    by_role: dict[FolderRole, str] = {}
    warnings: list[str] = []

    for f in items:
        if f.name.upper() == "INBOX":
            by_role["inbox"] = f.name
            break

    for role, wanted in (overrides or {}).items():
        match = _find_by_name(items, wanted)
        if match is None:
            warnings.append(f"folder override {role}={wanted!r}: no such folder")
        else:
            by_role[role] = match.name

    if use_special_use:
        for f in own:
            for flag in f.flags:
                role = ROLE_FLAGS.get(flag.lower())
                if role is not None and role not in by_role:
                    by_role[role] = f.name

    for role, names in ROLE_NAMES.items():
        if role in by_role:
            continue
        best: tuple[int, str] | None = None
        for f in own:
            if f.name in by_role.values():
                continue
            leaf = _heuristic_leaf(f)
            if leaf is None or leaf not in names:
                continue
            rank = names.index(leaf)
            if best is None or rank < best[0]:
                best = (rank, f.name)
        if best is not None:
            by_role[role] = best[1]

    return {name: role for role, name in by_role.items()}, warnings


def _find_by_name(items: list[RawFolder], wanted: str) -> RawFolder | None:
    for f in items:
        if f.name == wanted:
            return f
    for f in items:
        if f.display_name == wanted:
            return f
    target = _norm(wanted)
    for f in items:
        if _norm(f.display_name) == target:
            return f
    return None
