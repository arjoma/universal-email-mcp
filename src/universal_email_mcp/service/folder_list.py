"""Folder listings for ``list_folders``: overview first, then drill down.

Works on the session's cached folder list (one ``LIST`` per connection), never
with IMAP ``LIST`` patterns: those are case-sensitive and match the modified
UTF-7 wire names, so ``müller`` would not find ``Müller``. The hierarchy is the
display path without the personal namespace prefix (``INBOX.Clients.Huber`` →
``Clients / Huber``); levels that exist only implicitly become non-selectable
group nodes.

Folder names come from the server and are untrusted like any mail data; they are
only compared here.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from universal_email_mcp.errors import AmbiguousFolder, FolderNotFound
from universal_email_mcp.models import FolderInfo
from universal_email_mcp.service import fuzzy
from universal_email_mcp.service.query import MAX_QUERY_CHARS, Query, parse, similar

MAX_DEPTH = 3
"""Most levels one call lists (``depth``)."""
MAX_STATUS = 50
"""Most folders per call that get message/unread counts (one STATUS each)."""
DEFAULT_PAGE = 50
_ROLE_ORDER: dict[str | None, int] = {
    "inbox": 0,
    "drafts": 1,
    "sent": 2,
    "archive": 3,
    "junk": 4,
    "trash": 5,
}


@dataclass(eq=False, slots=True)
class Node:
    """A folder in the hierarchy; ``info`` is ``None`` for an implicit group level."""

    path: tuple[str, ...]
    info: FolderInfo | None = None
    children: list[Node] = field(default_factory=list["Node"])
    descendants: int = 0
    """All folders below this one (any depth)."""

    @property
    def name(self) -> str:
        return self.path[-1]

    @property
    def full_name(self) -> str:
        """The name other tools take (the server's display name; implicit groups:
        the path joined with ``/``)."""
        return self.info.display_name if self.info else self.joined

    @property
    def joined(self) -> str:
        return "/".join(self.path)

    @property
    def selectable(self) -> bool:
        return self.info.selectable if self.info else False

    @property
    def role(self) -> str | None:
        return self.info.role if self.info else None

    def as_folder(self) -> FolderInfo:
        """For fuzzy matching (implicit groups as non-selectable folders)."""
        if self.info is not None:
            return self.info
        return FolderInfo(self.joined, self.joined, "/", ("\\Noselect",), selectable=False)


def build(folders: Sequence[FolderInfo], personal_prefix: str = "") -> list[Node]:
    """The folder forest: special folders first, then alphabetical (umlaut-folded)."""
    root = Node(("",))
    index: dict[tuple[str, ...], Node] = {}
    for f in folders:
        path = fuzzy.folder_path(f, personal_prefix)
        parent = root
        for i in range(1, len(path) + 1):
            key = path[:i]
            node = index.get(key)
            if node is None:
                node = index[key] = Node(key)
                parent.children.append(node)
            parent = node
        if parent.info is None:  # the first of two names that fold to one path wins
            parent.info = f

    def count(n: Node) -> int:
        n.descendants = sum(1 + count(c) for c in n.children)
        return n.descendants

    def order(n: Node) -> None:
        # Special folders first (as the session sorted them), then by name with
        # umlauts folded: "Bäckerei" next to "Bauer", not after "Zöhrer".
        n.children.sort(key=lambda c: (_ROLE_ORDER.get(c.role, 10), fuzzy.normalize(c.name)))
        for c in n.children:
            order(c)

    count(root)
    order(root)
    return root.children


def walk(nodes: Sequence[Node]) -> Iterator[Node]:
    """All nodes below ``nodes`` (inclusive), pre-order."""
    for n in nodes:
        yield n
        yield from walk(n.children)


def levels(nodes: Sequence[Node], depth: int, level: int = 1) -> Iterator[tuple[Node, int]]:
    """Pre-order down to ``depth`` levels, with each node's level (1 = ``nodes``)."""
    for n in nodes:
        yield n, level
        if level < depth:
            yield from levels(n.children, depth, level + 1)


def resolve_parent(
    roots: Sequence[Node], name: str, personal_prefix: str = ""
) -> tuple[Node, str | None]:
    """The node ``name`` refers to: exact (full name, path, then case-insensitive,
    then role), else hierarchy-aware fuzzy. Returns the node and a note when it
    was matched approximately; raises :class:`FolderNotFound` (with similar names
    as hint) or :class:`AmbiguousFolder` (with the choices)."""
    nodes = list(walk(roots))
    wanted = name.strip().strip("/")
    for n in nodes:
        if wanted in (n.full_name, n.joined) or (n.info is not None and n.info.name == wanted):
            return n, None
    folded = wanted.casefold()
    for n in nodes:
        if folded in (n.full_name.casefold(), n.joined.casefold()):
            return n, None
    for n in nodes:
        if n.role is not None and n.role == folded:
            return n, None
    candidates = [n.as_folder() for n in nodes]
    by_id = {id(f): n for f, n in zip(candidates, nodes, strict=True)}
    picked = fuzzy.pick_folder(
        fuzzy.match_folders(
            wanted, candidates, personal_prefix=personal_prefix, include_groups=True
        )
    )
    if picked is None:
        near = similar_names(nodes, wanted)
        raise FolderNotFound(
            f"no folder matches {name!r}",
            hint=(f"Similar: {'; '.join(near)}. " if near else "")
            + "Call list_folders without parent to see the top level.",
        )
    if isinstance(picked, list):
        choices = [by_id[id(m.folder)].full_name for m in picked[:8]]
        raise AmbiguousFolder(f"{name!r} matches several folders: " + "; ".join(choices), choices)
    node = by_id[id(picked.folder)]
    return node, f"parent {name!r} → {node.full_name!r} (approximate match)"


@dataclass(frozen=True, slots=True)
class Match:
    node: Node
    score: float | None
    """Fuzzy score; ``None`` for wildcard matches."""


def search(
    nodes: Sequence[Node],
    query: Query,
    personal_prefix: str = "",
    threshold: float = fuzzy.DEFAULT_THRESHOLD,
) -> list[Match]:
    """Folders anywhere below ``nodes`` matching the query: wildcard patterns
    against the full path (``*`` crosses levels), in tree order; fuzzy queries
    hierarchy-aware (``clients/hubr``), best first. Groups match too."""
    all_nodes = list(walk(nodes))
    if query.pattern is not None:
        pat = query.pattern
        return [Match(n, None) for n in all_nodes if pat.match_any((n.joined, n.full_name))]
    candidates = [n.as_folder() for n in all_nodes]
    by_id = {id(f): n for f, n in zip(candidates, all_nodes, strict=True)}
    matches = fuzzy.match_folders(
        query.text,
        candidates,
        personal_prefix=personal_prefix,
        threshold=threshold,
        include_groups=True,
    )
    return [Match(by_id[id(m.folder)], round(m.score, 1)) for m in matches]


def similar_names(nodes: Sequence[Node], text: str, limit: int = 5) -> list[str]:
    """Full names of the folders whose leaf or path is closest to ``text``."""
    q = parse(text[:MAX_QUERY_CHARS])
    if q is None:
        return []
    by_name: dict[str, str] = {}
    for n in nodes:
        by_name.setdefault(n.name, n.full_name)
        by_name.setdefault(n.joined, n.full_name)
    return list(dict.fromkeys(by_name[s] for s in similar(q, by_name, limit=limit * 2)))[:limit]
