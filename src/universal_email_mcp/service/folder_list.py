"""Folder hierarchy, folder name resolution and folder search.

Works on the session's folder list, never with IMAP ``LIST`` patterns: those are
case-sensitive and match the modified UTF-7 wire names, so ``müller`` would not
find ``Müller``. The hierarchy is the display path without the personal namespace
prefix (``INBOX.Clients.Huber`` → ``Clients / Huber``); levels that exist only
implicitly become non-selectable group nodes.

:func:`resolve` is the one folder-name resolver (folder arguments of the message
tools and ``list_folders(parent=…)``): exact name, case-insensitive name, role,
then hierarchy-aware fuzzy matching; close matches are returned as a choice.

Folder names come from the server and are untrusted like any mail data; they are
only compared here.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from universal_email_mcp.errors import AmbiguousFolder, FolderNotFound
from universal_email_mcp.models import FolderInfo
from universal_email_mcp.service import fuzzy
from universal_email_mcp.service.cursor import Key
from universal_email_mcp.service.query import MAX_QUERY_CHARS, Query, parse, similar

MAX_DEPTH = 3
"""Most levels one call lists (``depth``)."""
MAX_STATUS = 50
"""Most folders per call that get message/unread counts (one STATUS each)."""
DEFAULT_PAGE = 50
GROUP_PREFERENCE = 10.0
"""``parent=``: a folder with subfolders this close (in score) to a best match
without subfolders turns the answer into a choice."""
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
    key: Key = ()
    """Tree-order sort key from content, not position: per level (role rank,
    folded name, name, full name), so a folder sorts right after its parent and
    keys stay valid when other folders appear or vanish (keyset paging)."""

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
        """The path joined with ``/`` (namespace prefix removed)."""
        return "/".join(self.path)

    @property
    def selectable(self) -> bool:
        return self.info.selectable if self.info else False

    @property
    def role(self) -> str | None:
        return self.info.role if self.info else None


def build(folders: Sequence[FolderInfo], personal_prefix: str = "") -> list[Node]:
    """The folder forest: special folders first, then alphabetical (umlaut-folded).

    Two folders with the same path (e.g. a name that equals another one without
    the namespace prefix) are both kept, as siblings."""
    root = Node(("",))
    index: dict[tuple[str, ...], Node] = {}
    for f in folders:
        path = fuzzy.folder_path(f, personal_prefix)
        parent = root
        for i in range(1, len(path)):
            key = path[:i]
            node = index.get(key)
            if node is None:
                node = index[key] = Node(key)
                parent.children.append(node)
            parent = node
        node = index.get(path)
        if node is None:
            node = index[path] = Node(path, f)
            parent.children.append(node)
        elif node.info is None:
            node.info = f  # an implicit group that exists after all
        else:
            parent.children.append(Node(path, f))  # same path, another folder

    def count(n: Node) -> int:
        n.descendants = sum(1 + count(c) for c in n.children)
        return n.descendants

    def order(n: Node) -> None:
        # Special folders first, then by name with umlauts folded: "Bäckerei" next
        # to "Bauer", not after "Zöhrer".
        for c in n.children:
            c.key = (
                *n.key,
                _ROLE_ORDER.get(c.role, 10),
                fuzzy.normalize(c.name),
                c.name,
                c.full_name,
            )
        n.children.sort(key=lambda c: c.key)
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


def resolve(
    roots: Sequence[Node],
    name: str,
    *,
    selectable_only: bool = False,
    prefer_groups: bool = False,
    where: str = "",
) -> tuple[Node, str | None]:
    """The folder ``name`` refers to: exact (wire name, display name, path), then
    case-insensitive, then a role (``sent``, ``archive`` …), then hierarchy-aware
    fuzzy matching (``clients/hubr``, ``Kunden``). Returns the node and a note when
    it was matched approximately.

    ``selectable_only``: only folders that can hold mail (message tools).
    ``prefer_groups`` (``list_folders(parent=…)``): an approximate match without
    subfolders next to a close one with subfolders is returned as a choice.
    Raises :class:`FolderNotFound` (similar names in the hint) or
    :class:`AmbiguousFolder` (with the choices); ``where`` is added to messages
    (e.g. `` in account 'Work'``).
    """
    nodes = [n for n in walk(roots) if n.selectable or not selectable_only]
    wanted = name.strip()
    for n in nodes:
        if wanted in (n.full_name, n.joined) or (n.info is not None and n.info.name == wanted):
            return n, None
    folded = wanted.casefold().strip("/")
    for n in nodes:
        if folded in (n.full_name.casefold(), n.joined.casefold()):
            return n, None
    for n in nodes:
        if n.role is not None and n.role == folded:
            return n, None
    matches = fuzzy.match_paths(wanted, [n.path for n in nodes], [n.role for n in nodes])
    picked = fuzzy.pick(matches)
    if picked is None:
        q = parse(wanted[:MAX_QUERY_CHARS])
        near = similar_names(nodes, q) if q else []
        raise FolderNotFound(
            f"no folder matches {name!r}{where}",
            hint=(f"Similar: {'; '.join(near)}. " if near else "")
            + "list_folders shows the top level; list_folders(query=…) searches all levels.",
        )
    if isinstance(picked, list):
        choices = [nodes[m.index].full_name for m in picked[:8]]
        raise AmbiguousFolder(
            f"{name!r} matches several folders{where}: " + "; ".join(choices), choices
        )
    node = nodes[picked.index]
    if prefer_groups and not node.children:
        groups = [
            nodes[m.index]
            for m in matches
            if nodes[m.index].children and picked.score - m.score < GROUP_PREFERENCE
        ]
        if groups:
            choices = [node.full_name, *(g.full_name for g in groups[:7])]
            raise AmbiguousFolder(
                f"{name!r} matches several folders{where}: " + "; ".join(choices),
                choices,
                hint="Repeat the call with one of the listed folder names "
                f"({node.full_name!r} has no subfolders).",
            )
    return node, f"folder {name!r} → {node.full_name!r} (approximate match)"


@dataclass(frozen=True, slots=True)
class Match:
    node: Node
    score: float | None
    """Fuzzy score; ``None`` for wildcard matches."""

    @property
    def key(self) -> Key:
        """Sort key from content: tree order for wildcard matches; best score,
        then shorter path, then name for fuzzy ones."""
        if self.score is None:
            return self.node.key
        n = self.node
        return (-self.score, len(n.path), n.joined.casefold(), n.full_name)


def search(nodes: Sequence[Node], query: Query) -> list[Match]:
    """Folders anywhere below ``nodes`` matching the query, groups included.

    Wildcard patterns without ``/`` match the folder's own name (at any depth),
    patterns with ``/`` its path without the namespace prefix (``clients/m*``,
    ``*/2025``); results in tree order. Fuzzy queries are hierarchy-aware
    (``clients/hubr``), best first.
    """
    all_nodes = list(walk(nodes))
    if query.pattern is not None:
        pat = query.pattern
        on_path = "/" in query.text
        return [Match(n, None) for n in all_nodes if pat.match(n.joined if on_path else n.name)]
    matches = fuzzy.match_paths(
        query.text, [n.path for n in all_nodes], [n.role for n in all_nodes]
    )
    return [Match(all_nodes[m.index], round(m.score, 1)) for m in matches]


def similar_names(nodes: Sequence[Node], query: Query, limit: int = 5) -> list[str]:
    """Full names of the folders whose name or path is closest to the query."""
    by_name: dict[str, str] = {}
    for n in nodes:
        by_name.setdefault(n.name, n.full_name)
        by_name.setdefault(n.joined, n.full_name)
    return list(dict.fromkeys(by_name[s] for s in similar(query, by_name, limit=limit * 2)))[:limit]
