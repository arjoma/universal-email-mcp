"""Keyset paging over lists merged from several accounts.

Each answering account contributes its rows sorted by a key (smallest first);
the page is the ``limit`` smallest rows over all accounts. The cursor remembers,
per account, the key of the last row it contributed, and the next page resumes
strictly after it — so rows that appear or vanish between pages cannot make a
page skip or repeat anything, and an account that fails on one page keeps its
place and continues when it answers again (the cursor is kept for a few retry
pages, like the message listings).

Keys must be totally ordered across accounts (include the account, or its rank,
when two accounts could produce equal keys).
"""

from __future__ import annotations

import heapq
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from universal_email_mcp.errors import AccountTimeout, ServerUnreachable
from universal_email_mcp.service.cursor import Cursor, CursorCodec, Key
from universal_email_mcp.service.router import AccountProblem

TRANSIENT = frozenset({AccountTimeout.code, ServerUnreachable.code})
"""Failures worth retrying on the next page."""
MAX_CURSOR_RETRIES = 3
"""Pages a cursor stays alive only to retry failed accounts."""
STOPPED_RETRYING = "stopped retrying the failed accounts; call again without a cursor later"


@dataclass(slots=True)
class Page[T]:
    items: list[tuple[str, T]]
    """(account, row) in page order."""
    total: int
    """Rows of all answering accounts (all pages)."""
    offset: int
    """Rows of the answering accounts before this page."""
    cursor: str | None
    exhausted: bool = False
    """A cursor was given but nothing was left (the list changed meanwhile)."""
    notes: list[str] = field(default_factory=list[str])


def keyset_page[T](
    rows: Mapping[str, Sequence[tuple[Key, T]]],
    *,
    limit: int,
    cursor: Cursor | None,
    codec: CursorCodec,
    tool: str,
    query: str,
    problems: Sequence[AccountProblem] = (),
) -> Page[T]:
    after = dict(cursor.after) if cursor else {}
    remaining: dict[str, list[tuple[Key, T]]] = {}
    total = offset = 0
    for acc, items in rows.items():
        last = after.get(acc)
        rest = [kt for kt in items if last is None or kt[0] > last]
        total += len(items)
        offset += len(items) - len(rest)
        remaining[acc] = rest
    merged = heapq.merge(
        *([(k, acc, i) for i, (k, _t) in enumerate(rest)] for acc, rest in remaining.items())
    )
    taken: list[tuple[str, T]] = []
    used: dict[str, int] = {}
    for key, acc, i in merged:
        if len(taken) >= limit:
            break
        taken.append((acc, remaining[acc][i][1]))
        after[acc] = key
        used[acc] = used.get(acc, 0) + 1
    more = any(used.get(acc, 0) < len(rest) for acc, rest in remaining.items())
    retry = any(p.code in TRANSIENT for p in problems)
    retries = (cursor.retries if cursor else 0) + 1 if retry and not more else 0
    notes: list[str] = []
    if retries > MAX_CURSOR_RETRIES:
        notes.append(STOPPED_RETRYING)
        retry = False
    next_cursor = None
    if more or retry:
        next_cursor = codec.encode(Cursor(tool, query, after=after, retries=retries))
    return Page(
        items=taken,
        total=total,
        offset=offset,
        cursor=next_cursor,
        exhausted=cursor is not None and not taken and not problems,
        notes=notes,
    )
