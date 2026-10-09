"""The one ``query`` parameter of the list tools: a wildcard pattern or fuzzy text.

``find_messages``, ``list_folders`` and ``find_contacts`` share these rules:

- A query containing ``*`` or ``?`` is a **wildcard pattern**: ``*`` matches any
  run of characters (also across words), ``?`` exactly one.
  Matching is case-insensitive and umlaut-folded (``Mü*`` finds ``Müller``,
  ``Mueller`` and ``Muller``). The pattern has to cover whole words: it may start
  at any word and must end at a word end, so ``hub*`` finds "Anna Huber" and
  ``*bau*`` finds ``anna@huber-bau.example``, while ``ub*`` does not (``*ub*``
  does). Everything else in the pattern is literal (no regular expressions).
  Folder names: a pattern without ``/`` matches the folder's own name at any
  depth, a pattern with ``/`` its path (``clients/m*``, ``*/2025``).
- Any other query is **fuzzy** (rapidfuzz, :mod:`.fuzzy`): typos, umlaut
  spellings and word order are tolerated, results are ranked by score.

Matching is linear in practice and never backtracks across stars: the pattern is
split at ``*`` into fixed-length segments, each found left-most once (which is
optimal for globs); the cost is bounded by ``len(text) × len(pattern)``, and both
are capped. Nothing here does I/O; the texts compared are untrusted mail data and
are only compared, never interpreted.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from universal_email_mcp.errors import InvalidArgument
from universal_email_mcp.models import MessageSummary
from universal_email_mcp.service import fuzzy

MAX_QUERY_CHARS = 200
"""Longest accepted query."""
MAX_ADDRESSES = 50
"""Recipients per message that a query is compared with."""
SIMILAR_THRESHOLD = 50.0
"""Minimum fuzzy score for "similar names" after a search without results."""

_WILDCARDS = re.compile(r"(\*+|\?)")

QueryMode = Literal["wildcard", "fuzzy"]


def is_wildcard(text: str) -> bool:
    return "*" in text or "?" in text


def _boundary(text: str, i: int) -> bool:
    """``i`` does not split a word (start, end, or next to a non-word character)."""
    return i <= 0 or i >= len(text) or not (text[i - 1].isalnum() and text[i].isalnum())


@dataclass(frozen=True, slots=True)
class _Glob:
    """One folded spelling of a pattern: fixed-length segments between stars."""

    segments: tuple[re.Pattern[str], ...]
    lengths: tuple[int, ...]
    starred: bool
    """At least one ``*``: segments[0] is the head, segments[-1] the tail."""

    @classmethod
    def compile(cls, tokens: Sequence[str], fold: int) -> _Glob:
        parts: list[list[str]] = [[]]
        lengths = [0]
        for tok in tokens:
            if tok.startswith("*"):
                parts.append([])
                lengths.append(0)
            elif tok == "?":
                parts[-1].append(".")
                lengths[-1] += 1
            elif tok:
                folded = fuzzy.fold_variants(tok)
                lit = folded[min(fold, len(folded) - 1)]
                parts[-1].append(re.escape(lit))
                lengths[-1] += len(lit)
        segs = tuple(re.compile("".join(p), re.DOTALL) for p in parts)
        return cls(segs, tuple(lengths), len(parts) > 1)

    def _find(self, k: int, text: str, pos: int, *, at_end: bool = False) -> int:
        """Left-most position ≥ ``pos`` where segment ``k`` matches and starts (or,
        with ``at_end``, ends) on a word boundary; -1 if there is none."""
        seg, n = self.segments[k], self.lengths[k]
        while pos <= len(text):
            m = seg.search(text, pos)
            if m is None:
                return -1
            s = m.start()
            if _boundary(text, s + n if at_end else s):
                return s
            pos = s + 1
        return -1

    def match(self, text: str) -> bool:
        if not self.starred:
            # Whole words only: a span that starts and ends on a word boundary.
            pos = 0
            while (s := self._find(0, text, pos)) >= 0:
                if _boundary(text, s + self.lengths[0]):
                    return True
                pos = s + 1
            return False
        # With a star after the head, the earliest head is always best: the star
        # absorbs anything up to a later one.
        if self.lengths[0]:
            start = self._find(0, text, 0)
            if start < 0:
                return False
            pos = start + self.lengths[0]
        else:
            pos = 0
        last = len(self.segments) - 1
        for k in range(1, last):  # middle segments: left-most occurrence each
            m = self.segments[k].search(text, pos)
            if m is None:
                return False
            pos = m.end()
        if not self.lengths[last]:
            return True  # trailing star: runs to the end of the text (a boundary)
        return self._find(last, text, pos, at_end=True) >= 0


@dataclass(frozen=True, slots=True)
class WildcardPattern:
    """A compiled ``*``/``?`` pattern (all folded spellings)."""

    text: str
    _globs: tuple[_Glob, ...]

    @classmethod
    def compile(cls, text: str) -> WildcardPattern:
        tokens = [t for t in _WILDCARDS.split(text) if t]
        globs = tuple(dict.fromkeys(_Glob.compile(tokens, fold) for fold in (0, 1)))
        return cls(text, globs)

    def match(self, candidate: str) -> bool:
        if not candidate:
            return False
        for spelling in fuzzy.fold_variants(candidate):
            if any(g.match(spelling) for g in self._globs):
                return True
        return False

    def match_any(self, candidates: Iterable[str]) -> bool:
        return any(self.match(c) for c in candidates if c)


@dataclass(frozen=True, slots=True)
class Query:
    """A parsed ``query`` argument."""

    text: str
    pattern: WildcardPattern | None
    """Set for wildcard queries."""

    @property
    def mode(self) -> QueryMode:
        return "wildcard" if self.pattern is not None else "fuzzy"

    def score(self, candidates: Iterable[str]) -> float:
        """0–100: a wildcard match scores 100 (or 0); fuzzy queries score the best
        candidate."""
        texts = [c for c in candidates if c]
        if self.pattern is not None:
            return 100.0 if self.pattern.match_any(texts) else 0.0
        return fuzzy.score_any(self.text, texts)

    @property
    def literal(self) -> str:
        """The text without wildcards (for "similar names")."""
        return " ".join(_WILDCARDS.sub(" ", self.text).split())


def parse(text: str | None) -> Query | None:
    """``None`` for an empty query; :class:`InvalidArgument` if it is too long."""
    if text is None or not text.strip():
        return None
    text = text.strip()
    if len(text) > MAX_QUERY_CHARS:
        raise InvalidArgument(
            f"query is longer than {MAX_QUERY_CHARS} characters",
            hint="Use a few words or a short pattern like 'hub*'.",
        )
    pattern = WildcardPattern.compile(text) if is_wildcard(text) else None
    return Query(text, pattern)


def similar(query: Query, names: Iterable[str], *, limit: int = 5) -> list[str]:
    """The names closest to the query (fuzzy, on its literal text), best first."""
    lit = query.literal
    if not lit:
        return []
    scored: dict[str, float] = {}
    for n in names:
        if n and n not in scored:
            scored[n] = fuzzy.score(lit, n)
    ranked = sorted(
        ((s, n) for n, s in scored.items() if s >= SIMILAR_THRESHOLD),
        key=lambda x: (-x[0], x[1].casefold()),
    )
    return [n for _s, n in ranked[:limit]]


def message_texts(m: MessageSummary) -> list[str]:
    """What a query is matched against in a message: sender and recipient names
    and addresses, and the subject (with and without ``Re:``/``AW:`` prefixes)."""
    subject = fuzzy.strip_subject_prefixes(m.subject)
    recipients = (*m.to, *m.cc)[:MAX_ADDRESSES]
    texts = [*fuzzy.address_texts(m.from_[:MAX_ADDRESSES]), *fuzzy.address_texts(recipients)]
    texts.append(subject)
    if subject != m.subject:
        texts.append(m.subject)
    return texts


def score_message(query: Query, m: MessageSummary) -> float:
    """0–100 for a message's headers (never its body).

    A multi-word fuzzy query is also scored against sender + subject and
    recipients + subject, so words spread over fields ("rechnung huber") add up."""
    texts = message_texts(m)
    if query.pattern is None and len(query.text.split()) > 1:
        subject = fuzzy.strip_subject_prefixes(m.subject)
        for people in (m.from_, (*m.to, *m.cc)[:MAX_ADDRESSES]):
            names = " ".join(a.name or a.email for a in people[:MAX_ADDRESSES])
            if names:
                texts.append(f"{names} {subject}")
    return query.score(texts)
