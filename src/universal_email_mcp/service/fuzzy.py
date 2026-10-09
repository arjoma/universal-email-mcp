"""Approximate matching of names, addresses, subjects and folders (rapidfuzz).

IMAP ``SEARCH`` is exact substring matching: it misses typos ("Hubr"), umlaut
spellings (Müller / Mueller / Muller) and name order ("Example Alice"). Here every
string is normalised into *variants* (German transliteration ä→ae … and plain
accent stripping ä→a) so both spellings meet, split into tokens, and each query
token is matched against the best candidate token.

Scores are 0–100. Nothing here does I/O; callers pass the candidates.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache

from rapidfuzz import fuzz

from universal_email_mcp.models import Address, FolderInfo

DEFAULT_THRESHOLD = 75.0
"""Minimum score for a fuzzy hit."""
COVERAGE_PENALTY = 8.0
"""Most a score loses for candidate words the query did not mention."""

_TRANSLIT = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "æ": "ae", "ø": "oe"})
_TOKEN_SPLIT = re.compile(r"[^0-9a-z]+")


def _strip_accents(s: str) -> str:
    decomposed = unicodedata.normalize("NFKD", s)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


MAX_TEXT_CHARS = 1000
"""Characters of a text that are normalised and compared (longer mail text is cut)."""
_CACHED_CHARS = 200
"""Only short texts (names, subjects, folder names) are cached: bounded memory."""


def variants(text: str) -> tuple[str, ...]:
    """Normalised spellings of ``text``: transliterated (ä→ae) and accent-stripped
    (ä→a), casefolded, punctuation collapsed to spaces. One entry if both agree.
    Only the first ``MAX_TEXT_CHARS`` characters count, also after decomposition
    (one character can expand to many: U+FDFA → 18)."""
    text = text[:MAX_TEXT_CHARS]
    if len(text) <= _CACHED_CHARS:
        return _variants_cached(text)
    return _variants(text)


@lru_cache(maxsize=32768)
def _variants_cached(text: str) -> tuple[str, ...]:
    return _variants(text)


def _variants(text: str) -> tuple[str, ...]:
    base = unicodedata.normalize("NFC", text).casefold()
    translit = _strip_accents(base.translate(_TRANSLIT))
    stripped = _strip_accents(base)
    out: list[str] = []
    for v in (translit, stripped):
        v = " ".join(_TOKEN_SPLIT.split(v[:MAX_TEXT_CHARS])).strip()
        if v not in out:
            out.append(v)
    return tuple(out)


def fold_variants(text: str) -> tuple[str, ...]:
    """Like :func:`variants` (casefolded, ä→ae and ä→a), but punctuation, spaces and
    wildcard characters are kept — for pattern matching (:mod:`.query`). The second
    spelling is lower-cased instead of casefolded, so ``ß`` stays one character.
    Not cached (candidates are mail text); each spelling is cut to
    ``MAX_TEXT_CHARS`` after decomposition."""
    text = unicodedata.normalize("NFC", text[:MAX_TEXT_CHARS])
    translit = _strip_accents(text.casefold().translate(_TRANSLIT))[:MAX_TEXT_CHARS]
    return tuple(dict.fromkeys((translit, _strip_accents(text.lower())[:MAX_TEXT_CHARS])))


def normalize(text: str) -> str:
    """Canonical form (transliterated variant) for keys and comparisons."""
    return variants(text)[0]


def _tokens(norm: str) -> list[str]:
    return [t for t in norm.split() if t]


def _token_score(query_tokens: Sequence[str], cand_tokens: Sequence[str]) -> float:
    """Mean over query tokens of the best ratio against any candidate token,
    minus up to ``COVERAGE_PENALTY`` for candidate tokens no query token matched
    (so "Maier GmbH" prefers the company over "Hubert Maier <…@maier-gmbh.at>").

    A candidate token that starts with a query token of ≥ 3 characters counts as
    a near-hit (95): "rech" finds "rechnung".
    """
    if not query_tokens or not cand_tokens:
        return 0.0
    total = 0.0
    covered: set[int] = set()
    for q in query_tokens:
        best = 0.0
        for i, c in enumerate(cand_tokens):
            s = 100.0 if q == c else fuzz.ratio(q, c)
            if s < 95.0 and len(q) >= 3 and c.startswith(q):
                s = 95.0
            if s >= 80.0:
                covered.add(i)
            best = max(best, s)
        total += best
    coverage = len(covered) / len(cand_tokens)
    return total / len(query_tokens) - COVERAGE_PENALTY * (1.0 - coverage)


def score(query: str, candidate: str) -> float:
    """Similarity of ``query`` to ``candidate`` (0–100), tolerant of typos, umlaut
    spellings, accents, word order and extra words in the candidate."""
    best = 0.0
    for qv in variants(query):
        q_tokens = [t for t in _tokens(qv) if len(t) > 1] or _tokens(qv)
        if not q_tokens:
            continue
        for cv in variants(candidate):
            c_tokens = _tokens(cv)
            if not c_tokens:
                continue
            s = _token_score(q_tokens, c_tokens)
            if s > best:
                best = s
    return max(0.0, best)


def score_any(query: str, candidates: Iterable[str]) -> float:
    return max((score(query, c) for c in candidates if c), default=0.0)


def address_texts(addrs: Iterable[Address]) -> list[str]:
    """Searchable strings for addresses: display name and the full address."""
    out: list[str] = []
    for a in addrs:
        if a.name:
            out.append(a.name)
        out.append(a.email)
    return out


# --------------------------------------------------------------------------- messages


_REPLY_PREFIX = re.compile(r"^\s*(?:(?:re|aw|fw|fwd|wg|sv|antw|vs)\s*(?:\[\d+\])?\s*:\s*)+", re.I)


def strip_subject_prefixes(subject: str) -> str:
    """``Re: AW: Fwd: Angebot`` → ``Angebot`` (reply/forward markers, EN/DE/Nordic)."""
    return _REPLY_PREFIX.sub("", subject)


# --------------------------------------------------------------------------- folders


def folder_path(folder: FolderInfo, personal_prefix: str = "") -> tuple[str, ...]:
    """Hierarchy of a folder as display parts, without the personal namespace
    prefix: ``INBOX.Clients.Huber`` (prefix ``INBOX.``) → ``("Clients", "Huber")``.
    INBOX itself stays ``("INBOX",)``."""
    name = folder.display_name
    if personal_prefix and name.startswith(personal_prefix) and name != personal_prefix:
        name = name[len(personal_prefix) :]
    parts = name.split(folder.delimiter) if folder.delimiter else [name]
    return tuple(p for p in parts if p) or (folder.display_name,)


@dataclass(frozen=True, slots=True)
class PathMatch:
    index: int
    """Position of the matched path in the list given to :func:`match_paths`."""
    path: tuple[str, ...]
    score: float


def _split_query(query: str) -> list[str]:
    parts = [p.strip() for p in re.split(r"\s*[/\\>]\s*|(?<=\S)\.(?=\S)", query) if p.strip()]
    return parts or [query.strip()]


_GROUP_ALIASES: dict[str, tuple[str, ...]] = {
    "clients": ("kunden", "client", "kunde", "customers", "customer"),
    "projects": ("projekte", "project", "projekt"),
    "invoices": ("rechnungen", "invoice", "rechnung", "bills"),
    "archive": ("archiv", "archives"),
}


def _alias_variants(part: str) -> list[str]:
    n = normalize(part)
    out = [part]
    for key, aliases in _GROUP_ALIASES.items():
        if n == key or n in aliases:
            out += [key, *aliases]
    return out


def match_paths(
    query: str,
    paths: Sequence[tuple[str, ...]],
    roles: Sequence[str | None] | None = None,
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> list[PathMatch]:
    """Rank folder paths (display parts, namespace prefix removed — see
    :func:`folder_path`) against a (possibly hierarchical) query, best first.

    ``"clients/hubr"`` matches group and leaf separately (``Clients`` / ``Huber``);
    a single word is matched against the leaf, and weakly against the full path.
    Common English/German group names (clients/Kunden, projects/Projekte …) are
    treated as synonyms; a role name (``sent``) matches its folder.
    """
    q_parts = _split_query(query)
    out: list[PathMatch] = []
    for i, path in enumerate(paths):
        if not path:
            continue
        role = roles[i] if roles is not None else None
        if len(q_parts) == 1:
            # "huber gmbh" should still find the leaf "Huber": also score the leaf
            # against the query (slightly discounted).
            leaf = max(
                max(score(v, path[-1]) for v in _alias_variants(q_parts[0])),
                0.9 * score(path[-1], q_parts[0]),
            )
            whole = score(q_parts[0], " ".join(path)) - 5.0
            s = max(leaf, whole)
            if role is not None and normalize(q_parts[0]) == role:
                s = 100.0
        else:
            # Align the query parts with the end of the path: leaf ↔ last part …
            if len(q_parts) > len(path):
                continue
            tail = path[-len(q_parts) :]
            s = min(
                max(score(v, p) for v in _alias_variants(qp))
                for qp, p in zip(q_parts, tail, strict=True)
            )
        if s >= threshold:
            out.append(PathMatch(i, path, s))
    out.sort(key=lambda m: (-m.score, len(m.path), "/".join(m.path).casefold()))
    return out


AMBIGUITY_MARGIN = 5.0
"""Two folder matches closer than this (in score) are reported as a choice."""


def pick(matches: Sequence[PathMatch]) -> PathMatch | list[PathMatch] | None:
    """The single best match, the tied candidates when ambiguous, or ``None``."""
    if not matches:
        return None
    best = matches[0]
    tied = [m for m in matches if best.score - m.score < AMBIGUITY_MARGIN]
    if len(tied) == 1 or best.score >= 100.0 > tied[1].score:
        return best
    return tied
