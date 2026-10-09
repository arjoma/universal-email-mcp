"""Send-time recipient check (design section 7.1): who is this mail going to?

Every recipient lands in one class:

- ``internal`` - one of the user's own identity addresses, or an address in a domain
  the policy lists as internal (``internal_domains``). A whole domain is never
  internal by itself: for a personal ``@gmail.com`` identity that would make every
  Gmail user "internal".
- ``known`` - the user has written to this address before (Sent folder, To/Cc), and
  it is not a near-twin of another address the user wrote to.
- ``new`` - never written to (or the history could not be read, ``history_unknown``).
- ``lookalike`` - close to an address or domain the user knows, or otherwise built to
  be mistaken for one. Dangerous in both directions: a phishing twin of a real
  contact, and the user's own typo (``oliver.grnat@``) that went out once and is
  therefore "known" itself - which is why a *known* address that has a near-twin
  among the other addresses written to is flagged too (with a different note).

Look-alike methods (all on lower-case addresses, domains in their Unicode form):

1. identical **skeleton** (case/diacritics folded, Cyrillic/Greek confusables mapped to
   Latin, ``0 o``, ``1 l i``, ``rn m``, ``vv w``): ``examp1e.com``, ``exаmple.com``
   (Cyrillic а), ``xn--`` IDN homographs;
2. same domain, local part one edit away (transposition counts as one:
   ``oliver.grnat`` / ``oliver.grant``; two edits for long local parts);
3. same local part, domain one or two edits away, or the same name with another
   top-level domain (``huber-bau.at`` / ``huber-bau.com``);
4. a domain within one edit of a known domain whatever the local part;
5. mixed scripts inside one domain label (always suspicious, no counterpart needed).

Pure functions; the I/O part (reading the Sent history) is :class:`RecipientChecker`.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from rapidfuzz.distance import OSA

from universal_email_mcp.errors import MailError
from universal_email_mcp.mail.imap import ImapSession
from universal_email_mcp.models import Account, Address
from universal_email_mcp.service.router import AccountRouter
from universal_email_mcp.service.trust import SentToIndex

Klass = Literal["internal", "known", "new", "lookalike"]
Field = Literal["to", "cc", "bcc"]
CLASSES: tuple[Klass, ...] = ("internal", "known", "new", "lookalike")
HISTORY_UPDATE_HEADERS = 3_000
"""Sent messages read to build the look-alike universe (newest first)."""

_CONFUSABLES = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",  # noqa: RUF001
    "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d",  # noqa: RUF001
    "ԍ": "g", "һ": "h", "ӏ": "l", "ь": "b", "ё": "e", "ԛ": "q", "ԝ": "w",  # noqa: RUF001
    # Greek
    "α": "a", "β": "b", "γ": "y", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v",  # noqa: RUF001
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",  # noqa: RUF001
    # Latin extras
    "ı": "i", "ɡ": "g", "ɩ": "i", "ʋ": "v", "ᴅ": "d", "ƅ": "b", "ɑ": "a",  # noqa: RUF001
    "ø": "o", "đ": "d", "ł": "l", "ħ": "h",
}  # fmt: skip
_ASCII_LOOK = str.maketrans({"0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "$": "s"})


def unicode_domain(domain: str) -> str:
    """The Unicode form of an IDNA (``xn--``) domain; the input if it cannot be decoded."""
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return domain


def skeleton(text: str) -> str:
    """Visual skeleton of a string (see module docstring)."""
    t = unicodedata.normalize("NFKD", text.casefold())
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = "".join(_CONFUSABLES.get(c, c) for c in t)
    t = t.translate(_ASCII_LOOK)
    return t.replace("rn", "m").replace("vv", "w")


def _script(ch: str) -> str | None:
    if not ch.isalpha():
        return None
    try:
        return unicodedata.name(ch).split(" ", 1)[0]
    except ValueError:
        return None


def mixed_scripts(domain_unicode: str) -> list[str]:
    """Scripts used together in one label (empty unless a label mixes them)."""
    for label in domain_unicode.split("."):
        scripts = {s for s in map(_script, label) if s}
        if len(scripts) > 1:
            return sorted(scripts)
    return []


_LOOK_SCRIPTS = frozenset({"CYRILLIC", "GREEK"})


def _word_risk(word: str) -> str | None:
    """A word that mixes scripts (``Hubеr`` with a Cyrillic ``е``) or is written
    entirely in letters that pass for Latin ones (Cyrillic ``раураl``)."""
    letters = [c for c in word if c.isalpha()]
    scripts = {s for c in letters if (s := _script(c))}
    if len(scripts) > 1 and scripts & _LOOK_SCRIPTS:
        return "mixed scripts"  # (Han + Kana in one word is normal Japanese)
    non_latin = [c for c in letters if _script(c) in _LOOK_SCRIPTS]
    if non_latin and all(c in _CONFUSABLES or c.isascii() for c in letters):
        return "look-alike letters"
    return None


def sender_warning(name: str, email_addr: str) -> str | None:
    """Why a sender's display name or address looks forged (mixed scripts, Latin
    look-alike letters from another alphabet, in the name, local part or domain),
    or ``None``. No counterpart is needed (unlike :func:`classify`): meant for
    listings of received mail. Normal non-Latin names (all letters one script, not
    mimicking Latin) are not flagged."""
    local_part, _, dom = email_addr.rpartition("@")
    words = [*name.replace(",", " ").split(), *local_part.replace(".", " ").split()]
    words += unicode_domain(dom).casefold().replace("-", ".").split(".")
    for w in words:
        if (risk := _word_risk(w)) is not None:
            return risk
    return None


def _split(email_addr: str) -> tuple[str, str]:
    local, _, domain = email_addr.lower().rpartition("@")
    return local, domain


def _tld_split(domain: str) -> tuple[str, str]:
    name, _, tld = domain.rpartition(".")
    return name, tld


def _domain_relation(cand: str, other: str) -> str | None:
    """Why the domain ``cand`` looks like the different domain ``other``."""
    if skeleton(unicode_domain(cand)) == skeleton(unicode_domain(other)):
        return "uses a look-alike of the domain"
    if len(cand) >= 7 and OSA.distance(cand, other) <= 1:
        return "uses a domain one typo away from the domain"
    return None


def _relation(cand: str, other: str) -> str | None:
    """Why ``cand`` looks like ``other`` (both full addresses, lower case, ``cand !=
    other``); ``None`` if it does not."""
    c_local, c_dom = _split(cand)
    o_local, o_dom = _split(other)
    cu, ou = unicode_domain(c_dom), unicode_domain(o_dom)
    same_domain = c_dom == o_dom
    if skeleton(c_local) == skeleton(o_local) and skeleton(cu) == skeleton(ou):
        return "is visually identical to"
    if same_domain:
        limit = 1 if len(c_local) < 10 else 2
        if len(c_local) >= 3 and OSA.distance(c_local, o_local) <= limit:
            return "differs by a typo from"
        return None
    if skeleton(cu) == skeleton(ou):
        return "uses a look-alike of the domain of"
    if c_local == o_local and len(c_local) >= 3:
        if len(c_dom) >= 6 and OSA.distance(c_dom, o_dom) <= 2:
            return "has a domain that differs by a typo from"
        c_name, c_tld = _tld_split(c_dom)
        o_name, o_tld = _tld_split(o_dom)
        if c_name == o_name and c_tld != o_tld and len(c_name) >= 4:
            return "has the same name but another top-level domain than"
    if len(c_dom) >= 7 and OSA.distance(c_dom, o_dom) <= 1:
        return "uses a domain one typo away from that of"
    return None


@dataclass(frozen=True, slots=True)
class Classified:
    address: Address
    field: Field
    klass: Klass
    notes: tuple[str, ...] = ()
    similar_to: str | None = None
    history_unknown: bool = False

    @property
    def email(self) -> str:
        return self.address.email

    @property
    def domain_unicode(self) -> str:
        return unicode_domain(self.address.email.rpartition("@")[2].lower())


@dataclass(slots=True)
class Universe:
    """What a recipient is compared with."""

    addresses: set[str] = field(default_factory=set[str])
    domains: set[str] = field(default_factory=set[str])


def classify(
    recipients: Iterable[tuple[Field, Address]],
    *,
    own: Iterable[str],
    internal_domains: Iterable[str],
    known: Mapping[str, bool | None],
    history: Iterable[str],
) -> list[Classified]:
    """Classify recipients. ``known`` maps address -> written to before (``None`` =
    could not tell); ``history`` is the set of addresses the user wrote to (the
    look-alike universe)."""
    own_set = {a.lower() for a in own}
    internal = {d.lower() for d in internal_domains}
    hist = {a.lower() for a in history} | own_set
    domains = {_split(a)[1] for a in hist} | internal
    out: list[Classified] = []
    seen: set[str] = set()
    for fld, addr in recipients:
        email_addr = addr.email.lower()
        if email_addr in seen:
            continue
        seen.add(email_addr)
        local, domain = _split(email_addr)
        if email_addr in own_set or domain in internal:
            out.append(Classified(addr, fld, "internal"))
            continue
        notes: list[str] = []
        shown = unicode_domain(domain)
        if shown != domain:
            notes.append(f"internationalized domain, shown as {shown}")
        mixed = mixed_scripts(shown)
        if mixed:
            out.append(
                Classified(
                    addr,
                    fld,
                    "lookalike",
                    (*notes, f"the domain mixes {', '.join(mixed).lower()} letters"),
                )
            )
            continue
        twin = _find_twin(email_addr, hist, domains)
        is_known = known.get(email_addr)
        if twin is not None:
            why, other = twin
            if is_known:
                note = f"you have written to this address and to {other}, which look alike"
                note += f" (this one {why} it): one of them may be a typo"
            else:
                note = f"{why} {other}"
            out.append(Classified(addr, fld, "lookalike", (*notes, note), similar_to=other))
        elif is_known:
            out.append(Classified(addr, fld, "known", tuple(notes)))
        else:
            if is_known is None:
                notes.append("could not check whether you have written to this address before")
            out.append(Classified(addr, fld, "new", tuple(notes), history_unknown=is_known is None))
    return out


def _find_twin(email_addr: str, history: set[str], domains: set[str]) -> tuple[str, str] | None:
    best: tuple[str, str] | None = None
    for other in sorted(history):
        if other == email_addr:
            continue
        why = _relation(email_addr, other)
        if why is not None:
            if why.startswith(("is visually", "differs by")):
                return why, other
            best = best or (why, other)
    if best is not None:
        return best
    # Internal domains have no addresses in the history: compare the domain alone.
    _local, dom = _split(email_addr)
    for d in sorted(domains):
        if d != dom and (why := _domain_relation(dom, d)) is not None:
            return why, f"@{d}"
    return best


def count_by_class(items: Iterable[Classified]) -> dict[str, int]:
    out: dict[str, int] = dict.fromkeys(CLASSES, 0)
    for c in items:
        out[c.klass] += 1
    return out


class RecipientChecker:
    """Reads the sent-to history of the account that stores the user's Sent mail."""

    def __init__(
        self,
        router: AccountRouter,
        sent_to: SentToIndex,
        own_addresses: Callable[[], set[str]],
        internal_domains: Iterable[str],
    ) -> None:
        self.router = router
        self.sent_to = sent_to
        self._own = own_addresses
        self._internal = tuple(internal_domains)

    async def check(
        self, store: Account | None, recipients: list[tuple[Field, Address]]
    ) -> tuple[list[Classified], list[str]]:
        """``(classified, notes)``. Without a readable history every external
        recipient is ``new`` (unknown) - never silently ``known``."""
        notes: list[str] = []
        known: dict[str, bool | None] = {}
        history: set[str] = set()
        own = self._own()
        external = [a.email for _f, a in recipients if a.email.lower() not in own]
        if store is not None and external:

            def fn(session: ImapSession) -> tuple[dict[str, bool | None], frozenset[str]]:
                snap = self.sent_to.update(session, max_new=HISTORY_UPDATE_HEADERS)
                return self.sent_to.check(session, external), snap.addresses

            async def work(a: Account) -> tuple[dict[str, bool | None], frozenset[str]]:
                return await self.router.call(a, fn)

            try:
                known, hist = await self.router.run_one(store, work)
                history = set(hist)
            except MailError as e:
                notes.append(f"the history of sent mail could not be read ({e.code})")
        elif store is None and external:
            notes.append("no mailbox to read the history of sent mail from")
        return (
            classify(
                recipients,
                own=own,
                internal_domains=self._internal,
                known=known,
                history=history,
            ),
            notes,
        )
