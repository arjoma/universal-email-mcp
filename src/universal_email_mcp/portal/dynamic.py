"""Server-generated sentences that the pages show next to the template text.

Some texts reach a page as finished English strings because the service layer builds them
(and the MCP tools show the very same strings to the AI client, which stays English): the
recipient notes and send warnings of the approval page, the notes of the message viewer.
Rewording them at the source would change the tool output, so the portal translates them
here: each entry is an English *pattern* with ``%(name)s`` holes, matched against the whole
line; the match goes through the language catalog like any other message id. A line no
pattern fits is shown as it is (English) - never dropped, never guessed.

The holes can contain anything (mail data!): they are only substituted, and the result is
escaped by the template like every other value.
"""

from __future__ import annotations

import re
from collections.abc import Callable

DYNAMIC_MESSAGES: tuple[str, ...] = (
    # recipient classes and the notes that explain them
    "internal",
    "written to before",
    "NEW - never written to",
    "NEW - history unknown",
    "LOOK-ALIKE",
    "internationalized domain, shown as %(domain)s",
    "the domain mixes %(scripts)s letters",
    "could not check whether you have written to this address before",
    "the history of sent mail could not be read (%(code)s)",
    "no mailbox to read the history of sent mail from",
    "is visually identical to %(other)s",
    "differs by a typo from %(other)s",
    "uses a look-alike of the domain of %(other)s",
    "uses a look-alike of the domain %(other)s",
    "has a domain that differs by a typo from %(other)s",
    "has the same name but another top-level domain than %(other)s",
    "uses a domain one typo away from that of %(other)s",
    "uses a domain one typo away from the domain %(other)s",
    # why the user is asked
    "%(n)s recipient(s) look like other addresses",
    "the policy asks for confirmation of every message",
    "the message goes to recipients outside your organisation",
    # what is shown of the message, and what is not
    "... %(cut)s more characters (%(lines)s lines) of the text NOT shown",
    "... %(n)s more characters beyond the first %(max)s NOT shown",
    "... %(n)s more characters of the HTML version NOT shown",
    "... %(n)s more characters of this part NOT shown",
    "... %(n)s more text part(s) NOT shown",
    "HTML version (differs from the text above - recipients with an HTML mail client "
    "read this):",
    "HTML version (the message has no plain text part - recipients read this):",
    "Additional text part %(n)s (%(kind)s):",
    "! The HTML version loads %(n)s remote image(s): they can tell the sender when and where "
    "the mail is read (tracking).",
    # warnings about the draft
    "the draft has no subject",
    "the draft has no recipient yet",
    "a recipient is one of your own addresses",
    "the original is very large; only its beginning is quoted",
    "%(n)s inline part(s) (images in the text) are not included in the plain-text draft",
    "not attached (more than %(n)s files): %(name)s",
    "not attached (total size limit %(n)s bytes): %(name)s",
    "not attached (larger than the %(n)s byte limit): %(name)s",
    "could not check whether you have written to the recipients before",
    "you have not written to these recipients before: %(list)s",
    "could not tell whether you have written to: %(list)s",
    "the server did not report the new draft's id; find it in the Drafts folder",
    "the server did not report the new draft's id, so it cannot be removed after sending",
    # what happened after sending
    "no copy in Sent: the SMTP server files its own",
    "no copy in Sent: the account has no Sent folder",
    "copy into %(folder)s failed: %(detail)s",
    "the draft could not be removed (%(detail)s)",
    "the draft was removed",
    "the draft stays in Drafts (%(outcome)s); delete it by hand",
    "the message was sent, but saving the copy / removing the draft failed: %(detail)s",
    "the original is marked as answered",
    "the original was not marked as answered (unknown account)",
    "the original was not marked as answered (no 'organize' or 'drafts' permission)",
    "the original was not marked as answered (invalid reference)",
    "the original was not marked as answered (it is gone)",
    "the original was not marked as answered (%(code)s)",
    # notes of the message viewer
    "%(n)s text parts: the body shows the first %(shown)s, the other %(extra)s are listed "
    "as attachments",
    "HTML part %(section)s is too long; only its beginning is shown",
    "%(n)s HTML part not converted (size limit), listed as attachments: %(names)s",
    "%(n)s HTML parts not converted (size limit), listed as attachments: %(names)s",
    "%(n)s more parts not listed (at most %(max)s)",
    "the message has no Message-ID; showing it alone",
)

_HOLE = re.compile(r"%\((\w+)\)s")


def _pattern(message: str) -> re.Pattern[str]:
    out: list[str] = []
    pos = 0
    for m in _HOLE.finditer(message):
        out.append(re.escape(message[pos : m.start()]))
        out.append(f"(?P<{m.group(1)}>.*?)")
        pos = m.end()
    out.append(re.escape(message[pos:]))
    return re.compile("".join(out), re.DOTALL)


_PATTERNS = tuple((m, _pattern(m)) for m in DYNAMIC_MESSAGES)


def translate_dynamic(translate: Callable[[str], str], text: str) -> str:
    """``text`` (one or several lines) with every line that fits a known pattern translated."""
    lines: list[str] = []
    for line in text.split("\n"):
        for message, pattern in _PATTERNS:
            m = pattern.fullmatch(line)
            if m is None:
                continue
            try:
                line = translate(message) % {k: v or "" for k, v in m.groupdict().items()}
            except (KeyError, ValueError, TypeError):
                pass  # a broken catalog entry: keep the English line
            break
        lines.append(line)
    return "\n".join(lines)
