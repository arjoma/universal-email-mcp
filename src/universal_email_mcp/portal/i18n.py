"""The translation layer of the end-user UI (AGENTS.md: translatable from the start).

Templates never contain visible text of their own: every string goes through ``_()``
(or ``{% trans %}``). The *message id is the English text* (gettext style), so English needs
no catalog at all; a language is a JSON file ``locales/<code>.json`` that maps English text
to its translation (``{"Sign in": "Anmelden"}``). English and German ship.

Which language a request gets: the user's choice (cookie ``uem_lang``) first, then the
browser's ``Accept-Language``, then the operator's default language, then English.
:func:`extract_messages` lists every message id used by the templates, which is how a
translator's catalog is created and checked.
"""

from __future__ import annotations

import gettext
import io
import json
import re
from datetime import datetime
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path
from typing import Any

import jinja2
from jinja2.ext import babel_extract

from universal_email_mcp.portal.dynamic import DYNAMIC_MESSAGES, translate_dynamic

PORTAL_DIR = Path(__file__).parent
TEMPLATE_DIR = PORTAL_DIR / "templates"
LOCALE_DIR = PORTAL_DIR / "locales"
DEFAULT_LANGUAGE = "en"
LANG_COOKIE = "uem_lang"
LANGUAGE_NAMES = {
    "en": "English",
    "de": "Deutsch",
    "fr": "Français",
    "es": "Español",
    "it": "Italiano",
    "nl": "Nederlands",
    "pt": "Português",
}
"""Names of languages in themselves (never translated); unknown codes show as the code."""
TIME_FORMAT = "%Y-%m-%d %H:%M UTC"
"""How the Python layer writes times (``strftime``); it is also a message id, so a language
can show them in its own order (German: ``%d.%m.%Y %H:%M UTC``)."""
_LANG_RE = re.compile(r"^[a-z]{2,3}(-[a-z0-9]{2,8})?$")


class Catalog(gettext.NullTranslations):
    """English text -> translation; unknown messages are returned unchanged."""

    def __init__(self, messages: Mapping[str, str] | None = None) -> None:
        super().__init__()
        self._messages = dict(messages or {})

    def gettext(self, message: str) -> str:
        return self._messages.get(message) or message

    def ngettext(self, msgid1: str, msgid2: str, n: int) -> str:
        singular = n == 1
        key = msgid1 if singular else msgid2
        return self._messages.get(key) or key


def language_name(code: str) -> str:
    return LANGUAGE_NAMES.get(code.split("-", 1)[0], code)


def load_catalogs(directory: Path = LOCALE_DIR) -> dict[str, Catalog]:
    """``locales/<code>.json`` files; ``en`` always exists (identity)."""
    out: dict[str, Catalog] = {DEFAULT_LANGUAGE: Catalog()}
    for path in sorted(directory.glob("*.json")):
        code = path.stem.lower()
        if not _LANG_RE.match(code):
            continue
        data: Any = json.loads(path.read_text(encoding="utf-8"))
        out[code] = Catalog({str(k): str(v) for k, v in data.items()})
    return out


def parse_accept_language(header: str) -> list[str]:
    """Language codes in the order of their quality values (no ``*``, no junk)."""
    ranked: list[tuple[float, int, str]] = []
    for i, item in enumerate(header.split(",")[:20]):
        code, _, params = item.strip().partition(";")
        code = code.strip().lower()
        if not _LANG_RE.match(code):
            continue
        q = 1.0
        m = re.search(r"q\s*=\s*([0-9.]+)", params)
        if m:
            try:
                q = float(m.group(1))
            except ValueError:
                q = 0.0
        if q > 0:
            ranked.append((-q, i, code))
    return [c for _, _, c in sorted(ranked)]


def resolve_locale(
    available: Iterable[str],
    *,
    cookie: str | None = None,
    accept_language: str = "",
    default: str = DEFAULT_LANGUAGE,
) -> str:
    """Pick the language: cookie, browser preference, operator default, English."""
    have = set(available)

    def pick(code: str | None) -> str | None:
        if not code:
            return None
        code = code.lower()
        if code in have:
            return code
        base = code.split("-", 1)[0]
        return base if base in have else None

    for candidate in [cookie, *parse_accept_language(accept_language), default]:
        found = pick(candidate)
        if found:
            return found
    return DEFAULT_LANGUAGE


class Translator:
    """Jinja environments per language over the shared templates."""

    def __init__(
        self,
        catalogs: Mapping[str, Catalog] | None = None,
        template_dir: Path = TEMPLATE_DIR,
    ) -> None:
        self.catalogs: dict[str, Catalog] = dict(catalogs or load_catalogs())
        self._dir = template_dir
        self._envs: dict[str, jinja2.Environment] = {}

    @property
    def languages(self) -> tuple[str, ...]:
        return tuple(self.catalogs)

    def env(self, lang: str) -> jinja2.Environment:
        lang = lang if lang in self.catalogs else DEFAULT_LANGUAGE
        env = self._envs.get(lang)
        if env is None:
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(self._dir),
                autoescape=jinja2.select_autoescape(["html"], default=True),
                extensions=["jinja2.ext.i18n"],
                undefined=jinja2.StrictUndefined,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            catalog = self.catalogs[lang]
            env.install_gettext_callables(  # pyright: ignore[reportAttributeAccessIssue,reportUnknownMemberType]
                catalog.gettext, catalog.ngettext, newstyle=True
            )
            env.filters["tr"] = lambda text: translate_dynamic(catalog.gettext, str(text))
            env.filters["when"] = lambda text: _localize_time(catalog, str(text))
            self._envs[lang] = env
        return env

    def render(self, template: str, lang: str, **context: Any) -> str:
        return self.env(lang).get_template(template).render(lang=lang, **context)


def _localize_time(catalog: Catalog, text: str) -> str:
    """A time written with :data:`TIME_FORMAT` in the language's own format (else unchanged)."""
    fmt = catalog.gettext(TIME_FORMAT)
    if fmt == TIME_FORMAT:
        return text
    try:
        return datetime.strptime(text, TIME_FORMAT).strftime(fmt)
    except ValueError:
        return text


def extract_messages(template_dir: Path = TEMPLATE_DIR) -> list[str]:
    """Every message id the pages use (templates, dynamic sentences, the time format; sorted,
    unique) - the translator's worklist."""
    env = jinja2.Environment(extensions=["jinja2.ext.i18n"])
    found: set[str] = set()
    for path in sorted(template_dir.glob("*.html")):
        source = io.BytesIO(path.read_bytes())
        extractor: Callable[..., Any] = babel_extract
        for _line, _func, message, _comments in extractor(
            source, ("_", "gettext", "ngettext"), [], {"silent": "false"}
        ):
            items = message if isinstance(message, tuple) else (message,)
            found.update(m for m in items if isinstance(m, str))  # pyright: ignore[reportUnknownVariableType]
    del env
    found.update(DYNAMIC_MESSAGES)
    found.add(TIME_FORMAT)
    return sorted(found)
