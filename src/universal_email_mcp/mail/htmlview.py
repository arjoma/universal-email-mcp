"""Sanitising a mail's HTML for the portal viewer (design section 6.2).

The output is a complete HTML document that is only ever shown inside a sandboxed ``iframe``
(or served with a ``sandbox`` CSP of its own). Defence in depth, because the HTML is
attacker-controlled:

* **Allow-list sanitizer** (``nh3``, the Python binding of the Rust ``ammonia`` library):
  only formatting, table and image tags; no ``script``, ``style``, ``link``, ``meta``,
  ``base``, ``form``, ``input``, ``iframe``, ``object``, ``svg`` ... (their content goes with
  them). No event handlers, no ``class``/``id``, relative URLs are dropped.
* **Own CSS filter** for the ``style`` attribute: a short list of presentation properties,
  values without ``url()``, escapes, comments or functions other than colours/``calc``.
  ``<style>`` blocks are not kept at all, so there is no ``@import``/``@font-face``/selector
  based exfiltration.
* **Links** keep only ``http``, ``https``, ``mailto`` and ``tel`` targets and open in a new tab
  with ``rel="noopener noreferrer"``.
* **Images**: ``cid:`` references become ``data:`` URIs of the message's own raster images;
  ``data:image/...`` stays; remote ``https:`` images are dropped unless the caller allows
  them (the viewer's explicit "load remote images" click) and then still need the page's
  ``img-src``; ``http:`` is never loaded.
* The caller adds the CSP (:func:`csp`), which would stop all of the above even if the
  sanitizer had a hole.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Final

import nh3

from universal_email_mcp.mail.mime import (
    RASTER_IMAGE_TYPES,
    html_view_parts,
    normalize_cid,
    sanitize_text,
)

MAX_HTML_CHARS = 2_000_000
MAX_NESTING = 400
"""``ammonia`` takes time quadratic in the nesting depth; deeper input is refused."""
MAX_IMAGE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_IMAGE_BYTES = 8 * 1024 * 1024
MAX_LINKS = 100

_TAGS: Final = frozenset(
    "a abbr acronym address article aside b bdi bdo big blockquote br caption center cite code "
    "col colgroup dd del details dfn div dl dt em figcaption figure font footer h1 h2 h3 h4 h5 "
    "h6 header hr i img ins kbd li main mark nav ol p pre q s samp section small span strike "
    "strong sub summary sup table tbody td tfoot th thead time tr tt u ul var wbr".split()
)
_DROP_WITH_CONTENT: Final = frozenset(
    "script style head title template noscript object embed iframe frame frameset svg math "
    "xmp textarea select option button audio video canvas applet".split()
)
_ATTRIBUTES: Final = {
    "*": {"style", "dir", "lang", "title", "align", "valign", "bgcolor", "width", "height"},
    "a": {"href"},
    "img": {"src", "alt"},
    "font": {"color", "face", "size"},
    "table": {"border", "cellpadding", "cellspacing"},
    "td": {"colspan", "rowspan", "nowrap"},
    "th": {"colspan", "rowspan", "nowrap"},
    "col": {"span"},
    "colgroup": {"span"},
    "ol": {"start", "type"},
    "ul": {"type"},
    "li": {"value"},
    "time": {"datetime"},
}
_SCHEMES: Final = {"http", "https", "mailto", "tel", "data", "cid"}
_LINK_SCHEMES: Final = ("http:", "https:", "mailto:", "tel:")

_CSS_PROPERTIES: Final = frozenset(
    "background background-color border border-bottom border-bottom-color border-bottom-style "
    "border-bottom-width border-collapse border-color border-left border-left-color "
    "border-left-style border-left-width border-radius border-right border-right-color "
    "border-right-style border-right-width border-spacing border-style border-top "
    "border-top-color border-top-style border-top-width border-width color direction display "
    "font font-family font-size font-style font-variant font-weight height letter-spacing "
    "line-height list-style-type margin margin-bottom margin-left margin-right margin-top "
    "max-width min-width max-height min-height opacity overflow-wrap padding padding-bottom "
    "padding-left padding-right padding-top table-layout text-align text-decoration "
    "text-indent text-transform vertical-align visibility white-space width word-break "
    "word-spacing".split()
)
_CSS_VALUE_OK: Final = re.compile(r"^[\w\s#%.,()+\-!/\"']*$")
_CSS_FUNCTION: Final = re.compile(r"([a-zA-Z-]*)\s*\(")
_CSS_FUNCTIONS: Final = frozenset({"rgb", "rgba", "hsl", "hsla", "calc"})
_DATA_IMAGE: Final = re.compile(
    r"^data:image/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/=\s]{1,3000000}$", re.IGNORECASE
)
_TAG: Final = re.compile(r"<(/?)([A-Za-z][A-Za-z0-9]*)[^<>]*?(/?)>")
_VOID: Final = frozenset("area base br col embed hr img input link meta source track wbr".split())


class TooComplex(Exception):
    """The HTML nests too deeply to be sanitised in reasonable time."""


def clean_style(value: str) -> str | None:
    """A ``style`` attribute reduced to allow-listed presentation declarations, or ``None``."""
    kept: list[str] = []
    for decl in value.split(";"):
        name, sep, val = decl.partition(":")
        name = name.strip().lower()
        val = val.strip()
        if not sep or name not in _CSS_PROPERTIES or not val or len(val) > 200:
            continue
        if not _CSS_VALUE_OK.match(val) or "\\" in val or "/*" in val:
            continue
        if any(f.lower() not in _CSS_FUNCTIONS for f in _CSS_FUNCTION.findall(val)):
            continue
        kept.append(f"{name}:{val}")
    return ";".join(kept) or None


def _depth_ok(html: str) -> bool:
    depth = 0
    for m in _TAG.finditer(html):
        tag = m.group(2).lower()
        if m.group(1):
            depth = max(0, depth - 1)
        elif not m.group(3) and tag not in _VOID:
            depth += 1
            if depth > MAX_NESTING:
                return False
    return True


@dataclass(frozen=True, slots=True)
class HtmlView:
    document: str | None
    """The sanitised page, ``None`` when the message has no HTML part."""
    remote_images: int = 0
    """Remote images the message refers to (``https:``)."""
    images_loaded: bool = False
    links: tuple[str, ...] = ()
    """Link targets (``http``/``https``/``mailto``/``tel``), distinct, in order of appearance."""


_PAGE_STYLE: Final = (
    "body{margin:8px;background:#fff;color:#111;font:15px/1.45 system-ui,sans-serif;"
    "overflow-wrap:anywhere}img{max-width:100%;height:auto}table{max-width:100%}"
    "a{color:#1a56b0}"
)


def csp(*, remote_images: bool, ancestor: str) -> str:
    """The CSP of the HTML document: nothing but inline presentation and ``data:`` images
    (plus ``https:`` images when the user asked for them). No script, frame, font, form,
    media, connection or base-URI source at all, and the document is sandboxed itself."""
    img = "data: https:" if remote_images else "data:"
    return (
        f"default-src 'none'; img-src {img}; style-src 'unsafe-inline'; base-uri 'none'; "
        f"form-action 'none'; frame-ancestors {ancestor}; "
        "sandbox allow-popups allow-popups-to-escape-sandbox"
    )


def sanitize_html(
    html: str, images: dict[str, tuple[str, bytes]], *, remote_images: bool
) -> tuple[str, int, tuple[str, ...]]:
    """``(clean fragment, remote image count, links)``; raises :class:`TooComplex`."""
    html = sanitize_text(html)
    if not _depth_ok(html):
        raise TooComplex
    remote = 0
    links: dict[str, None] = {}

    def attribute_filter(tag: str, attr: str, value: str) -> str | None:
        nonlocal remote
        if attr == "style":
            return clean_style(value)
        if attr == "href" and tag == "a":
            href = " ".join(value.split())
            if not href.lower().startswith(_LINK_SCHEMES):
                return None
            if len(links) < MAX_LINKS:
                links.setdefault(href[:2000], None)
            return href
        if attr == "src" and tag == "img":
            src = value.strip()
            low = src.lower()
            if low.startswith("cid:"):
                found = images.get(normalize_cid(src))
                if found is None:
                    return None
                return f"data:{found[0]};base64,{base64.b64encode(found[1]).decode('ascii')}"
            if low.startswith("data:"):
                return src if _DATA_IMAGE.match(src) else None
            if low.startswith("https://"):
                remote += 1
                return src if remote_images else None
            return None
        if attr in ("width", "height", "colspan", "rowspan", "span", "border", "size", "start"):
            return value if re.fullmatch(r"[0-9]{1,5}%?", value.strip()) else None
        return value

    cleaner = nh3.Cleaner(
        tags=set(_TAGS),
        clean_content_tags=set(_DROP_WITH_CONTENT),
        attributes={k: set(v) for k, v in _ATTRIBUTES.items()},
        attribute_filter=attribute_filter,
        strip_comments=True,
        link_rel="noopener noreferrer",
        url_schemes=set(_SCHEMES),
        url_relative="deny",
        set_tag_attribute_values={"a": {"target": "_blank"}},
    )
    return cleaner.clean(html), remote, tuple(links)


def build_html_view(raw: bytes, *, remote_images: bool = False) -> HtmlView:
    """Sanitised HTML document for the message in ``raw`` (``document=None``: no HTML part).

    :raises TooComplex: the HTML nests too deeply (the caller shows the text version)."""
    parts = html_view_parts(
        raw,
        max_html_chars=MAX_HTML_CHARS,
        max_image_bytes=MAX_IMAGE_BYTES,
        max_total_bytes=MAX_TOTAL_IMAGE_BYTES,
    )
    if not parts.html:
        return HtmlView(None)
    bodies: list[str] = []
    remote_total = 0
    links: dict[str, None] = {}
    for html in parts.html:
        body, remote, found = sanitize_html(html, parts.images, remote_images=remote_images)
        bodies.append(body)
        remote_total += remote
        links.update(dict.fromkeys(found))
    document = (
        '<!doctype html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f"<style>{_PAGE_STYLE}</style></head><body>" + "<hr>".join(bodies) + "</body></html>"
    )
    return HtmlView(
        document,
        remote_images=remote_total,
        images_loaded=remote_images and remote_total > 0,
        links=tuple(links)[:MAX_LINKS],
    )


__all__ = ["RASTER_IMAGE_TYPES", "HtmlView", "TooComplex", "build_html_view", "csp"]
