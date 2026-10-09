"""Building blocks of the HTML pages: rendering, cookies, CSRF, security headers.

Used by the OAuth sign-in and consent pages now and by the portal (WP 3d) later, so there
is one place that decides how a page, a cookie and a form token look.

* Cookies are ``__Host-`` prefixed (Secure, Path=/, no Domain) when the public URL is
  https; on a plain-http loopback URL (development) the prefix and ``Secure`` are dropped
  because browsers would refuse them. ``HttpOnly`` and ``SameSite=Lax`` always.
* CSRF: a random token in a cookie and the same value in a hidden form field (double
  submit); the ``__Host-`` prefix keeps sibling sites from planting the cookie. POSTs
  that browsers mark ``Sec-Fetch-Site: cross-site`` are refused outright.
* Every page: strict CSP (own origin stylesheet, no scripts at all), ``frame-ancestors
  'none'`` plus ``X-Frame-Options: DENY``, ``no-store``, ``Referrer-Policy: same-origin``.
"""

from __future__ import annotations

import hmac
import ipaddress
import secrets
from typing import Any

from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from universal_email_mcp.oauth.config import OAuthConfig
from universal_email_mcp.portal.i18n import LANG_COOKIE, Translator, resolve_locale

CSRF_BYTES = 32
CSRF_FIELD = "csrf_token"
MAX_FORWARDED_BYTES = 1024


def client_ip(request: Request, trusted_hops: int) -> str:
    """The caller's address. With ``trusted_hops`` reverse proxies in front, the entry that
    many places from the right of ``X-Forwarded-For`` (the one the first trusted proxy saw);
    otherwise the socket peer. Never trusts more than the operator declared."""
    peer = request.client.host if request.client else ""
    if trusted_hops <= 0:
        return peer
    # Only the right-hand entries matter; a hostile megabyte header is not parsed whole.
    header = request.headers.get("x-forwarded-for", "")[-MAX_FORWARDED_BYTES:]
    chain = [p.strip() for p in header.split(",") if p.strip()]
    if len(chain) < trusted_hops:
        return peer
    candidate = chain[-trusted_hops]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer


class Portal:
    def __init__(self, cfg: OAuthConfig, translator: Translator | None = None) -> None:
        self.cfg = cfg
        self.translator = translator or Translator()

    # -- cookies ----------------------------------------------------------------------

    def cookie_name(self, base: str) -> str:
        return f"__Host-uem_{base}" if self.cfg.secure_cookies else f"uem_{base}"

    def _set_cookie(self, response: Response, base: str, value: str) -> None:
        response.set_cookie(
            self.cookie_name(base),
            value,
            path="/",
            httponly=True,
            secure=self.cfg.secure_cookies,
            samesite="lax",
        )

    def delete_cookie(self, response: Response, base: str) -> None:
        response.delete_cookie(
            self.cookie_name(base),
            path="/",
            httponly=True,
            secure=self.cfg.secure_cookies,
            samesite="lax",
        )

    def session_cookie(self, request: Request) -> str | None:
        return request.cookies.get(self.cookie_name("session")) or None

    def set_session(self, response: Response, raw: str) -> None:
        self._set_cookie(response, "session", raw)

    # -- CSRF -------------------------------------------------------------------------

    def csrf_token(self, request: Request) -> str:
        """The token to embed in a form: the cookie's value, or a fresh one."""
        existing = request.cookies.get(self.cookie_name("csrf"))
        if existing and len(existing) >= CSRF_BYTES:
            return existing
        return secrets.token_urlsafe(CSRF_BYTES)

    def set_csrf(self, response: Response, token: str) -> None:
        self._set_cookie(response, "csrf", token)

    def rotate_csrf(self, response: Response) -> None:
        self.set_csrf(response, secrets.token_urlsafe(CSRF_BYTES))

    def check_csrf(self, request: Request, form: FormData) -> bool:
        if request.headers.get("sec-fetch-site", "same-origin") not in ("same-origin", "none"):
            return False
        cookie = request.cookies.get(self.cookie_name("csrf"), "")
        field = form.get(CSRF_FIELD)
        if not cookie or len(cookie) < CSRF_BYTES or not isinstance(field, str):
            return False
        return hmac.compare_digest(cookie.encode(), field.encode())

    # -- pages ------------------------------------------------------------------------

    def locale(self, request: Request) -> str:
        return resolve_locale(
            self.translator.languages,
            cookie=request.cookies.get(LANG_COOKIE),
            accept_language=request.headers.get("accept-language", ""),
            default=self.cfg.default_language,
        )

    def page(
        self,
        request: Request,
        template: str,
        *,
        status: int = 200,
        csrf: bool = True,
        form_action_extra: str = "",
        frame_src: str = "",
        headers: dict[str, str] | None = None,
        **context: Any,
    ) -> HTMLResponse:
        token = self.csrf_token(request) if csrf else ""
        lang = self.locale(request)
        body = self.translator.render(template, lang, csrf_token=token, **context)
        response = HTMLResponse(body, status_code=status, headers=headers)
        security_headers(response, form_action_extra, frame_src)
        response.headers["content-language"] = lang
        if csrf:
            self.set_csrf(response, token)
        return response


def security_headers(response: Response, form_action_extra: str = "", frame_src: str = "") -> None:
    """``frame_src``: where the page may embed a frame from (the message viewer's sandboxed
    HTML view); no frames at all otherwise."""
    form_action = "'self'" + (f" {form_action_extra}" if form_action_extra else "")
    frames = f"frame-src {frame_src}; " if frame_src else ""
    response.headers["content-security-policy"] = (
        "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; "
        f"{frames}form-action {form_action}; frame-ancestors 'none'"
    )
    response.headers["x-frame-options"] = "DENY"
    response.headers["cache-control"] = "no-store"
    response.headers["pragma"] = "no-cache"
    # Not "no-referrer": with it browsers send "Origin: null" on our own form POSTs, which the
    # Origin check rightly refuses. "same-origin" sends the real origin to us and nothing
    # (neither Origin nor Referer) to the redirect target of the OAuth client.
    response.headers["referrer-policy"] = "same-origin"
