"""The OAuth 2.1 endpoints: metadata, ``/authorize``, ``/token``, ``/revoke``, ``/register``.

Flow (design section 6.1): the client sends the user's browser to ``/authorize`` ->
sign-in with the mailbox login (if there is no portal session) -> consent page with the
grants -> redirect back with a single-use code (``iss`` included, RFC 9207) -> ``/token``
exchanges code + PKCE verifier for an opaque access token (audience = the MCP endpoint,
RFC 8707) and a rotating refresh token.

Everything the browser or the client sends is untrusted and re-validated on every request: the
authorization parameters travel in hidden form fields from page to page and are parsed again
on each POST, so there is no server-side "pending request" state to fix, expire or exhaust.
Errors that cannot be sent back safely (unknown client, unregistered redirect URI) are shown
on a page and never redirected (OAuth 2.1 section 4.1.2.1).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from universal_email_mcp.errors import MailError
from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.oauth import pkce, signin
from universal_email_mcp.oauth.clients import (
    ClientError,
    ClientInfo,
    RegistrationError,
    parse_registration,
)
from universal_email_mcp.oauth.config import (
    ACCOUNT_SCOPES,
    SCOPE_READ,
    SCOPE_SEND,
    permission_of,
)
from universal_email_mcp.oauth.ratelimit import RateLimiter, ip_group
from universal_email_mcp.oauth.redirects import (
    RedirectError,
    display_host,
    redirect_matches,
    validate_redirect_uri,
)
from universal_email_mcp.oauth.service import OAuthService, oauth_error, same_resource
from universal_email_mcp.portal import ops
from universal_email_mcp.portal.assets import PORTAL_CSS
from universal_email_mcp.portal.web import client_ip, security_headers
from universal_email_mcp.server.http import RouteGroup
from universal_email_mcp.store import (
    Grant,
    Identity,
    InvalidToken,
    MailAccount,
    OAuthClient,
    PortalSession,
    Token,
    User,
)

log = logging.getLogger(__name__)

MAX_PARAM = 512
MAX_REGISTER_BYTES = 8 * 1024

_AUTHZ_FIELDS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "state",
    "code_challenge",
    "code_challenge_method",
    "scope",
    "resource",
)


# ---------------------------------------------------------------- authorization request


@dataclass(frozen=True, slots=True)
class AuthzRequest:
    client: ClientInfo
    redirect_uri: str
    state: str
    code_challenge: str
    resource: str
    scopes: tuple[str, ...]
    """What the client asked for (recognised and offered scopes only)."""

    def hidden(self) -> dict[str, str]:
        """The request as hidden form fields (every page re-submits it)."""
        out = {
            "response_type": "code",
            "client_id": self.client.id,
            "redirect_uri": self.redirect_uri,
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "scope": " ".join(self.scopes),
            "resource": self.resource,
        }
        if self.state:
            out["state"] = self.state
        return out


def add_query(uri: str, params: Mapping[str, str]) -> str:
    parts = urlsplit(uri)
    query = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunsplit(parts._replace(query=urlencode(query)))


def _repeated(source: Any, names: Iterable[str] | None = None) -> bool:
    """Is a parameter (of ``names``, default all) sent more than once? RFC 6749 section 3.1:
    parameters must not be included more than once, and "last value wins" is how a
    proxy and this server could disagree."""
    seen: set[str] = set()
    watched = None if names is None else set(names)
    for key, _ in source.multi_items():
        if (watched is None or key in watched) and key in seen:
            return True
        seen.add(key)
    return False


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate member name")
    return dict(pairs)


def _params(source: Mapping[str, Any]) -> dict[str, str]:
    """Only the known authorization fields, only plain strings, length-capped."""
    out: dict[str, str] = {}
    for name in _AUTHZ_FIELDS:
        value = source.get(name)
        if isinstance(value, str):
            out[name] = value
    return out


def _error_page(svc: OAuthService, request: Request, reason: str, status: int = 400) -> Response:
    return svc.portal.page(request, "error.html", status=status, csrf=False, reason=reason)


@dataclass(frozen=True, slots=True)
class Row:
    id: str
    name: str
    available: tuple[str, ...]
    checked: tuple[str, ...]


# ---------------------------------------------------------------- the endpoints


class OAuthEndpoints:
    def __init__(self, svc: OAuthService) -> None:
        self.svc = svc

    # -- metadata ---------------------------------------------------------------------

    async def authorization_server_metadata(self, _: Request) -> Response:
        cfg = self.svc.cfg
        meta: dict[str, Any] = {
            "issuer": cfg.issuer,
            "authorization_endpoint": cfg.url("/authorize"),
            "token_endpoint": cfg.url("/token"),
            "revocation_endpoint": cfg.url("/revoke"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": list(cfg.offered_scopes),
            "authorization_response_iss_parameter_supported": True,
            "client_id_metadata_document_supported": True,
            "ui_locales_supported": list(self.svc.portal.translator.languages),
        }
        if cfg.dcr_enabled:
            meta["registration_endpoint"] = cfg.url("/register")
        return _metadata_response(meta)

    async def protected_resource_metadata(self, _: Request) -> Response:
        cfg = self.svc.cfg
        return _metadata_response(
            {
                "resource": cfg.resource,
                "authorization_servers": [cfg.issuer],
                "scopes_supported": list(cfg.offered_scopes),
                "bearer_methods_supported": ["header"],
                "resource_name": "Universal e-mail",
            }
        )

    async def stylesheet(self, _: Request) -> Response:
        return Response(
            PORTAL_CSS,
            media_type="text/css",
            headers={"cache-control": "public, max-age=3600", "x-content-type-options": "nosniff"},
        )

    # -- /authorize -------------------------------------------------------------------

    async def authorize_get(self, request: Request) -> Response:
        if _repeated(request.query_params, _AUTHZ_FIELDS):
            return _error_page(self.svc, request, "invalid")
        parsed = await self._parse(request, _params(request.query_params))
        if isinstance(parsed, Response):
            return parsed
        session = await self._session(request)
        if session is None:
            return self._signin_page(request, parsed)
        return await self._consent_page(request, parsed, session)

    @staticmethod
    def _too_many(
        limiter: RateLimiter, ip: str, description: str, error: str = "invalid_request"
    ) -> Response:
        wait = limiter.retry_after(ip_group(ip)) or 1
        return oauth_error(error, description, status=429, headers={"retry-after": str(wait)})

    async def authorize_post(self, request: Request) -> Response:
        ip = client_ip(request, self.svc.cfg.trusted_proxy_hops)
        if not self.svc.limits.authorize_ip.allow(ip_group(ip)):
            await self.svc.audit("ratelimit.hit", scope="authorize_ip", ip=ip)
            wait = self.svc.limits.authorize_ip.retry_after(ip_group(ip)) or 1
            response = _error_page(self.svc, request, "busy", 429)
            response.headers["retry-after"] = str(wait)
            return response
        form = await request.form()
        if _repeated(form, (*_AUTHZ_FIELDS, "action")):
            return _error_page(self.svc, request, "invalid")
        parsed = await self._parse(request, _params(form))
        if isinstance(parsed, Response):
            return parsed
        session = await self._session(request)
        if not self.svc.portal.check_csrf(request, form):
            await self.svc.audit("auth.csrf_failed")
            if session is None:
                return self._signin_page(request, parsed, error="csrf", status=403)
            return await self._consent_page(request, parsed, session, error="csrf", status=403)
        action = form.get("action")
        if action == "signin":
            return await self._sign_in(request, form, parsed)
        if action == "signout":
            return await self._sign_out(request, parsed)
        if session is None:
            return self._back_to_authorize(request, parsed)
        if action == "deny":
            await self.svc.audit("auth.consent", outcome="denied", client=parsed.client.id)
            return self._continue_page(request, parsed, error="access_denied")
        if action == "approve":
            return await self._approve(request, form, parsed, session)
        return _error_page(self.svc, request, "invalid")

    async def _parse(self, request: Request, params: dict[str, str]) -> AuthzRequest | Response:
        svc = self.svc
        if any(len(v) > 2000 for v in params.values()):
            return _error_page(svc, request, "invalid")
        client_id = params.get("client_id", "")
        if not client_id or len(client_id) > 512:
            return _error_page(svc, request, "invalid")
        ip = client_ip(request, svc.cfg.trusted_proxy_hops)
        try:
            client = await svc.clients.resolve(client_id, ip=ip)
        except ClientError as e:
            log_event(log, logging.INFO, "client refused", event="auth.client", reason=e.detail)
            await svc.audit("auth.client_refused", client=client_id)
            busy = "Too many requests" in str(e)
            return _error_page(svc, request, "busy" if busy else "client", 429 if busy else 400)
        redirect_uri = params.get("redirect_uri", "")
        if not redirect_uri:
            if len(client.redirect_uris) != 1:
                return _error_page(svc, request, "redirect")
            redirect_uri = client.redirect_uris[0]
        try:
            validate_redirect_uri(redirect_uri)
        except RedirectError:
            return _error_page(svc, request, "redirect")
        if not redirect_matches(client.redirect_uris, redirect_uri):
            await svc.audit("auth.redirect_refused", client=client_id)
            return _error_page(svc, request, "redirect")

        state = params.get("state", "")
        if len(state) > MAX_PARAM:
            return _error_page(svc, request, "invalid")

        def fail(error: str, description: str) -> Response:
            # Not redirected: anyone can register a client, so redirecting protocol errors
            # would make /authorize an open redirect (RFC 9700 4.11.2). Only the user's own
            # decision (access_denied) goes back to the client.
            log_event(
                log, logging.INFO, "authorization request refused",
                event="auth.request", error=error, detail=description,
            )  # fmt: skip
            return _error_page(svc, request, "invalid")

        if params.get("response_type") != "code":
            return fail("unsupported_response_type", "only response_type=code is supported")
        challenge = params.get("code_challenge", "")
        if not pkce.valid_challenge(challenge) or params.get("code_challenge_method") != "S256":
            return fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
        resource = params.get("resource", "")
        if resource and not same_resource(resource, svc.cfg.resource):
            return fail("invalid_target", "unknown resource")
        requested = params.get("scope", "").split()
        offered = svc.cfg.offered_scopes
        scopes = tuple(s for s in dict.fromkeys(requested) if s in offered)
        if requested and not scopes:
            return fail("invalid_scope", "none of the requested scopes is available")
        if not requested:
            scopes = offered
        if SCOPE_READ in offered and SCOPE_READ not in scopes:
            scopes = (SCOPE_READ, *scopes)
        return AuthzRequest(client, redirect_uri, state, challenge, svc.cfg.resource, scopes)

    # -- pages ------------------------------------------------------------------------

    def _page_context(self, req: AuthzRequest) -> dict[str, Any]:
        return {
            "client": req.client,
            "redirect_host": display_host(req.redirect_uri),
            "hidden": req.hidden(),
        }

    def _signin_page(
        self,
        request: Request,
        req: AuthzRequest,
        *,
        error: str = "",
        status: int = 200,
        address: str = "",
    ) -> Response:
        return self.svc.portal.page(
            request,
            "signin.html",
            status=status,
            error=error,
            address=address,
            **self._page_context(req),
        )

    async def _rows(self, user: User) -> tuple[list[Row], list[tuple[str, str]]]:
        """What the user can hand out: their accounts (per scope: the account's own
        permissions within what the operator offers) and the identities that may send."""
        store, offered = self.svc.store, self.svc.cfg.offered_scopes
        account_scopes = tuple(s for s in ACCOUNT_SCOPES if s in offered)
        rows = [
            Row(
                a.id,
                a.name,
                tuple(s for s in account_scopes if permission_of(s) in a.permissions),
                (),
            )
            for a in await store.list_for_user(MailAccount, user.id)
        ]
        identities: list[tuple[str, str]] = []
        if SCOPE_SEND in offered:
            for ident in await store.list_for_user(Identity, user.id):
                if not ident.send:
                    continue
                address = ident.addresses[0] if ident.addresses else ident.id
                label = f"{ident.display_name} <{address}>" if ident.display_name else address
                identities.append((ident.id, label))
        return rows, identities

    async def _consent_page(
        self,
        request: Request,
        req: AuthzRequest,
        session: PortalSession,
        *,
        error: str = "",
        status: int = 200,
    ) -> Response:
        user = await self.svc.store.get(User, session.user_id)
        if user is None:
            return self._signin_page(request, req)
        rows, identities = await self._rows(user)
        wanted = tuple(s for s in ACCOUNT_SCOPES if s in req.scopes)
        view_rows = [
            {
                "id": r.id,
                "name": r.name,
                "available": [s for s in wanted if s in r.available],
                "checked": [SCOPE_READ] if SCOPE_READ in r.available else [],
            }
            for r in rows
        ]
        view_idents = (
            [{"id": i, "label": label, "checked": False} for i, label in identities]
            if SCOPE_SEND in req.scopes
            else []
        )
        return self.svc.portal.page(
            request,
            "consent.html",
            status=status,
            error=error,
            address=user.primary_address,
            rows=view_rows,
            account_scopes=wanted,
            identities=view_idents,
            send_asked=SCOPE_SEND in req.scopes,
            **self._page_context(req),
        )

    # -- sessions ---------------------------------------------------------------------

    async def _session(self, request: Request) -> PortalSession | None:
        raw = self.svc.portal.session_cookie(request)
        if not raw or len(raw) > 200:
            return None
        return await self.svc.store.authenticate_portal_session(
            raw, idle_timeout=self.svc.cfg.portal_idle
        )

    def _back_to_authorize(self, request: Request, req: AuthzRequest) -> Response:
        response = RedirectResponse("/authorize?" + urlencode(req.hidden()), status_code=303)
        security_headers(response)
        return response

    async def _sign_out(self, request: Request, req: AuthzRequest) -> Response:
        raw = self.svc.portal.session_cookie(request)
        if raw:
            await self.svc.store.delete_portal_session(raw)
        response = self._back_to_authorize(request, req)
        self.svc.portal.delete_cookie(response, "session")
        self.svc.portal.rotate_csrf(response)
        return response

    async def _sign_in(self, request: Request, form: FormData, req: AuthzRequest) -> Response:
        svc = self.svc
        raw_address = form.get("address")
        typed = raw_address.strip() if isinstance(raw_address, str) else ""
        password = form.get("password")
        check = await signin.check_login(svc, request, typed, password)
        if not check.ok:
            return self._signin_page(
                request, req, error=check.error, status=check.status, address=typed
            )
        assert isinstance(password, str)
        raw = await signin.complete_sign_in(
            svc,
            check,
            password,
            svc.portal.session_cookie(request),
            store_password=bool(form.get("store_password")),
        )
        response = self._back_to_authorize(request, req)
        svc.portal.set_session(response, raw)
        svc.portal.rotate_csrf(response)
        return response

    # -- consent result ---------------------------------------------------------------

    async def _approve(
        self, request: Request, form: FormData, req: AuthzRequest, session: PortalSession
    ) -> Response:
        svc = self.svc
        user = await svc.store.get(User, session.user_id)
        if user is None:
            return self._back_to_authorize(request, req)
        view_rows, view_idents = await self._rows(user)
        allowed = {r.id: set(r.available) & set(req.scopes) for r in view_rows}
        account_scopes: dict[str, set[str]] = {}
        for item in form.getlist("grant"):
            account_id, _, scope = str(item).rpartition(":")
            if scope in allowed.get(account_id, set()):
                account_scopes.setdefault(account_id, set()).add(scope)
        identity_ids: list[str] = []
        if SCOPE_SEND in req.scopes:
            valid = {i for i, _ in view_idents}
            identity_ids = [
                v for v in dict.fromkeys(str(x) for x in form.getlist("identity")) if v in valid
            ]
        if not account_scopes and not identity_ids:
            return await self._consent_page(request, req, session, error="nothing", status=400)
        if identity_ids and not svc.store.reauth_fresh(session, svc.cfg.reauth_window):
            # Letting a client send mail as the user needs the password again (design 6).
            password = form.get("password")
            if not isinstance(password, str) or not password:
                return self._reauth_page(request, req, form, user)
            error = await signin.verify_user_password(svc, request, user, password)
            if error:
                status = 401 if error == signin.BAD_CREDENTIALS else 429
                return self._reauth_page(request, req, form, user, error=error, status=status)
            session = await svc.store.mark_reauth(session)
            await svc.audit("portal.reauth", outcome="ok", user=user.id, reason="consent_send")
        scope = ops.compute_scope(svc.cfg.offered_scopes, account_scopes, identity_ids)
        grant = await svc.store.create_grant(
            user_id=user.id,
            client_id=req.client.id,
            client_name=req.client.name,
            account_ids=list(account_scopes),
            account_scopes=ops.account_scope_strings(
                {a: sc | {SCOPE_READ} for a, sc in account_scopes.items()}
            ),
            identity_ids=identity_ids,
            scope=scope,
        )
        code = await svc.store.issue_auth_code(
            user_id=user.id,
            client_id=req.client.id,
            grant_id=grant.id,
            redirect_uri=req.redirect_uri,
            code_challenge=req.code_challenge,
            resource=req.resource,
            scope=scope,
        )
        await svc.audit(
            "auth.consent",
            outcome="approved",
            user=user.id,
            client=req.client.id,
            grant=grant.id,
            scope=scope,
            accounts=len(account_scopes),
        )
        return self._continue_page(request, req, code=code)

    def _reauth_page(
        self,
        request: Request,
        req: AuthzRequest,
        form: FormData,
        user: User,
        *,
        error: str = "",
        status: int = 200,
    ) -> Response:
        """Ask for the password again before the grant that allows sending is created.
        The selections travel along as hidden fields (they are not secret)."""
        carried = [("grant", str(v)) for v in form.getlist("grant")] + [
            ("identity", str(v)) for v in form.getlist("identity")
        ]
        return self.svc.portal.page(
            request,
            "consent_reauth.html",
            status=status,
            error=error,
            address=user.primary_address,
            carried=carried,
            **self._page_context(req),
        )

    def _continue_page(self, request: Request, req: AuthzRequest, **params: str) -> Response:
        """The answer to Allow/Deny: a 200 page that continues to the client by meta refresh
        (plus a visible link), not a 303. Chromium applies the page's CSP ``form-action``
        to every redirect hop after a form post, so a callback that redirects on would be
        blocked, and opening the form-action up to the client's host would loosen the
        policy of the consent page. A fresh navigation from a 200 page is not form-action
        governed. The target is the validated redirect URI of the request, only extended by
        our own parameters; the template escapes it for the attribute."""
        out = dict(params)
        if req.state:
            out["state"] = req.state
        out["iss"] = self.svc.cfg.issuer  # RFC 9207
        return self.svc.portal.page(
            request,
            "continue.html",
            csrf=False,
            target=add_query(req.redirect_uri, out),
            redirect_host=display_host(req.redirect_uri),
            denied=params.get("error") == "access_denied",
            client=req.client,
        )

    # -- /token -----------------------------------------------------------------------

    async def token(self, request: Request) -> Response:
        svc = self.svc
        ip = client_ip(request, svc.cfg.trusted_proxy_hops)
        if not svc.limits.token_ip.allow(ip_group(ip)):
            await svc.audit("ratelimit.hit", scope="token_ip")
            return self._too_many(svc.limits.token_ip, ip, "too many requests")
        if "application/x-www-form-urlencoded" not in request.headers.get("content-type", ""):
            return oauth_error("invalid_request", "send application/x-www-form-urlencoded")
        form = await request.form()
        if _repeated(form):
            return oauth_error("invalid_request", "a parameter was sent more than once")
        values = {k: v for k, v in form.items() if isinstance(v, str)}
        if "client_secret" in values or request.headers.get("authorization"):
            return oauth_error(
                "invalid_client",
                "only public clients are supported",
                status=401,
                headers={"www-authenticate": 'Basic realm="token"'},
            )
        grant_type = values.get("grant_type", "")
        client_id = values.get("client_id", "")
        if not client_id or len(client_id) > 512:
            return oauth_error("invalid_request", "client_id is required")
        resource = values.get("resource", "")
        if resource and not same_resource(resource, svc.cfg.resource):
            return oauth_error("invalid_target", "unknown resource")
        if grant_type == "authorization_code":
            return await self._code_grant(values, client_id)
        if grant_type == "refresh_token":
            return await self._refresh_grant(values, client_id)
        return oauth_error("unsupported_grant_type", "use authorization_code or refresh_token")

    def _token_response(self, issued: Any) -> Response:
        now = self.svc.store.now()
        body: dict[str, Any] = {
            "access_token": issued.access_token,
            "token_type": "Bearer",
            "expires_in": max(1, int((issued.access_expires_at - now).total_seconds())),
            "refresh_token": issued.refresh_token,
            "scope": issued.scope,
        }
        return JSONResponse(body, headers={"cache-control": "no-store", "pragma": "no-cache"})

    async def _code_grant(self, values: dict[str, str], client_id: str) -> Response:
        svc = self.svc
        raw = values.get("code", "")
        verifier = values.get("code_verifier", "")
        if not raw or len(raw) > 200:
            return oauth_error("invalid_request", "code is required")
        try:
            code = await svc.store.redeem_auth_code(raw)
        except InvalidToken:
            await svc.audit("auth.code_replay", client=client_id)
            return oauth_error("invalid_grant", "the authorization code is not valid")
        if code is None:
            await svc.audit("auth.token", grant_type="authorization_code", outcome="invalid_code")
            return oauth_error("invalid_grant", "the authorization code is not valid")
        ok = (
            code.client_id == client_id
            and values.get("redirect_uri", code.redirect_uri) == code.redirect_uri
            and pkce.verify(verifier, code.code_challenge)
        )
        if not ok:
            # The code is spent either way; take the pending grant with it.
            await svc.store.revoke_grant(code.grant_id)
            await svc.audit(
                "auth.token",
                grant_type="authorization_code",
                outcome="mismatch",
                grant=code.grant_id,
            )
            return oauth_error("invalid_grant", "the authorization code is not valid")
        grant = await svc.store.get(Grant, code.grant_id)
        if grant is None:
            return oauth_error("invalid_grant", "the authorization code is not valid")
        try:
            issued = await svc.store.issue_tokens(grant, resource=code.resource)
        except (InvalidToken, MailError):
            return oauth_error("invalid_grant", "the authorization code is not valid")
        await self._keep_client(client_id)
        await svc.audit(
            "auth.token",
            grant_type="authorization_code",
            outcome="ok",
            grant=grant.id,
            client=client_id,
        )
        return self._token_response(issued)

    async def _refresh_grant(self, values: dict[str, str], client_id: str) -> Response:
        svc = self.svc
        raw = values.get("refresh_token", "")
        if not raw or len(raw) > 200:
            return oauth_error("invalid_request", "refresh_token is required")
        asked = values.get("scope", "").split()
        if asked:
            old = await svc.store.get_by_secret(Token, raw)
            if old is not None and not set(asked) <= set(old.scope.split()):
                return oauth_error("invalid_scope", "scope exceeds the original grant")
        try:
            issued = await svc.store.rotate_refresh_token(
                raw, client_id=client_id, scope=asked or None
            )
        except InvalidToken as e:
            await svc.audit(
                "auth.token",
                grant_type="refresh_token",
                outcome=type(e).__name__.lower(),
                client=client_id,
            )
            return oauth_error("invalid_grant", "the refresh token is not valid")
        await self._keep_client(client_id)
        await svc.audit(
            "auth.token",
            grant_type="refresh_token",
            outcome="ok",
            grant=issued.grant.id,
            client=client_id,
        )
        return self._token_response(issued)

    async def _keep_client(self, client_id: str) -> None:
        """A registered client stays registered while its sessions are in use."""
        rec = await self.svc.store.get(OAuthClient, client_id)
        if rec is not None and rec.registration == "dcr":
            await self.svc.store.touch_client(rec)

    # -- /revoke ----------------------------------------------------------------------

    async def revoke(self, request: Request) -> Response:
        svc = self.svc
        ip = client_ip(request, svc.cfg.trusted_proxy_hops)
        if not svc.limits.token_ip.allow(ip_group(ip)):
            await svc.audit("ratelimit.hit", scope="token_ip")
            return self._too_many(svc.limits.token_ip, ip, "too many requests")
        if "application/x-www-form-urlencoded" not in request.headers.get("content-type", ""):
            return oauth_error("invalid_request", "send application/x-www-form-urlencoded")
        form = await request.form()
        if _repeated(form):
            return oauth_error("invalid_request", "a parameter was sent more than once")
        raw, client_id = form.get("token"), form.get("client_id")
        if not isinstance(raw, str) or not raw or len(raw) > 200:
            return oauth_error("invalid_request", "token is required")
        tok = await svc.store.get_by_secret(Token, raw)
        # RFC 7009: unknown tokens are not an error; another client's token is left alone.
        if tok is not None and (not isinstance(client_id, str) or client_id == tok.client_id):
            await svc.store.revoke_token(raw)
            await svc.audit("auth.revoke", token_type=tok.token_type, grant=tok.grant_id)
        return Response(status_code=200, headers={"cache-control": "no-store"})

    # -- /register (RFC 7591) ---------------------------------------------------------

    async def register(self, request: Request) -> Response:
        svc = self.svc
        ip = client_ip(request, svc.cfg.trusted_proxy_hops)
        if svc.limits.register_global.blocked("*") or not svc.limits.register_ip.allow(
            ip_group(ip)
        ):
            await svc.audit("ratelimit.hit", scope="register")
            return self._too_many(
                svc.limits.register_ip, ip, "too many registrations", "invalid_client_metadata"
            )
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_REGISTER_BYTES:
            return oauth_error("invalid_client_metadata", "request too large", status=413)
        body = await request.body()
        if len(body) > MAX_REGISTER_BYTES:
            return oauth_error("invalid_client_metadata", "request too large", status=413)
        try:
            data = json.loads(body, object_pairs_hook=_no_duplicate_keys)
        except (ValueError, RecursionError):
            return oauth_error("invalid_client_metadata", "the body is not valid JSON")
        try:
            name, redirects = parse_registration(data, svc.cfg)
        except RegistrationError as e:
            return oauth_error(e.error, e.description)
        svc.limits.register_global.add("*")
        info = await svc.clients.register(name, redirects)
        await svc.audit("auth.register", client=info.id)
        issued = int(svc.store.now().timestamp())
        return JSONResponse(
            {
                "client_id": info.id,
                "client_id_issued_at": issued,
                "client_name": info.name,
                "redirect_uris": list(info.redirect_uris),
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            },
            status_code=201,
            headers={"cache-control": "no-store", "pragma": "no-cache"},
        )


# ---------------------------------------------------------------- helpers and routes


def _metadata_response(meta: dict[str, Any]) -> Response:
    return JSONResponse(meta, headers={"cache-control": "public, max-age=300"})


def oauth_group(svc: OAuthService) -> RouteGroup:
    ep = OAuthEndpoints(svc)
    resource_path = svc.cfg.resource.removeprefix(svc.cfg.issuer)
    routes = [
        Route("/.well-known/oauth-authorization-server", ep.authorization_server_metadata),
        Route("/.well-known/oauth-protected-resource", ep.protected_resource_metadata),
        Route(
            f"/.well-known/oauth-protected-resource{resource_path}", ep.protected_resource_metadata
        ),
        Route("/authorize", ep.authorize_get, methods=["GET"]),
        Route("/authorize", ep.authorize_post, methods=["POST"]),
        Route("/token", ep.token, methods=["POST"]),
        Route("/revoke", ep.revoke, methods=["POST"]),
        Route("/portal/assets/portal.css", ep.stylesheet),
    ]
    if svc.cfg.dcr_enabled:
        routes.append(Route("/register", ep.register, methods=["POST"]))
    return RouteGroup(routes)
