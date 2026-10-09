"""The portal pages: accounts, identities, connected AI clients, language, re-authentication.

Everything here is server-rendered HTML without scripts. State changes are ``POST`` only
and carry the CSRF token; reads never change anything. Sensitive actions (adding or removing
an account, changing its password, raising permissions, letting identities send) need a
password entry within the last ``UEM_REAUTH_WINDOW``: when it is stale the user is sent to
``/portal/reauth`` and back (the form is shown again, nothing secret is carried along).
No page ever shows a password, and audit events carry pseudonyms and random ids only.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.routing import Route

from universal_email_mcp.errors import ConfigError, InvalidArgument
from universal_email_mcp.mail.compose import clean_email, header_text
from universal_email_mcp.mail.net import NetPolicy
from universal_email_mcp.models import Endpoint, ServerProfile
from universal_email_mcp.oauth import signin
from universal_email_mcp.oauth.clients import clean_text
from universal_email_mcp.oauth.config import SCOPE_SEND, permission_of
from universal_email_mcp.oauth.ratelimit import ip_group
from universal_email_mcp.oauth.redirects import display_host
from universal_email_mcp.portal import ops
from universal_email_mcp.portal.activity import ActivityPages
from universal_email_mcp.portal.approvals import ApprovalPages
from universal_email_mcp.portal.i18n import LANG_COOKIE, language_name
from universal_email_mcp.portal.privacy import PrivacyPages
from universal_email_mcp.portal.service import PortalService
from universal_email_mcp.portal.web import client_ip, security_headers
from universal_email_mcp.presets import normalize_hostname, profile_for_host
from universal_email_mcp.server.http import RouteGroup
from universal_email_mcp.store import (
    Grant,
    Identity,
    MailAccount,
    OAuthClient,
    PortalSession,
    User,
)

NOTICES = frozenset(
    {
        "account_added",
        "account_removed",
        "permissions_saved",
        "password_saved",
        "identity_saved",
        "identity_removed",
        "identity_default",
        "client_revoked",
        "client_saved",
        "language_saved",
        "approval_rejected",
        "signed_out",
    }
)
_ID = re.compile(r"^[a-z]_[0-9a-f]{16}$")
_GRANT_ID = re.compile(r"^g_[0-9a-f]{24}$")
MAX_NAME = 40
MAX_USERNAME = 254
MAX_DISPLAY_NAME = 80
MAX_SIGNATURE = 2000
LANG_COOKIE_AGE = 365 * 24 * 3600


def safe_next(value: object, default: str = "/portal/accounts") -> str:
    """A same-origin portal or message-viewer path from a form field, else ``default``
    (no open redirect)."""
    if (
        isinstance(value, str)
        and (
            (value.startswith("/portal") and len(value) <= 200)
            or (value.startswith("/m/") and len(value) <= 2000)
        )
        and not value.startswith("//")
        and all(32 < ord(c) < 127 for c in value)
        and "\\" not in value
    ):
        return value
    return default


def fmt_time(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else ""


def single_line(value: object, limit: int) -> str:
    """Trimmed text without control characters (as typed; refused, not cleaned, if bad)."""
    if not isinstance(value, str):
        return ""
    return header_text(value, "field", max_chars=limit)


_HIT_SCOPES = {"portal": "portal_action", "viewer": "viewer", "download": "download"}
"""``ratelimit.hit`` scope of each kind of per-user portal limit."""


@dataclass(frozen=True, slots=True)
class Auth:
    session: PortalSession
    user: User


class FormProblem(Exception):
    """A rejected form; ``code`` selects the (translated) message."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PortalEndpoints:
    def __init__(self, ps: PortalService) -> None:
        self.ps = ps
        self.svc = ps.oauth
        self.store = ps.oauth.store
        self.web = ps.oauth.portal

    # ------------------------------------------------------------------ plumbing

    def page(
        self,
        request: Request,
        template: str,
        *,
        status: int = 200,
        section: str = "",
        auth: Auth | None = None,
        **ctx: Any,
    ) -> Response:
        notice = request.query_params.get("notice", "")
        translator = self.web.translator
        return self.web.page(
            request,
            template,
            status=status,
            section=section,
            signed_in=auth is not None,
            notice=notice if notice in NOTICES else "",
            languages=[(c, language_name(c)) for c in translator.languages],
            current_lang=self.web.locale(request),
            here=safe_next(request.url.path),
            **ctx,
        )

    def redirect(self, path: str, notice: str = "") -> Response:
        if notice:
            path = f"{path}?{urlencode({'notice': notice})}"
        response = RedirectResponse(path, status_code=303)
        security_headers(response)
        return response

    def _to_signin(self, request: Request) -> Response:
        target = "/portal/signin?" + urlencode({"next": safe_next(request.url.path)})
        return self.redirect(target)

    def to_reauth(self, target: str) -> Response:
        return self.redirect("/portal/reauth?" + urlencode({"next": safe_next(target)}))

    async def _auth(self, request: Request) -> Auth | None:
        raw = self.web.session_cookie(request)
        if not raw or len(raw) > 200:
            return None
        session = await self.store.authenticate_portal_session(
            raw, idle_timeout=self.svc.cfg.portal_idle
        )
        if session is None:
            return None
        user = await self.store.get(User, session.user_id)
        return Auth(session, user) if user else None

    async def get_auth(self, request: Request) -> Auth | Response:
        return await self._auth(request) or self._to_signin(request)

    async def post_auth(
        self, request: Request, *, limited: bool = True
    ) -> tuple[Auth, FormData] | Response:
        form = await request.form()
        if not self.web.check_csrf(request, form):
            await self.svc.audit("auth.csrf_failed", area="portal")
            return self.page(request, "error.html", status=403, csrf=False, reason="csrf")
        auth = await self._auth(request)
        if auth is None:
            return self._to_signin(request)
        wait = await self._hit(request, auth.user.id, "portal") if limited else 0
        if wait:
            return self._too_many(request, wait)
        return auth, form

    def _ip_key(self, request: Request) -> str:
        return ip_group(client_ip(request, self.svc.cfg.trusted_proxy_hops))

    async def _hit(self, request: Request | None, user_id: str, kind: str) -> int:
        """Count a request against the per-user limit of ``kind`` (``portal``: state-changing
        requests, also per network; ``viewer``: message pages and frames; ``download``: raw
        mail and attachments). 0 = go on, else the seconds to wait (and the hit is audited)."""
        limits = self.svc.limits
        user_limiter = {
            "portal": limits.portal_user,
            "viewer": limits.viewer_user,
            "download": limits.download_user,
        }[kind]
        ip_limiter = limits.portal_ip if kind == "portal" and request is not None else None
        ip = self._ip_key(request) if request is not None and ip_limiter is not None else ""
        wait = max(
            user_limiter.retry_after(user_id), ip_limiter.retry_after(ip) if ip_limiter else 0
        )
        if wait:
            await self.svc.audit("ratelimit.hit", scope=_HIT_SCOPES[kind], user=user_id)
            return wait
        user_limiter.add(user_id)
        if ip_limiter is not None:
            ip_limiter.add(ip)
        return 0

    def _too_many(self, request: Request, wait: int) -> Response:
        response = self.page(request, "error.html", status=429, csrf=False, reason="ratelimited")
        response.headers["retry-after"] = str(wait)
        return response

    def fresh(self, auth: Auth) -> bool:
        return self.store.reauth_fresh(auth.session, self.svc.cfg.reauth_window)

    def not_found(self, request: Request, auth: Auth | None = None) -> Response:
        return self.page(request, "error.html", status=404, csrf=False, reason="notfound")

    async def _account(self, auth: Auth, account_id: str) -> MailAccount | None:
        if not _ID.match(account_id):
            return None
        acc = await self.store.get(MailAccount, account_id)
        return acc if acc and acc.user_id == auth.user.id else None

    async def _identity(self, auth: Auth, identity_id: str) -> Identity | None:
        if not _ID.match(identity_id):
            return None
        ident = await self.store.get(Identity, identity_id)
        return ident if ident and ident.user_id == auth.user.id else None

    async def _grant(self, auth: Auth, grant_id: str) -> Grant | None:
        if not _GRANT_ID.match(grant_id):
            return None
        grant = await self.store.get(Grant, grant_id)
        return grant if grant and grant.user_id == auth.user.id else None

    def _allowed_permissions(self, protocol: str) -> tuple[str, ...]:
        """What an account may be given at most: the protocol's capabilities and the
        operator's policy ('read-only deployments' offer reading only)."""
        offered = {permission_of(s) for s in self.svc.cfg.offered_scopes}
        allowed = tuple(p for p in ops.PERMISSIONS if p in offered)
        if protocol == "pop3":  # no folders, no flags, no drafts
            return tuple(p for p in allowed if p == "read")
        return allowed

    def _chosen_permissions(self, form: FormData, protocol: str) -> tuple[str, ...]:
        allowed = self._allowed_permissions(protocol)
        picked = {str(v) for v in form.getlist("perm")}
        return tuple(p for p in ops.PERMISSIONS if p in allowed and (p in picked or p == "read"))

    # ------------------------------------------------------------------ entry, sign-in

    async def home(self, request: Request) -> Response:
        auth = await self._auth(request)
        return self.redirect("/portal/accounts" if auth else "/portal/signin")

    async def signin_get(self, request: Request) -> Response:
        if await self._auth(request):
            return self.redirect(safe_next(request.query_params.get("next")))
        return self.page(
            request,
            "portal_signin.html",
            error="",
            address="",
            next=safe_next(request.query_params.get("next")),
        )

    async def signin_post(self, request: Request) -> Response:
        form = await request.form()
        nxt = safe_next(form.get("next"))
        raw_address = form.get("address")
        typed = raw_address.strip() if isinstance(raw_address, str) else ""
        if not self.web.check_csrf(request, form):
            await self.svc.audit("auth.csrf_failed", area="portal")
            return self.page(
                request, "portal_signin.html", status=403, error="csrf", address=typed, next=nxt
            )
        password = form.get("password")
        check = await signin.check_login(self.svc, request, typed, password)
        if not check.ok:
            return self.page(
                request,
                "portal_signin.html",
                status=check.status,
                error=check.error,
                address=typed,
                next=nxt,
            )
        assert isinstance(password, str)
        raw = await signin.complete_sign_in(
            self.svc,
            check,
            password,
            self.web.session_cookie(request),
            store_password=bool(form.get("store_password")),
        )
        response = self.redirect(nxt)
        self.web.set_session(response, raw)
        self.web.rotate_csrf(response)
        return response

    async def signout(self, request: Request) -> Response:
        form = await request.form()
        if not self.web.check_csrf(request, form):
            await self.svc.audit("auth.csrf_failed", area="portal")
            return self.page(request, "error.html", status=403, csrf=False, reason="csrf")
        raw = self.web.session_cookie(request)
        if raw:
            await self.store.delete_portal_session(raw)
        response = self.redirect("/portal/signin", "signed_out")
        self.web.delete_cookie(response, "session")
        self.web.rotate_csrf(response)
        return response

    async def reauth_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        return self.page(
            request,
            "reauth.html",
            section="",
            auth=auth,
            error="",
            next=safe_next(request.query_params.get("next")),
        )

    async def reauth_post(self, request: Request) -> Response:
        got = await self.post_auth(
            request, limited=False
        )  # a password check: signin_* limits apply
        if isinstance(got, Response):
            return got
        auth, form = got
        nxt = safe_next(form.get("next"))
        error = await signin.verify_user_password(
            self.svc, request, auth.user, form.get("password")
        )
        if error:
            status = (
                401 if error == signin.BAD_CREDENTIALS else 429 if error == "rate_limited" else 503
            )
            return self.page(
                request, "reauth.html", status=status, auth=auth, error=error, next=nxt
            )
        await self.store.mark_reauth(auth.session)
        await self.svc.audit("portal.reauth", outcome="ok", user=auth.user.id)
        return self.redirect(nxt)

    async def language(self, request: Request) -> Response:
        form = await request.form()
        if not self.web.check_csrf(request, form):
            await self.svc.audit("auth.csrf_failed", area="portal")
            return self.page(request, "error.html", status=403, csrf=False, reason="csrf")
        lang = str(form.get("lang", "")).lower()
        response = self.redirect(safe_next(form.get("next"), "/portal"))
        if lang in self.web.translator.languages:
            response.set_cookie(
                LANG_COOKIE,
                lang,
                max_age=LANG_COOKIE_AGE,
                path="/",
                httponly=True,
                secure=self.svc.cfg.secure_cookies,
                samesite="lax",
            )
        return response

    # ------------------------------------------------------------------ accounts

    async def accounts(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        accounts = await self.store.list_for_user(MailAccount, auth.user.id)
        return self.page(
            request,
            "accounts.html",
            section="accounts",
            auth=auth,
            accounts=[self._account_view(a) for a in accounts],
        )

    def _account_view(self, a: MailAccount) -> dict[str, Any]:
        return {
            "id": a.id,
            "name": a.name,
            "protocol": a.protocol.upper(),
            "host": a.host,
            "permissions": [p for p in ops.PERMISSIONS if p in a.permissions],
        }

    def _add_form_context(
        self, values: Mapping[str, Any] | None = None, error: str = ""
    ) -> dict[str, Any]:
        v: dict[str, Any] = {
            "name": "",
            "username": "",
            "protocol": "imap",
            "server": "",
            "host": "",
            "perms": ["read"],
            "identity": True,
            **(values or {}),
        }
        servers = self.ps.mail_servers
        return {
            "values": v,
            "error": error,
            "servers": [(p.name, p.label or p.name) for p in servers],
            "fixed_server": servers[0].label or servers[0].name if len(servers) == 1 else "",
            "custom": self.ps.custom_allowed,
            "permissions": self._allowed_permissions("imap"),
        }

    async def account_new_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        if not self.fresh(auth):
            return self.to_reauth(request.url.path)
        return self.page(
            request, "account_new.html", section="accounts", auth=auth, **self._add_form_context()
        )

    def _server_for(self, form: FormData) -> tuple[ServerProfile, NetPolicy, str]:
        """The profile the form selects, its network policy and the ``preset`` to record.
        Never trusts a posted host for a listed server: only the name is used."""
        servers = self.ps.mail_servers
        if len(servers) == 1:
            return servers[0], self.ps.net, servers[0].name
        if servers:
            wanted = str(form.get("server", ""))
            for p in servers:
                if p.name == wanted:
                    return p, self.ps.net, p.name
            raise FormProblem("server")
        host = single_line(form.get("host"), 253)
        try:
            name = normalize_hostname(host)
        except ConfigError:
            raise FormProblem("host") from None
        if "." not in name or name.replace(".", "").isdigit() or ":" in name:
            raise FormProblem("host")  # no bare names, no IP literals
        return profile_for_host(name), self.ps.custom_net, ""

    async def _check_limits(self, request: Request, auth: Auth, target: str) -> None:
        limits = self.svc.limits
        ip = self._ip_key(request)
        if (
            not limits.test_ip.allow(ip)
            or not limits.test_user.allow(auth.user.id)
            or not limits.test_target.allow(target)
        ):
            await self.svc.audit("ratelimit.hit", scope="portal_test", user=auth.user.id)
            raise FormProblem("rate_limited")

    @staticmethod
    def _target(endpoint: Endpoint, username: str, user_id: str = "") -> str:
        return f"{user_id}:{endpoint.host.lower()}:{endpoint.port}:{username}"

    async def account_new_post(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, form = got
        if not self.fresh(auth):
            return self.to_reauth("/portal/accounts/new")
        protocol = str(form.get("protocol", "imap"))
        values = {
            "name": clean_text(form.get("name"), MAX_NAME),
            "username": form.get("username", "") if isinstance(form.get("username"), str) else "",
            "protocol": protocol if protocol in ("imap", "pop3") else "imap",
            "server": str(form.get("server", "")),
            "host": str(form.get("host", ""))[:253],
            "perms": [str(v) for v in form.getlist("perm")],
            "identity": form.get("identity") is not None,
        }

        def again(code: str, status: int = 400) -> Response:
            return self.page(
                request,
                "account_new.html",
                status=status,
                section="accounts",
                auth=auth,
                **self._add_form_context(values, code),
            )

        try:
            account, identity = await self._build_account(request, auth, form, values)
        except FormProblem as e:
            return again(e.code, 429 if e.code == "rate_limited" else 400)
        await self.store.create(account)
        if identity is not None:
            await self.store.create(identity)
            if identity.is_default:
                await ops.set_default_identity(self.store, auth.user.id, identity.id)
        await self.svc.audit(
            "portal.account_add",
            user=auth.user.id,
            account=account.id,
            protocol=account.protocol,
            with_identity=identity is not None,
        )
        return self.redirect(f"/portal/accounts/{account.id}", "account_added")

    async def _build_account(
        self, request: Request, auth: Auth, form: FormData, values: dict[str, Any]
    ) -> tuple[MailAccount, Identity | None]:
        existing = await self.store.list_for_user(MailAccount, auth.user.id)
        if len(existing) >= self.svc.cfg.max_accounts:
            raise FormProblem("too_many")
        name = values["name"]
        if not name:
            raise FormProblem("name")
        if name.casefold() in {a.name.casefold() for a in existing}:
            raise FormProblem("name_taken")
        protocol: str = values["protocol"]
        profile, net, preset = self._server_for(form)
        endpoint = profile.imap if protocol == "imap" else profile.pop3
        if endpoint is None:
            raise FormProblem("protocol")
        username = values["username"]
        password = form.get("password")
        try:
            username = single_line(username, MAX_USERNAME)
        except InvalidArgument:
            raise FormProblem("username") from None
        if not username:
            raise FormProblem("username")
        if not signin.valid_password(password):
            raise FormProblem("password")
        assert isinstance(password, str)
        await self._check_limits(request, auth, self._target(endpoint, username, auth.user.id))
        outcome = await self.ps.tester.incoming(protocol, endpoint, username, password, net)
        if not outcome.ok:
            raise FormProblem(f"test_{outcome.status}")
        account = MailAccount(
            id=ops.new_id("a"),
            user_id=auth.user.id,
            name=name,
            protocol=protocol,
            host=endpoint.host,
            port=endpoint.port,
            tls=ops.to_record_tls(endpoint.tls),
            preset=preset,
            username=username,
            password=password,
            permissions=self._chosen_permissions(form, protocol),
            created_at=self.store.now(),
        )
        identity: Identity | None = None
        mail = clean_email(username)
        if values["identity"] and mail and profile.smtp is not None:
            known = {i.addresses[0] for i in await self.store.list_for_user(Identity, auth.user.id)}
            if mail not in known and len(known) < self.svc.cfg.max_identities:
                idents = await self.store.list_for_user(Identity, auth.user.id)
                identity = Identity(
                    id=ops.new_id("i"),
                    user_id=auth.user.id,
                    addresses=(mail,),
                    copies_account_id=account.id if protocol == "imap" else "",
                    is_default=not idents,
                    created_at=self.store.now(),
                    **ops.smtp_fields(account, profile.smtp),
                )
        return account, identity

    async def account_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        return self._account_page(request, auth, account)

    def _account_page(
        self,
        request: Request,
        auth: Auth,
        account: MailAccount,
        *,
        results: list[dict[str, Any]] | None = None,
        error: str = "",
        status: int = 200,
    ) -> Response:
        return self.page(
            request,
            "account.html",
            status=status,
            section="accounts",
            auth=auth,
            account=self._account_view(account) | {"username": account.username},
            allowed=self._allowed_permissions(account.protocol),
            results=results,
            error=error,
        )

    async def account_test(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, _form = got
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        endpoint = ops.account_endpoint(account)
        try:
            await self._check_limits(
                request, auth, self._target(endpoint, account.username, auth.user.id)
            )
        except FormProblem as e:
            return self._account_page(request, auth, account, error=e.code, status=429)
        net = self.ps.net if account.preset else self.ps.custom_net
        results = [
            {
                "kind": account.protocol,
                "outcome": await self.ps.tester.incoming(
                    account.protocol, endpoint, account.username, account.password, net
                ),
            }
        ]
        smtp_ep = ops.smtp_endpoint_of(account, self.ps.known_profiles())
        if smtp_ep is not None:
            results.append(
                {
                    "kind": "smtp",
                    "outcome": await self.ps.tester.submission(
                        smtp_ep, account.username, account.password, net
                    ),
                }
            )
        await self.svc.audit(
            "portal.account_test",
            user=auth.user.id,
            account=account.id,
            outcome="ok" if all(r["outcome"].ok for r in results) else "failed",
        )
        return self._account_page(request, auth, account, results=results)

    async def account_permissions(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, form = got
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        new = self._chosen_permissions(form, account.protocol)
        if set(new) - set(account.permissions) and not self.fresh(auth):
            return self.to_reauth(f"/portal/accounts/{account.id}")
        await ops.update_retry(
            self.store, MailAccount, account.id, lambda a: replace(a, permissions=new)
        )
        await ops.clamp_grants(self.store, auth.user.id, self.svc.cfg.offered_scopes)
        await self.svc.audit(
            "portal.account_permissions",
            user=auth.user.id,
            account=account.id,
            permissions=" ".join(new),
        )
        return self.redirect(f"/portal/accounts/{account.id}", "permissions_saved")

    async def account_password_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        if not self.fresh(auth):
            return self.to_reauth(request.url.path)
        return self.page(
            request,
            "account_password.html",
            section="accounts",
            auth=auth,
            account=self._account_view(account),
            error="",
        )

    async def account_password_post(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, form = got
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        if not self.fresh(auth):
            return self.to_reauth(f"/portal/accounts/{account.id}/password")

        def again(code: str, status: int = 400) -> Response:
            return self.page(
                request,
                "account_password.html",
                status=status,
                section="accounts",
                auth=auth,
                account=self._account_view(account),
                error=code,
            )

        password = form.get("password")
        if not signin.valid_password(password):
            return again("password")
        assert isinstance(password, str)
        endpoint = ops.account_endpoint(account)
        try:
            await self._check_limits(
                request, auth, self._target(endpoint, account.username, auth.user.id)
            )
        except FormProblem as e:
            return again(e.code, 429)
        net = self.ps.net if account.preset else self.ps.custom_net
        outcome = await self.ps.tester.incoming(
            account.protocol, endpoint, account.username, password, net
        )
        if not outcome.ok:
            return again(f"test_{outcome.status}")
        await ops.set_password(self.store, auth.user.id, account.id, password)
        await self.svc.audit("portal.account_password", user=auth.user.id, account=account.id)
        return self.redirect(f"/portal/accounts/{account.id}", "password_saved")

    async def account_remove_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        if not self.fresh(auth):
            return self.to_reauth(request.url.path)
        grants = [
            g
            for g in await self.store.list_for_user(Grant, auth.user.id)
            if account.id in g.account_ids
        ]
        derived = [
            i
            for i in await self.store.list_for_user(Identity, auth.user.id)
            if i.smtp_account_id == account.id
        ]
        return self.page(
            request,
            "account_remove.html",
            section="accounts",
            auth=auth,
            account=self._account_view(account),
            clients=len(grants),
            identities=len(derived),
        )

    async def account_remove_post(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, _form = got
        account = await self._account(auth, request.path_params["account_id"])
        if account is None:
            return self.not_found(request, auth)
        if not self.fresh(auth):
            return self.to_reauth(f"/portal/accounts/{account.id}/remove")
        removal = await ops.remove_account(
            self.store, auth.user.id, account.id, self.svc.cfg.offered_scopes
        )
        await self.svc.audit(
            "portal.account_remove",
            user=auth.user.id,
            account=account.name,  # the account is gone afterwards: the feed keeps its name
            grants=removal.grants_revoked if removal else 0,
            identities=removal.identities_removed if removal else 0,
        )
        return self.redirect("/portal/accounts", "account_removed")

    # ------------------------------------------------------------------ identities

    async def identities(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        idents = await self.store.list_for_user(Identity, auth.user.id)
        accounts = {a.id: a for a in await self.store.list_for_user(MailAccount, auth.user.id)}
        return self.page(
            request,
            "identities.html",
            section="identities",
            auth=auth,
            identities=[self._identity_view(i, accounts) for i in idents],
            can_add=bool(accounts),
        )

    @staticmethod
    def _identity_view(i: Identity, accounts: Mapping[str, MailAccount]) -> dict[str, Any]:
        store_acc = accounts.get(i.copies_account_id)
        smtp_acc = accounts.get(i.smtp_account_id)
        return {
            "id": i.id,
            "address": i.addresses[0] if i.addresses else "",
            "display_name": i.display_name,
            "default": i.is_default,
            "send": i.send,
            "smtp_host": i.smtp_host,
            "store_account": store_acc.name if store_acc else "",
            "smtp_account": smtp_acc.name if smtp_acc else "",
        }

    async def _identity_form_context(
        self,
        auth: Auth,
        values: Mapping[str, Any] | None = None,
        error: str = "",
        identity_id: str = "",
    ) -> dict[str, Any]:
        accounts = await self.store.list_for_user(MailAccount, auth.user.id)
        known = self.ps.known_profiles()
        smtp_choices = [
            (a.id, a.name) for a in accounts if ops.smtp_endpoint_of(a, known) is not None
        ]
        store_choices = [(a.id, a.name) for a in accounts if a.protocol == "imap"]
        v: dict[str, Any] = {
            "address": "",
            "display_name": "",
            "signature": "",
            "smtp_account": smtp_choices[0][0] if smtp_choices else "",
            "store_account": store_choices[0][0] if store_choices else "",
            "default": False,
            "send": False,
            **(values or {}),
        }
        return {
            "values": v,
            "error": error,
            "results": None,
            "identity_id": identity_id,
            "smtp_choices": smtp_choices,
            "store_choices": store_choices,
            "send_possible": self.svc.cfg.offered_scopes.count(SCOPE_SEND) > 0,
        }

    async def identity_new_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        return self.page(
            request,
            "identity_form.html",
            section="identities",
            auth=auth,
            **await self._identity_form_context(auth),
        )

    async def identity_edit_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        ident = await self._identity(auth, request.path_params["identity_id"])
        if ident is None:
            return self.not_found(request, auth)
        values = {
            "address": ident.addresses[0] if ident.addresses else "",
            "display_name": ident.display_name,
            "signature": ident.signature,
            "smtp_account": ident.smtp_account_id,
            "store_account": ident.copies_account_id,
            "default": ident.is_default,
            "send": ident.send,
        }
        return self.page(
            request,
            "identity_form.html",
            section="identities",
            auth=auth,
            **await self._identity_form_context(auth, values, identity_id=ident.id),
        )

    async def identity_save(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, form = got
        existing: Identity | None = None
        if "identity_id" in request.path_params:
            existing = await self._identity(auth, request.path_params["identity_id"])
            if existing is None:
                return self.not_found(request, auth)
        values = {
            "address": str(form.get("address", ""))[:MAX_USERNAME],
            "display_name": str(form.get("display_name", ""))[: MAX_DISPLAY_NAME * 2],
            "signature": str(form.get("signature", ""))[: MAX_SIGNATURE * 2],
            "smtp_account": str(form.get("smtp_account", "")),
            "store_account": str(form.get("store_account", "")),
            "default": form.get("default") is not None,
            "send": form.get("send") is not None,
        }

        try:
            fields = await self._identity_fields(auth, values, existing)
        except FormProblem as e:
            return await self._again(request, auth, values, e.code, existing)
        if fields["send"] and not self.fresh(auth):
            target = f"/portal/identities/{existing.id}" if existing else "/portal/identities/new"
            return self.to_reauth(target)
        if existing is None:
            idents = await self.store.list_for_user(Identity, auth.user.id)
            if len(idents) >= self.svc.cfg.max_identities:
                return await self._again(request, auth, values, "too_many", existing)
            ident = Identity(
                id=ops.new_id("i"),
                user_id=auth.user.id,
                created_at=self.store.now(),
                is_default=not idents,
                **fields,
            )
            await self.store.create(ident)
            event = "portal.identity_add"
        else:
            ident = existing
            await ops.update_retry(
                self.store,
                Identity,
                existing.id,
                lambda i: replace(i, **fields),
            )
            event = "portal.identity_edit"
        if values["default"]:
            await ops.set_default_identity(self.store, auth.user.id, ident.id)
        elif existing is None and ident.is_default:
            await ops.set_default_identity(self.store, auth.user.id, ident.id)
        await ops.clamp_grants(self.store, auth.user.id, self.svc.cfg.offered_scopes)
        await self.svc.audit(event, user=auth.user.id, identity=ident.id, can_send=fields["send"])
        return self.redirect("/portal/identities", "identity_saved")

    async def _again(
        self,
        request: Request,
        auth: Auth,
        values: Mapping[str, Any],
        code: str,
        existing: Identity | None,
    ) -> Response:
        return self.page(
            request,
            "identity_form.html",
            status=429 if code == "rate_limited" else 400,
            section="identities",
            auth=auth,
            **await self._identity_form_context(
                auth, values, code, existing.id if existing else ""
            ),
        )

    async def _identity_fields(
        self, auth: Auth, values: Mapping[str, Any], existing: Identity | None
    ) -> dict[str, Any]:
        """Validated record fields (no ``id`` / ``user_id`` / ``created_at``). Header
        values are refused when they hold line breaks or other control characters."""
        cleaned = clean_email(values["address"])
        if cleaned is None:
            raise FormProblem("address")
        address = cleaned.lower()  # as in the TOML config
        others = [
            i
            for i in await self.store.list_for_user(Identity, auth.user.id)
            if not existing or i.id != existing.id
        ]
        if any(address in i.addresses for i in others):
            raise FormProblem("address_taken")
        try:
            display = header_text(values["display_name"], "name", max_chars=MAX_DISPLAY_NAME)
        except InvalidArgument:
            raise FormProblem("display_name") from None
        if "=?" in display or any(c in display for c in '<>"\\'):
            raise FormProblem("display_name")
        signature = str(values["signature"]).replace("\r\n", "\n").replace("\r", "\n")
        if len(signature) > MAX_SIGNATURE or any(
            ord(c) < 32 and c not in "\n\t" or ord(c) == 127 for c in signature
        ):
            raise FormProblem("signature")
        accounts = {a.id: a for a in await self.store.list_for_user(MailAccount, auth.user.id)}
        fields: dict[str, Any] = {
            "addresses": (address,),
            "display_name": display,
            "signature": signature.strip(),
            "send": bool(values["send"]),
        }
        smtp_id, store_id = values["smtp_account"], values["store_account"]
        if smtp_id:
            smtp_acc = accounts.get(smtp_id)
            endpoint = (
                ops.smtp_endpoint_of(smtp_acc, self.ps.known_profiles()) if smtp_acc else None
            )
            if smtp_acc is None or endpoint is None:
                raise FormProblem("smtp_account")
            fields.update(ops.smtp_fields(smtp_acc, endpoint))
        else:
            fields.update(
                smtp_host="", smtp_port=465, smtp_tls="implicit", smtp_username="",
                smtp_password="", smtp_account_id="",
            )  # fmt: skip
        store_acc = accounts.get(store_id) if store_id else None
        if store_id and (store_acc is None or store_acc.protocol != "imap"):
            raise FormProblem("store_account")
        fields["copies_account_id"] = store_acc.id if store_acc else ""
        if fields["send"]:
            if SCOPE_SEND not in self.svc.cfg.offered_scopes:
                raise FormProblem("send_off")
            if not smtp_id or store_acc is None or "drafts" not in store_acc.permissions:
                raise FormProblem("send_needs")
        return fields

    async def identity_default(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, _ = got
        ident = await self._identity(auth, request.path_params["identity_id"])
        if ident is None:
            return self.not_found(request, auth)
        await ops.set_default_identity(self.store, auth.user.id, ident.id)
        await self.svc.audit("portal.identity_edit", user=auth.user.id, identity=ident.id)
        return self.redirect("/portal/identities", "identity_default")

    async def identity_remove_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        ident = await self._identity(auth, request.path_params["identity_id"])
        if ident is None:
            return self.not_found(request, auth)
        return self.page(
            request,
            "identity_remove.html",
            section="identities",
            auth=auth,
            identity=self._identity_view(ident, {}),
        )

    async def identity_remove_post(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, _ = got
        ident = await self._identity(auth, request.path_params["identity_id"])
        if ident is None:
            return self.not_found(request, auth)
        touched = await ops.remove_identity(self.store, auth.user.id, ident.id)
        await self.svc.audit(
            "portal.identity_remove",
            user=auth.user.id,
            identity=ident.id,
            grants=touched or 0,
        )
        return self.redirect("/portal/identities", "identity_removed")

    async def identity_test(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, _ = got
        ident = await self._identity(auth, request.path_params["identity_id"])
        if ident is None:
            return self.not_found(request, auth)
        endpoint = ops.identity_smtp_endpoint(ident)
        accounts = {a.id: a for a in await self.store.list_for_user(MailAccount, auth.user.id)}
        view = self._identity_view(ident, accounts)
        values = {
            "address": view["address"], "display_name": ident.display_name,
            "signature": ident.signature, "smtp_account": ident.smtp_account_id,
            "store_account": ident.copies_account_id, "default": ident.is_default,
            "send": ident.send,
        }  # fmt: skip
        ctx = await self._identity_form_context(auth, values, identity_id=ident.id)
        if endpoint is None:
            return self.page(
                request, "identity_form.html", status=400, section="identities", auth=auth,
                **{**ctx, "error": "smtp_account"},
            )  # fmt: skip
        try:
            await self._check_limits(
                request, auth, self._target(endpoint, ident.smtp_username, auth.user.id)
            )
        except FormProblem as e:
            return self.page(
                request, "identity_form.html", status=429, section="identities", auth=auth,
                **{**ctx, "error": e.code},
            )  # fmt: skip
        source = accounts.get(ident.smtp_account_id)
        net = self.ps.net if source is None or source.preset else self.ps.custom_net
        outcome = await self.ps.tester.submission(
            endpoint, ident.smtp_username, ident.smtp_password, net
        )
        await self.svc.audit(
            "portal.identity_test", user=auth.user.id, identity=ident.id,
            outcome=outcome.status,
        )  # fmt: skip
        return self.page(
            request, "identity_form.html", section="identities", auth=auth,
            **{**ctx, "results": [{"kind": "smtp", "outcome": outcome}]},
        )  # fmt: skip

    # ------------------------------------------------------------------ connected clients

    async def clients(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        grants = await self.store.list_for_user(Grant, auth.user.id)
        names = await self._names(auth.user.id)
        views = [await self._grant_view(g, names) for g in reversed(grants)]
        return self.page(request, "clients.html", section="clients", auth=auth, grants=views)

    async def _names(self, user_id: str) -> dict[str, str]:
        out = {a.id: a.name for a in await self.store.list_for_user(MailAccount, user_id)}
        for i in await self.store.list_for_user(Identity, user_id):
            address = i.addresses[0] if i.addresses else i.id
            out[i.id] = f"{i.display_name} <{address}>" if i.display_name else address
        return out

    async def _grant_view(self, g: Grant, names: Mapping[str, str]) -> dict[str, Any]:
        client = await self.store.get(OAuthClient, g.client_id)
        if client is None:
            source = ""
        elif client.registration == "cimd":
            source = display_host(g.client_id)
        else:
            source = "-"
        return {
            "id": g.id,
            "name": clean_text(g.client_name, 80),
            "registered": client is not None and client.registration == "dcr",
            "host": source if source != "-" else "",
            "created": fmt_time(g.created_at),
            "last_used": fmt_time(g.last_used),
            "expires": fmt_time(g.expires_at),
            "accounts": [
                {
                    "name": names.get(a, ""),
                    "permissions": [
                        p for p in ops.PERMISSIONS if p in g.account_scopes.get(a, "").split()
                    ],
                }
                for a in g.account_ids
            ],
            "identities": [names.get(i, "") for i in g.identity_ids],
        }

    async def client_get(self, request: Request) -> Response:
        auth = await self.get_auth(request)
        if isinstance(auth, Response):
            return auth
        grant = await self._grant(auth, request.path_params["grant_id"])
        if grant is None:
            return self.not_found(request, auth)
        return await self._client_page(request, auth, grant)

    async def _client_page(
        self, request: Request, auth: Auth, grant: Grant, *, error: str = "", status: int = 200
    ) -> Response:
        names = await self._names(auth.user.id)
        view = await self._grant_view(grant, names)
        scopes = ops.grant_account_scopes(grant)
        rows = [
            {
                "id": a,
                "name": names[a],
                "perms": [p for p in ops.PERMISSIONS if f"mail.{p}" in scopes.get(a, set())],
            }
            for a in grant.account_ids
            if a in names
        ]
        return self.page(
            request,
            "client.html",
            status=status,
            section="clients",
            auth=auth,
            grant=view,
            rows=rows,
            idents=[(i, names[i]) for i in grant.identity_ids if i in names],
            error=error,
        )

    async def client_save(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, form = got
        grant = await self._grant(auth, request.path_params["grant_id"])
        if grant is None:
            return self.not_found(request, auth)
        keep: dict[str, set[str]] = {}
        for item in form.getlist("grant"):
            account_id, _, perm = str(item).rpartition(":")
            if perm in ops.PERMISSIONS:
                keep.setdefault(account_id, set()).add(f"mail.{perm}")
        idents = [str(v) for v in form.getlist("identity")]
        offered = self.svc.cfg.offered_scopes
        preview = ops.compute_scope(
            offered,
            {a: s & ops.grant_account_scopes(grant).get(a, set()) for a, s in keep.items()},
            [i for i in idents if i in grant.identity_ids],
        )
        if not preview:
            return await self._client_page(request, auth, grant, error="keep_one", status=400)
        await ops.reduce_grant(self.store, grant.id, offered, keep, idents)
        await self.svc.audit("portal.grant_edit", user=auth.user.id, grant=grant.id, scope=preview)
        return self.redirect("/portal/clients", "client_saved")

    async def client_revoke(self, request: Request) -> Response:
        got = await self.post_auth(request)
        if isinstance(got, Response):
            return got
        auth, _ = got
        grant = await self._grant(auth, request.path_params["grant_id"])
        if grant is None:
            return self.not_found(request, auth)
        await self.store.revoke_grant(grant.id)
        await self.svc.audit("portal.grant_revoke", user=auth.user.id, grant=grant.id)
        return self.redirect("/portal/clients", "client_revoked")


def portal_group(ps: PortalService) -> RouteGroup:
    ep = PortalEndpoints(ps)
    approvals = ApprovalPages(ep)
    activity = ActivityPages(ep)
    privacy = PrivacyPages(ep)
    get, post = ["GET"], ["POST"]
    routes = [
        Route("/portal", ep.home, methods=get),
        Route("/portal/signin", ep.signin_get, methods=get),
        Route("/portal/signin", ep.signin_post, methods=post),
        Route("/portal/signout", ep.signout, methods=post),
        Route("/portal/reauth", ep.reauth_get, methods=get),
        Route("/portal/reauth", ep.reauth_post, methods=post),
        Route("/portal/language", ep.language, methods=post),
        Route("/portal/accounts", ep.accounts, methods=get),
        Route("/portal/accounts/new", ep.account_new_get, methods=get),
        Route("/portal/accounts/new", ep.account_new_post, methods=post),
        Route("/portal/accounts/{account_id}", ep.account_get, methods=get),
        Route("/portal/accounts/{account_id}/test", ep.account_test, methods=post),
        Route("/portal/accounts/{account_id}/permissions", ep.account_permissions, methods=post),
        Route("/portal/accounts/{account_id}/password", ep.account_password_get, methods=get),
        Route("/portal/accounts/{account_id}/password", ep.account_password_post, methods=post),
        Route("/portal/accounts/{account_id}/remove", ep.account_remove_get, methods=get),
        Route("/portal/accounts/{account_id}/remove", ep.account_remove_post, methods=post),
        Route("/portal/identities", ep.identities, methods=get),
        Route("/portal/identities/new", ep.identity_new_get, methods=get),
        Route("/portal/identities/new", ep.identity_save, methods=post),
        Route("/portal/identities/{identity_id}", ep.identity_edit_get, methods=get),
        Route("/portal/identities/{identity_id}", ep.identity_save, methods=post),
        Route("/portal/identities/{identity_id}/default", ep.identity_default, methods=post),
        Route("/portal/identities/{identity_id}/test", ep.identity_test, methods=post),
        Route("/portal/identities/{identity_id}/remove", ep.identity_remove_get, methods=get),
        Route("/portal/identities/{identity_id}/remove", ep.identity_remove_post, methods=post),
        Route("/portal/clients", ep.clients, methods=get),
        Route("/portal/clients/{grant_id}", ep.client_get, methods=get),
        Route("/portal/clients/{grant_id}", ep.client_save, methods=post),
        Route("/portal/clients/{grant_id}/revoke", ep.client_revoke, methods=post),
        Route("/portal/activity", activity.index, methods=get),
        Route("/portal/privacy", privacy.index, methods=get),
        Route("/portal/privacy/export", privacy.export, methods=post),
        Route("/portal/privacy/delete", privacy.delete_get, methods=get),
        Route("/portal/privacy/delete", privacy.delete_post, methods=post),
        Route("/portal/approvals", approvals.index, methods=get),
        Route("/portal/approvals/{approval_id}", approvals.detail, methods=get),
        Route("/portal/approvals/{approval_id}", approvals.decide, methods=post),
    ]
    return RouteGroup(routes)
