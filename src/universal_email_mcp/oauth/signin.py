"""Signing in with the mailbox login, shared by ``/authorize`` and the portal.

``check_login`` is the one place that rate-limits, parses and verifies an address and
password against the server the operator assigned to the address's domain.
``complete_sign_in`` turns a successful check into a user record, the sign-in mailbox as
a real account (WP 3d) and a portal session. ``verify_user_password`` is the same check
for an already signed-in user who must type the password again (sensitive actions).
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from starlette.requests import Request

from universal_email_mcp.errors import AuthFailed, MailError
from universal_email_mcp.jsonlog import log_event
from universal_email_mcp.models import ServerProfile
from universal_email_mcp.oauth.identity import Address, AddressError, parse_address, short_id
from universal_email_mcp.oauth.service import OAuthService
from universal_email_mcp.portal.ops import ensure_primary
from universal_email_mcp.portal.web import client_ip
from universal_email_mcp.store import User

log = logging.getLogger(__name__)

LOGIN_TIMEOUT = 25.0
MAX_PASSWORD = 1024

OK = ""
BAD_CREDENTIALS = "bad_credentials"
RATE_LIMITED = "rate_limited"
UNAVAILABLE = "unavailable"

_STATUS = {OK: 200, BAD_CREDENTIALS: 401, RATE_LIMITED: 429, UNAVAILABLE: 503}


@dataclass(frozen=True, slots=True)
class LoginCheck:
    error: str = OK
    address: Address | None = None
    user_id: str = ""
    profile: ServerProfile | None = None

    @property
    def ok(self) -> bool:
        return self.error == OK

    @property
    def status(self) -> int:
        return _STATUS[self.error]


def valid_password(password: object) -> bool:
    """Non-empty, bounded, and free of line breaks and NUL (they would end up in the
    IMAP command line or be mangled by it)."""
    return (
        isinstance(password, str)
        and 0 < len(password) <= MAX_PASSWORD
        and not any(c in password for c in "\r\n\x00")
    )


async def _verify(
    svc: OAuthService, address: Address, password: str, profile: ServerProfile, user_id: str
) -> str:
    try:
        async with svc.login_slots:
            await asyncio.wait_for(svc.login.verify(address, password, profile), LOGIN_TIMEOUT)
    except AuthFailed:
        return BAD_CREDENTIALS
    except (MailError, TimeoutError) as e:
        log_event(
            log, logging.WARNING, "login server problem", event="auth.sign_in",
            error=type(e).__name__,
        )  # fmt: skip
        svc.audit("auth.sign_in", outcome="unavailable", user=short_id(user_id))
        return UNAVAILABLE
    return OK


async def check_login(
    svc: OAuthService, request: Request, typed_address: str, password: object
) -> LoginCheck:
    ip = client_ip(request, svc.cfg.trusted_proxy_hops)
    if not svc.limits.signin_ip.allow(ip or "-"):
        svc.audit("ratelimit.hit", scope="signin_ip")
        return LoginCheck(RATE_LIMITED)
    if not valid_password(password):
        return LoginCheck(BAD_CREDENTIALS)
    assert isinstance(password, str)
    try:
        address = parse_address(typed_address)
    except AddressError:
        return LoginCheck(BAD_CREDENTIALS)
    user_id = svc.pseudonyms.user_id(address.normal)
    if svc.limits.signin_address.blocked(user_id):
        svc.audit("ratelimit.hit", scope="signin_address", user=short_id(user_id))
        return LoginCheck(RATE_LIMITED)

    def failed(outcome: str) -> LoginCheck:
        svc.limits.signin_address.add(user_id)
        svc.audit("auth.sign_in", outcome=outcome, user=short_id(user_id))
        return LoginCheck(BAD_CREDENTIALS)

    profile = svc.login_domains.get(address.domain)
    if profile is None:
        return failed("unknown_domain")
    error = await _verify(svc, address, password, profile, user_id)
    if error == BAD_CREDENTIALS:
        return failed("bad_credentials")
    if error:
        return LoginCheck(error)
    svc.limits.signin_address.reset(user_id)
    return LoginCheck(OK, address, user_id, profile)


async def complete_sign_in(
    svc: OAuthService, check: LoginCheck, password: str, old_cookie: str | None = None
) -> str:
    """Create/refresh the user and the sign-in mailbox account, open a portal session
    (counts as a fresh password entry). Returns the cookie value."""
    assert check.ok and check.address is not None and check.profile is not None
    user = await svc.store.get_or_create_user(check.user_id, check.address.normal)
    await ensure_primary(svc.store, user, check.address, password, check.profile)
    if old_cookie and len(old_cookie) <= 200:
        await svc.store.delete_portal_session(old_cookie)  # no session survives a sign-in
    raw, _ = await svc.store.create_portal_session(
        check.user_id, svc.cfg.portal_max, fresh_login=True
    )
    svc.audit("auth.sign_in", outcome="ok", user=short_id(check.user_id))
    return raw


async def verify_user_password(
    svc: OAuthService, request: Request, user: User, password: object
) -> str:
    """Re-authentication: is ``password`` the user's mailbox password? Returns ``OK`` or
    an error code. Shares the sign-in limits (wrong passwords count against the user)."""
    ip = client_ip(request, svc.cfg.trusted_proxy_hops)
    if not svc.limits.signin_ip.allow(ip or "-"):
        svc.audit("ratelimit.hit", scope="signin_ip")
        return RATE_LIMITED
    if svc.limits.signin_address.blocked(user.id):
        svc.audit("ratelimit.hit", scope="signin_address", user=short_id(user.id))
        return RATE_LIMITED
    if not valid_password(password):
        return BAD_CREDENTIALS
    assert isinstance(password, str)
    try:
        address = parse_address(user.primary_address)
    except AddressError:
        return UNAVAILABLE
    profile = svc.login_domains.get(address.domain)
    if profile is None:
        return UNAVAILABLE
    error = await _verify(svc, address, password, profile, user.id)
    if error == BAD_CREDENTIALS:
        svc.limits.signin_address.add(user.id)
        svc.audit("portal.reauth", outcome="bad_credentials", user=short_id(user.id))
    elif error == OK:
        svc.limits.signin_address.reset(user.id)
    return error
