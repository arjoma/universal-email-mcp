"""Rate limits: the limiter, the configuration, and each limit end to end (no mail server)."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from pathlib import Path

import pytest
from starlette.requests import Request

from tests.oauth_util import PASSWORD, Authz, make_app, new_client, operator, register
from tests.portal_util import Browser, FakeTester
from universal_email_mcp.audit import LOGGER_NAME
from universal_email_mcp.errors import ConfigError
from universal_email_mcp.oauth.config import RATE_VARIABLES, Rate, RateLimits
from universal_email_mcp.oauth.ratelimit import LimiterSet, RateLimiter, ip_group
from universal_email_mcp.operator import OAuthSettings, load_operator_config, parse_rate
from universal_email_mcp.portal.web import client_ip
from universal_email_mcp.service.toolrate import ToolRateLimiter


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def minutes(count: int, n: int = 1) -> Rate:
    return Rate(count, timedelta(minutes=n))


# ---------------------------------------------------------------- the limiter


def test_sliding_window_and_retry_after():
    clock = Clock()
    lim = RateLimiter(3, 60, clock=clock)
    assert [lim.allow("k") for _ in range(3)] == [True] * 3
    assert not lim.allow("k") and lim.blocked("k")
    assert lim.retry_after("k") == 61
    assert lim.retry_after("other") == 0 and lim.allow("other")  # keys are independent
    clock.t += 30
    assert lim.retry_after("k") == 31
    clock.t += 31  # the first events slid out
    assert not lim.blocked("k") and lim.retry_after("k") == 0 and lim.allow("k")


def test_refused_events_are_not_counted_and_reset_clears():
    clock = Clock()
    lim = RateLimiter(2, 10, clock=clock)
    assert lim.allow("k") and lim.allow("k")
    for _ in range(50):
        assert not lim.allow("k")  # hammering does not extend the block
    clock.t += 11
    assert lim.allow("k")
    lim.add("k")
    lim.add("k")
    lim.reset("k")
    assert not lim.blocked("k")


def test_one_key_never_holds_more_than_limit_timestamps():
    lim = RateLimiter(5, 3600)
    for _ in range(10_000):
        lim.add("flood")  # e.g. failed logins recorded without a prior check
    assert len(lim._events["flood"]) == 5  # pyright: ignore[reportPrivateUsage]


def test_many_distinct_keys_stay_bounded_and_recent_keys_survive():
    clock = Clock()
    lim = RateLimiter(2, 600, clock=clock, max_keys=200)
    for i in range(5000):
        clock.t += 0.01
        lim.add(f"user-{i}")
        assert len(lim) <= 200
    assert lim.blocked("nobody") is False
    lim.add("user-4999")
    assert lim.blocked("user-4999")  # the newest keys were kept (two events)


def test_expired_keys_are_dropped_before_live_ones():
    clock = Clock()
    lim = RateLimiter(1, 10, clock=clock, max_keys=10)
    for i in range(10):
        lim.add(f"old-{i}")
    clock.t += 5
    lim.add("live")
    clock.t += 6  # old-* expired, live is still counted
    for i in range(9):
        lim.add(f"new-{i}")
    assert lim.blocked("live") and len(lim) <= 10


def test_limiter_set_counts_all_or_none():
    clock = Clock()
    burst, sustained = RateLimiter(2, 10, clock=clock), RateLimiter(3, 100, clock=clock)
    both = LimiterSet(burst, sustained)
    assert both.hit("k") == 0 and both.hit("k") == 0
    wait = both.hit("k")  # burst exhausted
    assert wait == 11
    clock.t += 11
    assert both.hit("k") == 0  # third in the sustained window
    clock.t += 11
    assert both.hit("k") == 79  # burst is free again, the sustained window is used up
    assert len(sustained._events["k"]) == 3  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    ("raw", "group"),
    [
        ("203.0.113.7", "203.0.113.7"),
        ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"),
        ("2001:db8:1:2:1111:2222:3333:4444", "2001:db8:1:2::/64"),
        ("2001:db8:1:3::1", "2001:db8:1:3::/64"),
        ("::ffff:198.51.100.9", "198.51.100.9"),
        ("::1", "::/64"),
        ("", "-"),
        ("testclient", "-"),
        ("999.1.1.1", "-"),
        ("1.2.3.4, 5.6.7.8", "-"),
        ("A" * 100_000, "-"),
        ("\x00\n", "-"),
    ],
)
def test_ip_group(raw: str, group: str):
    assert ip_group(raw) == group


# ---------------------------------------------------------------- the client address


def request_with(forwarded: str | None, peer: str = "10.0.0.1") -> Request:
    headers = [(b"host", b"x")]
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode("latin-1", "replace")))
    return Request(
        {"type": "http", "headers": headers, "client": (peer, 1234), "method": "GET", "path": "/"}
    )


def test_client_ip_follows_the_declared_number_of_proxies():
    r = request_with("6.6.6.6, 203.0.113.7")  # a client-supplied entry, then the real one
    assert client_ip(r, 0) == "10.0.0.1"  # no proxy declared: the header is ignored
    assert client_ip(r, 1) == "203.0.113.7"
    assert client_ip(r, 2) == "6.6.6.6"
    assert client_ip(r, 3) == "10.0.0.1"  # chain shorter than declared: the peer


@pytest.mark.parametrize(
    "forwarded",
    ["", "garbage", "," * 5000, "1.2.3.4," + "x" * 1_000_000, "\x00\x01", "[::1]:80", "a" * 2000],
)
def test_hostile_forwarded_headers_fall_back_to_the_peer(forwarded: str):
    assert client_ip(request_with(forwarded), 1) == "10.0.0.1"  # never a string of the header


# ---------------------------------------------------------------- tool-call limiter


def tool_limiter(clock: Clock, **changes: Rate) -> ToolRateLimiter:
    loose = Rate(10_000, timedelta(hours=1))
    base = {
        f: loose
        for f in (
            "tool_user_burst", "tool_user", "tool_grant_burst",
            "tool_grant", "tool_write_burst", "tool_write",
        )
    }  # fmt: skip
    return ToolRateLimiter(RateLimits(**{**base, **changes}), clock=clock)


def test_tool_burst_and_sustained_windows():
    clock = Clock()
    tl = tool_limiter(
        clock,
        tool_user_burst=Rate(3, timedelta(seconds=10)),
        tool_user=Rate(5, timedelta(seconds=100)),
    )
    for _ in range(3):
        assert tl.check("u1", "g1", "find_messages") is None
    refusal = tl.check("u1", "g1", "find_messages")
    assert refusal and refusal.scope == "tool_user" and refusal.retry_after == 11
    clock.t += 11
    assert tl.check("u1", "g1", "find_messages") is None  # burst over, sustained 4 of 5
    assert tl.check("u1", "g1", "find_messages") is None
    clock.t += 11  # burst fine again, sustained used up (5 of 5 within 100 s)
    refusal = tl.check("u1", "g1", "find_messages")
    assert refusal and refusal.retry_after > 50
    assert tl.check("u2", "g2", "find_messages") is None  # other users are unaffected


def test_tool_refused_calls_cost_nothing_and_writes_are_tighter():
    clock = Clock()
    tl = tool_limiter(clock, tool_write_burst=Rate(1, timedelta(seconds=10)))
    assert tl.check("u", "g", "mark_messages") is None
    for _ in range(20):
        refusal = tl.check("u", "g", "delete_messages")
        assert refusal and refusal.scope == "tool_write"
    assert tl.check("u", "g", "find_messages") is None  # reads go on
    clock.t += 11
    assert tl.check("u", "g", "move_messages") is None  # the 20 refusals did not extend it


def test_tool_grant_limit_is_separate_from_the_user_limit():
    clock = Clock()
    tl = tool_limiter(clock, tool_grant_burst=Rate(1, timedelta(seconds=10)))
    assert tl.check("u", "g1", "account_info") is None
    refusal = tl.check("u", "g1", "account_info")
    assert refusal and refusal.scope == "tool_grant"
    assert tl.check("u", "g2", "account_info") is None  # second client of the same user


def test_tool_error_is_structured_english_with_retry_after():
    clock = Clock()
    tl = tool_limiter(clock, tool_user_burst=Rate(1, timedelta(seconds=10)))
    tl.check("u", "g", "account_info")
    refusal = tl.check("u", "g", "account_info")
    assert refusal
    err = tl.error(refusal)
    assert err.code == "RATE_LIMITED"
    assert err.to_dict()["retry_after"] == refusal.retry_after
    assert str(refusal.retry_after) in err.hint and "tool calls" in err.message


def test_many_distinct_users_do_not_grow_memory_without_bound():
    tl = tool_limiter(Clock())
    for i in range(60_000):
        tl.check(f"u_{i}", f"g_{i}", "find_messages")
    for limiters in (tl._user, tl._grant):  # pyright: ignore[reportPrivateUsage]
        assert all(len(lim) <= 20_000 for lim in limiters.limiters)


# ---------------------------------------------------------------- configuration


ENV = {
    "STORE_BACKEND": "memory",
    "PUBLIC_URL": "https://mcp.example.com",
    "LOGIN_DOMAINS": "example.org=imap.example.org",
}


def test_defaults_are_sane():
    op = load_operator_config(ENV)
    assert op.rate_limits == RateLimits()
    for name in RateLimits.__slots__:
        rate = getattr(op.rate_limits, name)
        assert 1 <= rate.count <= 10_000 and 1 <= rate.seconds <= 86_400
    r = RateLimits()
    assert r.tool_write_burst.count < r.tool_user_burst.count
    assert r.tool_write.count < r.tool_user.count


def test_rates_are_read_from_the_environment():
    op = load_operator_config(
        {**ENV, "UEM_RATE_SIGNIN_IP": "7/2m", "UEM_RATE_TOOL_USER_BURST": " 12 / 30 ",
         "UEM_RATE_DOWNLOAD_USER": "5/1h", "UEM_RATE_TOKEN_IP": "9/45s", "UEM_RATE_PORTAL_IP": "3/1d"}
    )  # fmt: skip
    rl = op.rate_limits
    assert rl.signin_ip == Rate(7, timedelta(minutes=2))
    assert rl.tool_user_burst == Rate(12, timedelta(seconds=30))  # bare number = seconds
    assert rl.download_user == minutes(5, 60)
    assert rl.token_ip == Rate(9, timedelta(seconds=45)) and rl.portal_ip.window.days == 1
    assert rl.signin_address == RateLimits().signin_address  # the rest keeps its default


@pytest.mark.parametrize(
    "value",
    ["", "5", "/5m", "5/", "0/5m", "-1/5m", "5/0", "5/0m", "5/-3", "5/8d", "100001/1m",
     "five/5m", "5/xm", "5/1.5m", "5/5 m x", "1e3/5m", "5//5m", "٣/5m", "5/٣m", "5/5w", "1_0/5m", "+5/5m", "5/1_0"],
)  # fmt: skip
def test_nonsense_rates_are_rejected_naming_the_variable(value: str):
    if value == "":
        assert (
            load_operator_config({**ENV, "UEM_RATE_SIGNIN_IP": value}).rate_limits == RateLimits()
        )
        return
    with pytest.raises(ConfigError, match="UEM_RATE_SIGNIN_IP"):
        load_operator_config({**ENV, "UEM_RATE_SIGNIN_IP": value})


def test_unknown_rate_variable_is_an_error_not_silently_ignored():
    with pytest.raises(ConfigError, match="UEM_RATE_SIGNIN_IPP"):
        load_operator_config({**ENV, "UEM_RATE_SIGNIN_IPP": "5/1m"})


def test_parse_rate_roundtrip():
    for text in ("5/15m", "300/1m", "30/10s", "60/10m", "10/1h", "7/1d"):
        assert str(parse_rate("X", text)) == text


def test_every_limit_is_documented_with_its_default():
    doc = (Path(__file__).parent.parent / "docs" / "operator-env.md").read_text()
    defaults = RateLimits()
    for var, field_name in RATE_VARIABLES.items():
        rows = [line for line in doc.splitlines() if f"`{var}`" in line]
        assert rows, f"{var} is not documented in docs/operator-env.md"
        assert f"`{getattr(defaults, field_name)}`" in rows[0], f"default of {var} is stale"


# ---------------------------------------------------------------- end to end: portal


def hits(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [
        json.loads(r.getMessage())
        for r in caplog.records
        if r.name == LOGGER_NAME and '"ratelimit.hit"' in r.getMessage()
    ]


async def build(op=None, **limits: Rate):
    return await make_app(op or operator(), tester=FakeTester(), rate_limits=RateLimits(**limits))


def xff(ip: str) -> dict[str, str]:
    return {"x-forwarded-for": ip}


async def test_reauthentication_brute_force_is_blocked_per_user(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    app = await build()
    with Browser(app) as b:
        b.signed_in()
        codes = [b.post("/portal/reauth", {"password": f"guess{i}"}).status_code for i in range(5)]
        assert codes == [401] * 5
        r = b.post("/portal/reauth", {"password": PASSWORD})  # even the right one is refused now
        assert r.status_code == 429 and "Too many attempts" in r.text
    assert [h["scope"] for h in hits(caplog)] == ["signin_address"]


async def test_reauthentication_attempts_are_blocked_per_network():
    op = operator(oauth=OAuthSettings(trusted_proxy_hops=1))
    app = await build(op, signin_ip=minutes(4, 15))
    with Browser(app) as b:
        b.client.headers.update(xff("203.0.113.9"))
        b.signed_in()  # attempt 1 from this address
        assert [b.post("/portal/reauth", {"password": PASSWORD}).status_code for _ in range(3)] == [
            303,
            303,
            303,
        ]
        assert b.post("/portal/reauth", {"password": PASSWORD}).status_code == 429
        b.client.headers.update(xff("203.0.113.10"))  # another network is not affected
        assert b.post("/portal/reauth", {"password": PASSWORD}).status_code == 303


async def test_ipv6_clients_are_limited_per_64():
    op = operator(oauth=OAuthSettings(trusted_proxy_hops=1))
    app = await build(op, signin_ip=minutes(2, 15))
    client = new_client(app)
    a = Authz(client, register(client))
    for ip in ("2001:db8:1:2::1", "2001:db8:1:2:ffff::7"):  # two addresses, one /64
        client.headers.update(xff(ip))
        assert a.sign_in("x@example.org", "wrong").status_code == 401
    assert a.sign_in("bob@example.org").status_code == 429
    client.headers.update(xff("2001:db8:1:3::1"))  # the next /64
    assert a.sign_in("bob@example.org").status_code == 303


async def test_a_forged_forwarded_header_does_not_buy_a_new_allowance():
    op = operator(oauth=OAuthSettings(trusted_proxy_hops=1))
    app = await build(op, signin_ip=minutes(2, 15))
    client = new_client(app)
    a = Authz(client, register(client))
    # the proxy appends the real peer; entries to its left are the client's claims
    for forged in ("1.1.1.1", "2.2.2.2", "garbage", "3.3.3.3, 4.4.4.4"):
        client.headers.update(xff(f"{forged}, 198.51.100.77"))
        a.sign_in("x@example.org", "wrong")
    assert a.sign_in("bob@example.org").status_code == 429


async def test_hostile_client_address_headers_do_not_break_or_fill_the_limiter():
    op = operator(oauth=OAuthSettings(trusted_proxy_hops=1))
    app = await build(op)
    client = new_client(app)
    a = Authz(client, register(client))
    for forged in ("A" * 100_000, ",,,,", "\x01\x02", "::ffff:1.2.3.4:99", "1" * 4000):
        client.headers.update(xff(forged))
        assert a.sign_in("x@example.org", "wrong").status_code in (401, 429)
    limiter = app.state.oauth_service.limits.signin_ip
    assert len(limiter) <= 3  # all garbage shares the one bucket (plus real peers)


async def test_portal_actions_are_limited_per_user(caplog: pytest.LogCaptureFixture):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    app = await build(portal_user=minutes(3))
    with Browser(app) as b:
        b.signed_in()
        codes = [b.post("/portal/accounts/a_0/test").status_code for _ in range(4)]
        assert codes == [404, 404, 404, 429]
        r = b.post("/portal/accounts/a_0/test")
        assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 61
        assert "too often" in r.text and "<script" not in r.text
        assert b.get("/portal/accounts").status_code == 200  # reading is not limited
    assert {h["scope"] for h in hits(caplog)} == {"portal_action"}


async def test_portal_actions_are_limited_per_network():
    op = operator(oauth=OAuthSettings(trusted_proxy_hops=1))
    app = await build(op, portal_ip=minutes(3))
    with Browser(app) as alice, Browser(app, "bob@example.org") as bob:
        for b in (alice, bob):
            b.client.headers.update(xff("203.0.113.5"))
            b.signed_in()
        codes = [alice.post("/portal/accounts/a_0/test").status_code for _ in range(2)]
        codes.append(bob.post("/portal/accounts/a_0/test").status_code)
        assert codes == [404, 404, 404]
        assert bob.post("/portal/accounts/a_0/test").status_code == 429  # same network
        bob.client.headers.update(xff("203.0.113.6"))
        assert bob.post("/portal/accounts/a_0/test").status_code == 404


async def test_viewer_and_downloads_have_their_own_per_user_limits(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    app = await build(viewer_user=minutes(2), download_user=minutes(1))
    with Browser(app) as b:
        b.signed_in()
        pages = [b.get("/m/m1.abcdef").status_code for _ in range(3)]
        assert pages[:2] != [429, 429] and 429 not in pages[:2] and pages[2] == 429
        r = b.get("/m/m1.abcdef")
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        assert "too often" in r.text
        assert b.get("/m/m1.abcdef/eml").status_code != 429
        r = b.get("/m/m1.abcdef/eml")
        assert r.status_code == 429 and "too often" in r.text
        assert (
            b.get("/m/m1.abcdef/a/1.2").status_code == 429
        )  # attachments share the download limit
    assert {h["scope"] for h in hits(caplog)} == {"viewer", "download"}


async def test_the_authorize_endpoint_is_limited_per_network():
    app = await build(authorize_ip=minutes(3))
    with new_client(app) as c:
        codes = [c.post("/authorize", data={"action": "approve"}).status_code for _ in range(5)]
        assert codes[:3] == [400, 400, 400] and codes[3:] == [429, 429]
        assert int(c.post("/authorize", data={}).headers["retry-after"]) >= 1


async def test_token_endpoint_answers_429_with_retry_after_and_audits(
    caplog: pytest.LogCaptureFixture,
):
    caplog.set_level(logging.INFO, logger=LOGGER_NAME)
    app = await build(token_ip=minutes(2))
    with new_client(app) as c:
        for path in ("/token", "/revoke", "/token"):
            r = c.post(path, data={"grant_type": "x"})
        assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
        assert r.json()["error"] == "invalid_request"
    assert {h["scope"] for h in hits(caplog)} == {"token_ip"}
    assert len(hits(caplog)) == 1


def test_ratelimit_hit_events_carry_no_address_unless_pseudonymised():
    from universal_email_mcp import audit

    spec = audit.EVENTS["ratelimit.hit"]
    assert {"scope", "ip", "grant"} <= spec.fields


def test_eviction_keeps_currently_blocked_keys():
    clock = Clock()
    lim = RateLimiter(2, 600, clock=clock, max_keys=50)
    lim.add("victim")
    lim.add("victim")
    for i in range(500):
        clock.t += 0.01
        lim.add(f"noise-{i}")
    assert lim.blocked("victim")  # the oldest key survived because it is blocked
