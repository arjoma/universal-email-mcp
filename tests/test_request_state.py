"""The key material of the sealed ``requestState`` (WP 3f): same on every instance, rotates
with the store key ring, bound to user and grant."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from mcp.server.request_state import InvalidRequestState

from universal_email_mcp.server.peruser import (
    request_state_security,
    state_principal,
    user_context_var,
)
from universal_email_mcp.store import KeyRing


def test_two_instances_of_one_deployment_open_each_others_states():
    ring = lambda: KeyRing({"k1": b"a" * 32})  # noqa: E731 - one ring per "instance"
    one, two = request_state_security(ring()), request_state_security(ring())
    token = one.codec.seal(b"payload")
    assert two.codec.unseal(token) == b"payload"


def test_another_deployment_or_a_changed_key_does_not():
    mine = request_state_security(KeyRing({"k1": b"a" * 32}))
    theirs = request_state_security(KeyRing({"k1": b"b" * 32}))
    token = mine.codec.seal(b"payload")
    with pytest.raises(InvalidRequestState):
        theirs.codec.unseal(token)
    # nor is a state sealed under the store key itself (a different purpose) accepted
    with pytest.raises(InvalidRequestState):
        mine.codec.unseal("v1." + "A" * 80)


def test_rotation_keeps_old_states_valid_and_seals_with_the_new_key():
    before = request_state_security(KeyRing({"k1": b"a" * 32}))
    after = request_state_security(KeyRing({"k1": b"a" * 32, "k2": b"b" * 32}))
    old = before.codec.seal(b"old")
    assert after.codec.unseal(old) == b"old"
    new = after.codec.seal(b"new")
    with pytest.raises(InvalidRequestState):
        before.codec.unseal(new)  # a lagging instance does not know k2 yet: it refuses, safely


def test_the_principal_is_user_and_grant_and_missing_context_fails_closed():
    ctx: Any = SimpleNamespace(user_id="u_1", grant_id="g_1")
    token = user_context_var.set(ctx)
    try:
        a = state_principal(None)  # pyright: ignore[reportArgumentType]
        user_context_var.set(SimpleNamespace(user_id="u_1", grant_id="g_2"))  # type: ignore[arg-type]
        b = state_principal(None)  # pyright: ignore[reportArgumentType]
    finally:
        user_context_var.reset(token)
    assert a != b and "u_1" in a and "g_1" in a
    with pytest.raises(RuntimeError):
        state_principal(None)  # pyright: ignore[reportArgumentType]
