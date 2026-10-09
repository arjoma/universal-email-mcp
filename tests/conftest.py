"""Shared fixtures: the audit pipeline is strict in tests (a call site that passes an
unknown field or a value outside the allow-list fails loudly) and starts fresh per test."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from universal_email_mcp import audit


@pytest.fixture(autouse=True)
def _audit_strict() -> Iterator[None]:
    audit.reset()
    audit.configure(strict=True)
    yield
    audit.reset()
