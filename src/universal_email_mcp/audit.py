"""Audit events (design section 9): one JSON line per event on stderr.

Events describe *what happened*, never *what was in it*: no addresses, subjects,
bodies, attachment names, folder names or credentials - only counts, size buckets,
account names the user chose and outcomes. ``setup()`` attaches the stderr handler
(always on, independent of ``-v``); in tests the logger is captured with ``caplog``.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

LOGGER_NAME = "universal_email_mcp.audit"
log = logging.getLogger(LOGGER_NAME)


def setup() -> None:
    """Send audit events to stderr (idempotent)."""
    if any(getattr(h, "_uem_audit", False) for h in log.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler._uem_audit = True  # type: ignore[attr-defined]  # pyright: ignore[reportAttributeAccessIssue]
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    log.propagate = False


def size_bucket(n: int) -> str:
    for limit, label in (
        (10_000, "<10k"),
        (100_000, "<100k"),
        (1_000_000, "<1M"),
        (10_000_000, "<10M"),
    ):
        if n < limit:
            return label
    return ">=10M"


def event(name: str, **fields: Any) -> None:
    """Log one event. Callers pass only counts, buckets, names and outcomes."""
    payload = {"event": name, "ts": round(time.time(), 3), **fields}
    log.info(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
