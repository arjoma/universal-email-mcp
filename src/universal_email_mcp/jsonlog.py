"""Structured JSON logging for the HTTP server (one object per line on stdout).

Field names follow what Cloud Logging understands (``severity``, ``message``,
``time``) and work anywhere else. The request id of the request being served is
added to every record through a context variable. Records carry what the code
passes as ``extra={"fields": {...}}``; never put mail content or secrets there.
"""

from __future__ import annotations

import contextvars
import json
import logging
import os
import sys
import traceback
from typing import Any, TextIO

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "uem_request_id", default=None
)

_MARK = "_uem_json"


def safe_trace(exc: BaseException | None, depth: int = 8, chain: int = 4) -> str:
    """A one-line account of an exception that is safe to log: class names, the error code of a
    ``MailError`` and the innermost ``depth`` frames (file:line function) of each exception in the
    chain - **never the message** and never local values. Messages and arguments of exceptions
    from the mail path carry mail-derived text (addresses, folder names, server replies); an
    ordinary traceback would copy them into the logs."""
    parts: list[str] = []
    seen: set[int] = set()
    e = exc
    while e is not None and id(e) not in seen and len(parts) < chain:
        seen.add(id(e))
        code = getattr(e, "code", None)
        label = type(e).__name__ + (f"[{code}]" if isinstance(code, str) else "")
        frames = traceback.extract_tb(e.__traceback__)[-depth:]
        where = " > ".join(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in frames)
        parts.append(f"{label} at {where}" if where else label)
        e = e.__cause__ or e.__context__
    return " <- ".join(parts) or "no exception"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": round(record.created, 3),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)  # pyright: ignore[reportUnknownArgumentType]
        if record.exc_info:
            # class names and frames only: exception messages can hold mail-derived text
            payload["exception"] = safe_trace(record.exc_info[1])
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str)


def setup_json_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    """Route all logging (root logger, so uvicorn and the SDK too) to JSON lines."""
    root = logging.getLogger()
    for h in list(root.handlers):  # also the CLI's plain-text stderr handler
        root.removeHandler(h)
    handler = logging.StreamHandler(stream or sys.stdout)
    setattr(handler, _MARK, True)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level)
    # Protocol-level debug output of the mail libraries contains mail data.
    logging.getLogger("imapclient").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").disabled = True  # we log requests ourselves


def log_event(logger: logging.Logger, level: int, message: str, **fields: Any) -> None:
    logger.log(level, message, extra={"fields": fields})
