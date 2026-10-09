"""Storage backends: a minimal document store with atomic multi-document commits.

A backend knows nothing about records, encryption or expiry; it keeps ``dict`` documents in
named collections and checks versions. Documents carry their version in ``_v``.
:class:`MemoryBackend` serves tests and single-process development; the Firestore backend
lives in :mod:`universal_email_mcp.store.firestore` (optional extra ``gcp``).
"""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from universal_email_mcp.errors import MailError

VERSION_KEY = "_v"

Doc = dict[str, Any]


class StoreConflict(MailError):
    """A precondition failed: stale version, missing record, or a concurrent change."""

    code = "STORE_CONFLICT"


class AlreadyExists(StoreConflict):
    code = "STORE_EXISTS"


@dataclass(frozen=True, slots=True)
class Op:
    """One write of an atomic commit.

    ``create`` fails if the id exists. ``replace`` needs ``expected_version`` and fails if the
    stored version differs. ``delete`` with ``expected_version`` is conditional, without it
    unconditional (and a no-op for a missing document).
    """

    kind: Literal["create", "replace", "delete"]
    collection: str
    id: str
    doc: Doc | None = None
    expected_version: int | None = None


class Backend(Protocol):
    async def get(self, collection: str, id: str) -> Doc | None: ...

    async def commit(self, ops: Sequence[Op]) -> None:
        """Apply all ops atomically or none (raises ``StoreConflict`` / ``AlreadyExists``)."""
        ...

    async def find(self, collection: str, field: str, value: str) -> list[tuple[str, Doc]]:
        """Documents whose top-level ``field`` equals ``value``."""
        ...

    def scan(self, collection: str) -> AsyncIterator[tuple[str, Doc]]: ...

    async def close(self) -> None: ...


def check_op(op: Op, current: Doc | None) -> None:
    """Shared precondition check of one op against the current document."""
    if op.kind == "create":
        if current is not None:
            raise AlreadyExists(f"{op.collection} record already exists")
    elif op.expected_version is not None or op.kind == "replace":
        if current is None or current.get(VERSION_KEY) != op.expected_version:
            raise StoreConflict(f"{op.collection} record changed or is missing")


class MemoryBackend:
    """In-process dict store. Documents are deep-copied in and out."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, Doc]] = {}

    async def get(self, collection: str, id: str) -> Doc | None:
        doc = self._data.get(collection, {}).get(id)
        return copy.deepcopy(doc) if doc is not None else None

    async def commit(self, ops: Sequence[Op]) -> None:
        for op in ops:  # no await between check and apply: atomic within the event loop
            check_op(op, self._data.get(op.collection, {}).get(op.id))
        for op in ops:
            col = self._data.setdefault(op.collection, {})
            if op.kind == "delete":
                col.pop(op.id, None)
            else:
                col[op.id] = copy.deepcopy(op.doc or {})

    async def find(self, collection: str, field: str, value: str) -> list[tuple[str, Doc]]:
        return [
            (i, copy.deepcopy(d))
            for i, d in self._data.get(collection, {}).items()
            if d.get(field) == value
        ]

    async def scan(self, collection: str) -> AsyncIterator[tuple[str, Doc]]:
        for i, d in list(self._data.get(collection, {}).items()):
            yield i, copy.deepcopy(d)

    async def close(self) -> None:
        pass

    def raw(self, collection: str) -> dict[str, Doc]:
        """The stored documents as they are (tests inspect them for plaintext)."""
        return self._data.get(collection, {})
