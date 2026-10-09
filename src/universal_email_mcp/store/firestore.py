"""Firestore (native mode) backend. Needs the extra ``gcp``: ``pip install universal-email-mcp[gcp]``.

Layout: one top-level collection per record kind (``<prefix><kind>``, prefix default empty so
several instances can share a project via e.g. ``prefix="uem1_"``), document id = record id.
Fields are the record fields; ``_v`` is the version, ``expires_at`` a timestamp for Firestore
TTL policies, ``_sealed`` the encrypted blob. Every commit runs in one transaction (reads
first, then writes), which makes token rotation atomic. Queries are single-field equality
(``user_id``, ``grant_id``) and need no composite index.

Firestore deletes expired documents some time after ``expires_at`` (typically within 24 h),
therefore the store also checks ``expires_at`` on every read.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from typing import Any
from urllib.parse import quote, unquote

from google.cloud import firestore  # pyright: ignore[reportMissingTypeStubs]
from google.cloud.firestore_v1.base_query import FieldFilter  # pyright: ignore

from universal_email_mcp.store.backend import Doc, Op, StoreConflict, check_op

_ATTEMPTS = 10
TTL_FIELD = "expires_at"


def _doc_id(record_id: str) -> str:
    """Firestore ids cannot contain "/" (CIMD client ids are URLs): percent-encode, reversibly."""
    return quote(record_id, safe="")


class FirestoreBackend:
    def __init__(
        self,
        client: Any | None = None,
        *,
        project: str | None = None,
        database: str | None = None,
        prefix: str = "",
    ) -> None:
        """``client`` is an ``AsyncClient``; by default one is created from the environment
        (application default credentials, or ``FIRESTORE_EMULATOR_HOST``)."""
        kwargs: dict[str, Any] = {}
        if project:
            kwargs["project"] = project
        if database:
            kwargs["database"] = database
        self._client: Any = client or firestore.AsyncClient(**kwargs)
        self._prefix = prefix

    def _col(self, collection: str) -> Any:
        return self._client.collection(self._prefix + collection)

    async def get(self, collection: str, id: str) -> Doc | None:
        snap = await self._col(collection).document(_doc_id(id)).get()
        return snap.to_dict() if snap.exists else None

    async def commit(self, ops: Sequence[Op]) -> None:
        if not ops:
            return
        refs = [self._col(op.collection).document(_doc_id(op.id)) for op in ops]

        @firestore.async_transactional
        async def run(tx: Any) -> None:
            for op, ref in zip(ops, refs, strict=True):
                snap = await ref.get(transaction=tx)
                check_op(op, snap.to_dict() if snap.exists else None)
            for op, ref in zip(ops, refs, strict=True):
                if op.kind == "delete":
                    tx.delete(ref)
                else:
                    tx.set(ref, op.doc or {})

        try:
            await run(self._client.transaction(max_attempts=_ATTEMPTS))
        except ValueError as e:  # the SDK's "failed to commit in N attempts": heavy contention
            if "attempts" not in str(e):
                raise
            raise StoreConflict("too many concurrent changes to these records") from e

    async def find(self, collection: str, field: str, value: str) -> list[tuple[str, Doc]]:
        query = self._col(collection).where(filter=FieldFilter(field, "==", value))
        return [(unquote(s.id), s.to_dict()) async for s in query.stream()]

    async def scan(self, collection: str) -> AsyncIterator[tuple[str, Doc]]:
        async for s in self._col(collection).stream():
            yield unquote(s.id), s.to_dict()

    async def close(self) -> None:
        self._client.close()
