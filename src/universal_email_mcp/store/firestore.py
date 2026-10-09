"""Firestore (native mode) backend. Needs the extra ``gcp``: ``pip install universal-email-mcp[gcp]``.

Layout: one top-level collection per record kind (``<prefix><kind>``, prefix default empty so
several instances can share a project via e.g. ``prefix="uem1_"``), document id = SHA-256 of kind and record id (the real id is kept in ``_id``).
Fields are the record fields; ``_v`` is the version, ``expires_at`` a timestamp for Firestore
TTL policies, ``_sealed`` the encrypted blob. Every commit runs in one transaction (reads
first, then writes), which makes token rotation atomic. Queries are single-field equality
(``user_id``, ``grant_id``) and need no composite index.

Firestore deletes expired documents some time after ``expires_at`` (typically within 24 h),
therefore the store also checks ``expires_at`` on every read.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
from collections.abc import AsyncIterator, Sequence
from typing import Any

from google.api_core import exceptions as gexc
from google.cloud import firestore  # pyright: ignore[reportMissingTypeStubs]
from google.cloud.firestore_v1.base_query import FieldFilter  # pyright: ignore

from universal_email_mcp.store.backend import AlreadyExists, Doc, Op, StoreConflict, check_op

ID_KEY = "_id"
_ATTEMPTS = 10
_TX_ATTEMPTS = 3
_ROUNDS = 6


def _doc_id(collection: str, record_id: str) -> str:
    """Fixed-length document id derived from the record id.

    Record ids can come from untrusted input (OAuth client ids are client-chosen URLs) and
    Firestore rejects ids like ``.``, ``__x__``, with ``/`` or over 1500 bytes. The real id is
    kept in the ``_id`` field.
    """
    return hashlib.sha256(f"{collection}\x00{record_id}".encode()).hexdigest()


def _out(snap: Any) -> tuple[str, Doc]:
    doc: Doc = snap.to_dict()
    return str(doc.pop(ID_KEY)), doc


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
        snap = await self._col(collection).document(_doc_id(collection, id)).get()
        return _out(snap)[1] if snap.exists else None

    async def commit(self, ops: Sequence[Op]) -> None:
        if not ops:
            return
        refs = [self._col(op.collection).document(_doc_id(op.collection, op.id)) for op in ops]
        if all(
            op.kind == "create" or (op.kind == "delete" and op.expected_version is None)
            for op in ops
        ):
            await self._write_batch(ops, refs)
            return

        @firestore.async_transactional
        async def run(tx: Any) -> None:
            for op, ref in zip(ops, refs, strict=True):
                snap = await ref.get(transaction=tx)
                check_op(op, _out(snap)[1] if snap.exists else None)
            for op, ref in zip(ops, refs, strict=True):
                if op.kind == "delete":
                    tx.delete(ref)
                else:
                    tx.set(ref, {**(op.doc or {}), ID_KEY: op.id})

        # The SDK retries an aborted transaction itself, but with long back-offs, and the
        # racers of one document keep aborting each other (all hold a read lock, all want to
        # write). A few short rounds with jitter let one win; the others then fail the
        # version check at once instead of timing out.
        for round_ in range(_ROUNDS):
            try:
                await run(self._client.transaction(max_attempts=_TX_ATTEMPTS))
                return
            except ValueError as e:  # the SDK's "failed to commit in N attempts"
                if "attempts" not in str(e):
                    raise
            await asyncio.sleep(random.uniform(0.05, 0.25) * (round_ + 1))
        raise StoreConflict("too many concurrent changes to these records")

    async def _write_batch(self, ops: Sequence[Op], refs: Sequence[Any]) -> None:
        """Commits without a precondition read: creates (``exists == false`` is checked by
        the server) and unconditional deletes. A transaction would read the documents and
        lock them, so concurrent sign-ins of one user or revocations of one grant would
        queue behind each other until the SDK gives up ("Transaction lock timeout");
        here the server decides atomically and nobody waits."""
        batch = self._client.batch()
        for op, ref in zip(ops, refs, strict=True):
            if op.kind == "delete":
                batch.delete(ref)
            else:
                batch.create(ref, {**(op.doc or {}), ID_KEY: op.id})
        for attempt in range(_ATTEMPTS):
            try:
                await batch.commit()
                return
            except gexc.AlreadyExists as e:
                raise AlreadyExists("record already exists") from e
            except gexc.Aborted:
                # Contention on a document ("Transaction lock timeout", "too much contention"):
                # nothing was written, so trying again is safe. The retry then either wins or
                # meets the other writer's document and reports AlreadyExists.
                await asyncio.sleep(min(1.0, 0.05 * 2**attempt) * (0.5 + random.random()))
        raise StoreConflict("too many concurrent changes to these records")

    async def find(self, collection: str, field: str, value: str) -> list[tuple[str, Doc]]:
        query = self._col(collection).where(filter=FieldFilter(field, "==", value))
        return [_out(s) async for s in query.stream()]

    async def scan(self, collection: str) -> AsyncIterator[tuple[str, Doc]]:
        async for s in self._col(collection).stream():
            yield _out(s)

    async def close(self) -> None:
        self._client.close()
