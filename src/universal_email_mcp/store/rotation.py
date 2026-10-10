"""Key rotation: re-seal and re-authenticate every record with the active key.

Rotation procedure (no logouts, no downtime): add the new key to ``STORE_KEYS`` (``k2``),
set ``STORE_ACTIVE_KEY=k2`` and deploy - new writes use ``k2``, old blobs still open with
``k1``. Then run ``universal-email-mcp admin rotate-keys`` (:func:`rotate_keys`) to migrate
the records nobody has written since; afterwards ``k1`` may be removed from the ring. Each
record carries a MAC under a key derived from the key that wrote it, so the run rewrites
records that are only MAC'd with an old key too (tokens, grants, sessions ...).

One thing rotation cannot carry over: the *ids* of bearer-secret records (access and refresh
tokens, authorization codes, portal sessions) are keyed by the ring key that issued them,
and the secret is not stored, so they cannot be re-keyed. Removing ``k1`` ends the portal
sessions and client sessions issued under it (users sign in again, clients re-authorize);
wait for their lifetimes to pass (12 h sessions, 30-day refresh tokens) if that matters.

A record that cannot be read (damaged, tampered, sealed with a key that is no longer in the
ring) does not stop the run: it is skipped and counted per kind, and a warning without any
content is logged. Such records need a look by the operator (restore from a backup, or let
the user add the account again); ``k1`` must not be removed while they are the only ones
left that need it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from universal_email_mcp.store.backend import StoreConflict
from universal_email_mcp.store.crypto import CryptoError
from universal_email_mcp.store.records import ALL_RECORDS
from universal_email_mcp.store.store import MAC_KEY, SEALED_KEY, UNREADABLE, Store

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RotationReport:
    resealed: dict[str, int]
    """Records re-sealed per kind (with ``dry_run``: that would be)."""
    unreadable: dict[str, int] = field(default_factory=dict[str, int])
    """Records skipped because they cannot be read, per kind (only kinds with any)."""
    dry_run: bool = False

    @property
    def total_unreadable(self) -> int:
        return sum(self.unreadable.values())


async def rotate_keys(store: Store, *, dry_run: bool = False) -> RotationReport:
    """Re-seal all blobs not sealed with the active key.

    Records changed concurrently are retried once and then skipped (they were rewritten
    with the active key by whoever changed them, or will be on the next run). Unreadable
    records are skipped and counted. With ``dry_run`` nothing is written.
    """
    resealed: dict[str, int] = {}
    unreadable: dict[str, int] = {}
    for cls in ALL_RECORDS:
        done = bad = 0
        async for rec_id, doc in store.backend.scan(cls.KIND):
            blob = doc.get(SEALED_KEY)
            try:
                if cls.SEALED and not isinstance(blob, str):
                    raise CryptoError("record has no sealed data")
                old_blob = isinstance(blob, str) and store.keys.needs_rotation(blob)
                old_mac = store.keys.mac_key_id(doc.get(MAC_KEY, "")) != store.keys.active
                if not (old_blob or old_mac):
                    continue
                if dry_run:
                    store.decode(cls, rec_id, doc)  # readable, so a run would re-seal it
                    done += 1
                    continue
            except UNREADABLE:
                bad += 1
                continue
            for _ in range(2):
                try:
                    rec = await store.get(cls, rec_id)
                except UNREADABLE:
                    bad += 1
                    break
                if rec is None:
                    break
                try:
                    await store.update(rec)
                    done += 1
                    break
                except StoreConflict:
                    continue
        resealed[cls.KIND] = done
        if bad:
            unreadable[cls.KIND] = bad
            # no ids, no content: only that something is damaged and where to look
            log.warning("rotate_keys: %d unreadable %s record(s) skipped", bad, cls.KIND)
    return RotationReport(resealed, unreadable, dry_run)
