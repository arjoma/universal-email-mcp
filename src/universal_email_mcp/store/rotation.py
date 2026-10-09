"""Key rotation: re-seal every record with the active key.

Rotation procedure (no logouts, no downtime): add the new key to ``STORE_KEYS`` (``k2``),
set ``STORE_ACTIVE_KEY=k2`` and deploy - new writes use ``k2``, old blobs still open with
``k1``. Then run ``rotate_keys(store)`` (the future ``admin rotate-keys`` command) to migrate
the records nobody has written since; afterwards ``k1`` may be removed from the ring.
"""

from __future__ import annotations

from universal_email_mcp.store.backend import StoreConflict
from universal_email_mcp.store.records import ALL_RECORDS
from universal_email_mcp.store.store import SEALED_KEY, Store


async def rotate_keys(store: Store) -> dict[str, int]:
    """Re-seal all blobs not sealed with the active key; returns counts per record kind.

    Records changed concurrently are retried once and then skipped (they were rewritten
    with the active key by whoever changed them, or will be on the next run).
    """
    counts: dict[str, int] = {}
    for cls in ALL_RECORDS:
        if not cls.SEALED:
            continue
        done = 0
        async for rec_id, doc in store.backend.scan(cls.KIND):
            blob = doc.get(SEALED_KEY)
            if not isinstance(blob, str) or not store.keys.needs_rotation(blob):
                continue
            for _ in range(2):
                rec = await store.get(cls, rec_id)
                if rec is None:
                    break
                try:
                    await store.update(rec)
                    done += 1
                    break
                except StoreConflict:
                    continue
        counts[cls.KIND] = done
    return counts
