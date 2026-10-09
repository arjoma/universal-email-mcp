"""Persistent state of remote mode (design section 10): records, encryption, backends.

The Firestore backend is not imported here (optional extra ``gcp``):
``from universal_email_mcp.store.firestore import FirestoreBackend``.
"""

from universal_email_mcp.store.backend import (
    AlreadyExists,
    Backend,
    MemoryBackend,
    StoreConflict,
)
from universal_email_mcp.store.crypto import (
    Aad,
    CryptoError,
    KeyRing,
    hash_token,
    new_token,
    tokens_equal,
)
from universal_email_mcp.store.records import (
    ActivityEntry,
    AuthCode,
    Grant,
    Identity,
    MailAccount,
    OAuthClient,
    PendingApproval,
    PortalSession,
    Token,
    User,
)
from universal_email_mcp.store.rotation import RotationReport, rotate_keys
from universal_email_mcp.store.store import (
    CodeReplay,
    InvalidToken,
    IssuedTokens,
    SessionPolicy,
    Store,
    TokenReuse,
)

__all__ = [
    "Aad",
    "ActivityEntry",
    "AlreadyExists",
    "AuthCode",
    "Backend",
    "CodeReplay",
    "CryptoError",
    "Grant",
    "Identity",
    "InvalidToken",
    "IssuedTokens",
    "KeyRing",
    "MailAccount",
    "MemoryBackend",
    "OAuthClient",
    "PendingApproval",
    "PortalSession",
    "SessionPolicy",
    "Store",
    "StoreConflict",
    "Token",
    "TokenReuse",
    "User",
    "hash_token",
    "new_token",
    "RotationReport",
    "rotate_keys",
    "tokens_equal",
]
