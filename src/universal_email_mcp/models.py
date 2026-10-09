"""Typed domain models shared by config, backends and tools.

All models are frozen dataclasses: cheap, hashable where it makes sense, and
directly usable as structured tool output. Datetimes are timezone-aware.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, get_args

from universal_email_mcp.errors import InvalidRef

# --------------------------------------------------------------------------- servers

TlsMode = Literal["tls", "starttls"]
"""``tls`` = implicit TLS (993/995/465); ``starttls`` = upgrade a plain connection
(143/110/587). Plain-text connections are not supported."""

TLS_MODES: tuple[TlsMode, ...] = get_args(TlsMode)

FolderRole = Literal["inbox", "sent", "drafts", "trash", "junk", "archive"]
FOLDER_ROLES: tuple[FolderRole, ...] = get_args(FolderRole)

AccountKind = Literal["imap", "pop3"]
ACCOUNT_KINDS: tuple[AccountKind, ...] = get_args(AccountKind)


@dataclass(frozen=True, slots=True)
class Endpoint:
    """One protocol endpoint of a mail server."""

    host: str
    port: int
    tls: TlsMode = "tls"


@dataclass(frozen=True, slots=True)
class ServerProfile:
    """Where an account's servers live. Built from a preset, a hostname or config.

    ``folder_roles`` maps a role to a folder name and overrides role detection
    (used for providers whose folders carry no SPECIAL-USE flags and unusual names).
    """

    name: str
    imap: Endpoint | None = None
    pop3: Endpoint | None = None
    smtp: Endpoint | None = None
    folder_roles: dict[FolderRole, str] = field(default_factory=dict[FolderRole, str])
    label: str = ""


# --------------------------------------------------------------------------- accounts


@dataclass(frozen=True, slots=True)
class Permissions:
    """What the assistant may do with an incoming account (capped by policy)."""

    read: bool = True
    organize: bool = False  # mark seen/flagged, move
    delete: bool = False  # move to Trash
    drafts: bool = False  # create/update drafts


@dataclass(frozen=True, slots=True)
class CredentialRef:
    """Where the password comes from. Passwords are never stored in models or config.

    ``kind="env"``: ``name`` is an environment variable.
    ``kind="keyring"``: ``name`` is the key in the OS keyring under service
    ``universal-email-mcp``.
    """

    kind: Literal["env", "keyring"]
    name: str


@dataclass(frozen=True, slots=True)
class TlsSettings:
    """Per-account TLS knobs. ``verify=False`` is only for local/test setups."""

    verify: bool = True
    ca_file: str | None = None


@dataclass(frozen=True, slots=True)
class Account:
    """One incoming mailbox (IMAP or POP3)."""

    name: str
    kind: AccountKind
    username: str
    server: ServerProfile
    credential: CredentialRef
    permissions: Permissions = Permissions()
    tls: TlsSettings = TlsSettings()
    folder_roles: dict[FolderRole, str] = field(default_factory=dict[FolderRole, str])
    """User overrides for role detection; take precedence over ``server.folder_roles``."""

    @property
    def endpoint(self) -> Endpoint:
        """The incoming endpoint for ``kind`` (validated at config load)."""
        ep = self.server.imap if self.kind == "imap" else self.server.pop3
        if ep is None:  # pragma: no cover - guarded by config validation
            raise ValueError(f"account {self.name!r} has no {self.kind} endpoint")
        return ep

    def effective_folder_roles(self) -> dict[FolderRole, str]:
        return {**self.server.folder_roles, **self.folder_roles}


@dataclass(frozen=True, slots=True)
class Identity:
    """A sender identity (used from M2 on; parsed and validated already)."""

    name: str
    addresses: tuple[str, ...]
    display_name: str = ""
    smtp_account: str | None = None
    """Account whose server profile (SMTP endpoint) and credentials send this identity's mail."""
    store_account: str | None = None
    """IMAP account that receives Drafts and Sent copies; ``None`` = no copies."""
    default: bool = False
    send: bool = False
    signature: str = ""


# --------------------------------------------------------------------------- folders


@dataclass(frozen=True, slots=True)
class FolderInfo:
    """A mailbox folder.

    ``name`` is the exact name on the wire (modified UTF-7, as the server lists it)
    and is what backends and message references use. ``display_name`` is the decoded
    human form to show to users/models.
    """

    name: str
    display_name: str
    delimiter: str | None
    flags: tuple[str, ...]
    role: FolderRole | None = None
    selectable: bool = True
    messages: int | None = None
    unseen: int | None = None


# --------------------------------------------------------------------------- messages

_REF_PREFIX = "m1."
_MAX_REF_LEN = 4096
_MAX_U32 = 2**32 - 1


def _has_control(s: str) -> bool:
    return any(ord(c) < 0x20 or ord(c) == 0x7F for c in s)


@dataclass(frozen=True, slots=True)
class MessageRef:
    """Stable identity of an IMAP message: (account, folder, UIDVALIDITY, UID).

    ``encode()`` produces an opaque, URL-safe id; ``MessageRef.decode(id)`` reverses
    it and raises :class:`InvalidRef` for anything malformed. The id is not a
    security token: callers must still check that the account is accessible.
    """

    account: str
    folder: str
    uidvalidity: int
    uid: int

    def __post_init__(self) -> None:
        _validate_ref_fields(self.account, self.folder, self.uidvalidity, self.uid)

    def encode(self) -> str:
        payload = json.dumps(
            [self.account, self.folder, self.uidvalidity, self.uid],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return _REF_PREFIX + base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

    @property
    def id(self) -> str:
        return self.encode()

    @classmethod
    def decode(cls, ref_id: str) -> MessageRef:
        if not isinstance(ref_id, str) or not ref_id.startswith(_REF_PREFIX):
            raise InvalidRef("not a message id (unknown format or version)")
        if len(ref_id) > _MAX_REF_LEN:
            raise InvalidRef("message id is too long")
        body = ref_id[len(_REF_PREFIX) :]
        if not body or any(c not in _B64URL for c in body):
            raise InvalidRef("message id contains invalid characters")
        try:
            raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
            data = json.loads(raw.decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError) as e:
            raise InvalidRef("message id is corrupted") from e
        if not (isinstance(data, list) and len(data) == 4):  # pyright: ignore[reportUnknownArgumentType]
            raise InvalidRef("message id has an unexpected structure")
        account, folder, uidvalidity, uid = data  # pyright: ignore[reportUnknownVariableType]
        if not (
            type(account) is str
            and type(folder) is str
            and type(uidvalidity) is int
            and type(uid) is int
        ):
            raise InvalidRef("message id has an unexpected structure")
        ref = cls(account, folder, uidvalidity, uid)
        if ref.encode() != ref_id:  # one canonical id per message
            raise InvalidRef("message id is not in canonical form")
        return ref


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def _validate_ref_fields(account: str, folder: str, uidvalidity: int, uid: int) -> None:
    if not account or len(account) > 200 or _has_control(account):
        raise InvalidRef("invalid account name in message reference")
    if not folder or len(folder) > 1000 or _has_control(folder):
        raise InvalidRef("invalid folder name in message reference")
    for label, value in (("UIDVALIDITY", uidvalidity), ("UID", uid)):
        if type(value) is not int or not 1 <= value <= _MAX_U32:
            raise InvalidRef(f"invalid {label} in message reference")


@dataclass(frozen=True, slots=True)
class Address:
    name: str
    email: str

    def __str__(self) -> str:
        return f"{self.name} <{self.email}>" if self.name else self.email


@dataclass(frozen=True, slots=True)
class MessageSummary:
    """Compact header view of a message (no body)."""

    ref: MessageRef
    date: datetime | None
    """``Date:`` header; falls back to ``received`` when missing or unparseable."""
    received: datetime | None
    """Server INTERNALDATE (arrival time)."""
    from_: tuple[Address, ...]
    to: tuple[Address, ...]
    cc: tuple[Address, ...]
    reply_to: tuple[Address, ...]
    subject: str
    flags: tuple[str, ...]
    size: int | None
    has_attachments: bool
    message_id: str | None
    in_reply_to: str | None
    references: tuple[str, ...]

    @property
    def id(self) -> str:
        return self.ref.encode()

    @property
    def seen(self) -> bool:
        return "\\Seen" in self.flags

    @property
    def flagged(self) -> bool:
        return "\\Flagged" in self.flags


@dataclass(frozen=True, slots=True)
class Attachment:
    """An attachment or inline part. ``part_id`` is the IMAP body section (e.g. ``2.1``)."""

    part_id: str
    filename: str | None
    content_type: str
    size: int
    inline: bool = False
    content_id: str | None = None


@dataclass(frozen=True, slots=True)
class TextSlice:
    """A window of a (possibly long) text. ``next_offset`` is ``None`` at the end."""

    text: str
    offset: int
    total_chars: int
    next_offset: int | None

    @property
    def truncated(self) -> bool:
        return self.next_offset is not None


@dataclass(frozen=True, slots=True)
class Message:
    """A full message: summary + text body window + attachment list.

    ``body_source`` tells where the text came from: ``plain``, ``html`` (converted),
    ``mixed`` (several inline text parts, some of them HTML), ``none`` or
    ``unparseable`` (MIME structure too deep or broken to parse; the headers still
    are). ``source_truncated`` is set when the raw message exceeded the fetch size
    cap and only its beginning was parsed. ``body_notes`` say what the body leaves
    out or shortens (server-generated, safe to show).
    """

    summary: MessageSummary
    body: TextSlice
    body_source: Literal["plain", "html", "mixed", "none", "unparseable"]
    attachments: tuple[Attachment, ...]
    source_truncated: bool = False
    body_notes: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.summary.id
