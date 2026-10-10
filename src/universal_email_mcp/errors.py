"""Error hierarchy with stable machine-readable codes.

Every error the mail layer raises on purpose is a :class:`MailError` with a stable
``code`` (for tools and logs) and a human ``hint`` (what the user can do about it).
Messages never contain passwords; callers should still avoid putting mail content
into them.
"""

from __future__ import annotations

from typing import ClassVar


class MailError(Exception):
    """Base class. ``code`` is stable API; ``str(err)`` and ``hint`` are for humans."""

    code: ClassVar[str] = "MAIL_ERROR"
    default_hint: ClassVar[str] = ""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint if hint is not None else self.default_hint

    def to_dict(self) -> dict[str, str | int]:
        """Serialisable form for tool error results: ``{"code", "message", "hint"}``."""
        return {"code": self.code, "message": self.message, "hint": self.hint}


class ConfigError(MailError):
    code = "CONFIG_INVALID"
    default_hint = "Fix the configuration file and try again."


class AuthFailed(MailError):
    code = "AUTH_FAILED"
    default_hint = "Check the username and password (an app password may be required)."


class ReauthRequired(AuthFailed):
    """Remote mode: the stored mail password stopped working. The user has to enter it
    again in the portal; until then the server does not try to log in again."""

    code = "REAUTH_REQUIRED"
    default_hint = "Ask the user to enter the mailbox password again in the portal."


class Busy(MailError):
    """Remote mode: a per-user or per-instance cap is reached (connections, parallel calls)."""

    code = "BUSY"
    default_hint = "Too many requests at once. Wait a few seconds and try again."


class ServerUnreachable(MailError):
    code = "SERVER_UNREACHABLE"
    default_hint = "Check host name, port and network connectivity; the server may be down."


class TlsError(MailError):
    code = "TLS_ERROR"
    default_hint = (
        "The TLS handshake or certificate check failed. Check host name and port "
        "(993 = implicit TLS, 143 = STARTTLS) and the server certificate."
    )


class AddressNotAllowed(MailError):
    code = "ADDRESS_NOT_ALLOWED"
    default_hint = (
        "The server resolves to an address that is not allowed "
        "(private, loopback, link-local or otherwise non-public)."
    )


class ProtocolError(MailError):
    code = "SERVER_ERROR"
    default_hint = "The mail server rejected the request or answered unexpectedly."


class UnsupportedByServer(MailError):
    code = "UNSUPPORTED_BY_SERVER"
    default_hint = "The mail server lacks a capability this operation needs."


class UidValidityChanged(MailError):
    code = "UIDVALIDITY_CHANGED"
    default_hint = (
        "The folder was rebuilt on the server, so old message references are void. "
        "Search or list the messages again."
    )


class FolderNotFound(MailError):
    code = "FOLDER_NOT_FOUND"
    default_hint = "List the folders to see which exist."


class MessageNotFound(MailError):
    code = "MESSAGE_NOT_FOUND"
    default_hint = "The message may have been moved or deleted. Search again."


class TooLarge(MailError):
    code = "TOO_LARGE"
    default_hint = "The result exceeds a configured size limit."


class InvalidRef(MailError):
    code = "INVALID_REF"
    default_hint = "Use a message id exactly as returned by a list or search result."


WRONG_MAILBOX = (
    "this message id belongs to a different mailbox than the account that has this name now "
    "(the account was removed and added again, or points to another login); "
    "search again to get current ids"
)
"""Why an id whose account key does not match is refused (message ids carry the key of the
mailbox they were issued for, ``models.account_key``)."""


class NotPermitted(MailError):
    code = "NOT_PERMITTED"
    default_hint = "The account's permissions or the policy do not allow this."


class CredentialMissing(MailError):
    code = "CREDENTIAL_MISSING"
    default_hint = (
        "Set the environment variable named in the config (password_env) or store "
        "the password in the OS keyring (service 'universal-email-mcp', key = account name)."
    )


class InvalidCursor(MailError):
    code = "INVALID_CURSOR"
    default_hint = (
        "Pass the cursor exactly as returned, together with the same arguments; "
        "or start again without a cursor."
    )


class StaleCursor(MailError):
    code = "STALE_CURSOR"
    default_hint = "The mailbox changed in a way that voids the cursor. Start again without it."


class AccountTimeout(MailError):
    code = "TIMEOUT"
    default_hint = "The mail server did not answer in time. Try again, or narrow the request."


class NotSupportedYet(MailError):
    code = "NOT_SUPPORTED_YET"
    default_hint = "This account type or operation is not implemented yet."


class AmbiguousFolder(MailError):
    code = "AMBIGUOUS_FOLDER"
    default_hint = "Several folders match. Repeat the call with one of the listed folder names."

    def __init__(self, message: str, choices: list[str], *, hint: str | None = None) -> None:
        super().__init__(message, hint=hint)
        self.choices = choices

    def to_dict(self) -> dict[str, str | int]:
        d = super().to_dict()
        d["choices"] = "; ".join(self.choices)
        return d


class InvalidArgument(MailError):
    code = "INVALID_ARGUMENT"
    default_hint = "Check the tool arguments."


class AttachmentNotFound(MailError):
    code = "ATTACHMENT_NOT_FOUND"
    default_hint = "Use an attachment id exactly as listed by get_message for this message."


class InvalidFolderName(MailError):
    code = "INVALID_FOLDER_NAME"
    default_hint = "Use plain names without * % \" \\ or control characters; '/' separates levels."


class NoArchiveFolder(MailError):
    code = "NO_ARCHIVE_FOLDER"
    default_hint = (
        "The account has no recognisable Archive folder (see account_info). Set "
        "folders.archive in the account configuration, or pass the destination folder "
        "by name instead of 'archive'. Nothing was changed."
    )


class NoTrashFolder(MailError):
    code = "NO_TRASH_FOLDER"
    default_hint = (
        "The account has no recognisable Trash folder (see account_info). Set "
        "folders.trash in the account configuration. Permanent deletion is not offered."
    )


class NoDraftsFolder(MailError):
    code = "NO_DRAFTS_FOLDER"
    default_hint = (
        "The account has no recognisable Drafts folder (see account_info). Set "
        "folders.drafts in the account configuration."
    )


class RecipientsRefused(MailError):
    code = "RECIPIENT_REFUSED"
    default_hint = (
        "The mail server refused one or more recipients; nothing was sent. Check the "
        "addresses (typos?) and correct the draft."
    )

    def __init__(
        self, message: str, refused: dict[str, str] | None = None, *, hint: str | None = None
    ) -> None:
        super().__init__(message, hint=hint)
        self.refused = refused or {}


class RateLimited(MailError):
    code = "RATE_LIMITED"
    default_hint = "The send limit of the policy is reached. Wait, or ask the user to raise it."

    def __init__(
        self, message: str, *, hint: str | None = None, retry_after: int | None = None
    ) -> None:
        super().__init__(message, hint=hint)
        self.retry_after = retry_after
        """Seconds to wait before trying again, when known."""

    def to_dict(self) -> dict[str, str | int]:
        data = super().to_dict()
        if self.retry_after is not None:
            data["retry_after"] = self.retry_after
        return data


class SendOutcomeUnknown(MailError):
    code = "SEND_OUTCOME_UNKNOWN"
    default_hint = (
        "The connection broke after the message was handed to the server: it may or may "
        "not have been sent. Do NOT send it again; check the Sent folder and ask the "
        "user. The draft was kept."
    )


class AlreadySent(MailError):
    code = "ALREADY_SENT"
    default_hint = "This message was sent earlier in this session; sending it again is refused."
