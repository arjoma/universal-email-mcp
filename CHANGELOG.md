# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Local download links: `universal-email-mcp local` runs a listener on `127.0.0.1`
  (random port, or `[downloads] port`) that streams attachments from IMAP at
  `/a/<token>`. Tokens are HMAC-signed with a per-run key and expire (`link_ttl`,
  default 24 h), so links die with the process. The part is read in ranged chunks
  (own router call each, the account is not locked for the whole download) and
  transfer-decoded incrementally (base64, quoted-printable); `get_message` and
  `get_attachment` now show these links. Served as `attachment` with a sanitised
  file name, passive content types only, `nosniff`, sandbox CSP, `no-store`; `Host`
  checking against DNS rebinding; `GET`/`HEAD` only. Config: `[downloads]`
  (`enabled`, `port`, `link_ttl`, `max_download_bytes`). `get_message` also offers
  a "download .eml" link (`/m/<token>`, the raw message); `account_info` reports
  whether download links are on (and where) or off (and why).
- `save_draft` (permission `drafts`; offered only when an account allows it and the
  policy is not read-only): writes a plain-text draft into the account's Drafts
  folder (`\Draft`, `\Seen`; the new draft's id from `APPENDUID`) and never sends.
  New mail, reply, reply-all (`reply_to_id`, `reply_all`) and forward (`forward_id`;
  attaches the original's files through the verified part lookup, capped by
  `limits.max_attachment_bytes` per file and 10 MiB in total, never local files or
  URLs); `draft_id` replaces a draft: the new version is appended first, then the old
  one removed with `\Deleted` + `UID EXPUNGE` of that one UID, only if it is a
  `\Draft` in the Drafts folder (otherwise, or without UIDPLUS, it is left and the
  result says so). The sender is always a configured identity (explicit `from`, the
  address the original was sent to, an identity of the original's account, the
  default); threading headers come from the original with strict Message-ID syntax
  checks and at most 10 References; recipients are validated, line breaks and control
  characters in headers are refused, the policy's `max_recipients` applies. The result
  previews the draft and warns about a Reply-To to another domain, malformed
  addresses of the original and recipients never written to.
- `move_messages(to="archive")`: files into the account's archive folder (SPECIAL-USE
  `\Archive`, role detection or `folders.archive`). The scheme is detected from the
  archive's subfolders (flat, `YYYY`, `YYYY/MM`, `YYYY-MM`; an empty archive is flat)
  or fixed per account with `archive_scheme`; each message goes to the folder of its
  `Date` header (trusted only if plausible: 1990 or later and not after the arrival date + 1 day; else INTERNALDATE, else now), missing
  year/month folders are created once. No archive folder: `NO_ARCHIVE_FOLDER`.
- `move_messages(with_conversation=true)`: also moves the rest of each message's
  conversation in the same account (INBOX, Sent, the archive and the message's own
  folder; mail filed in other folders is reported as left there, Trash/Junk/Drafts
  never move). Only replies and ancestors of the message are followed - a hostile
  reply cannot pull unrelated mail in. The batch limit counts the whole set.
- `move_messages(dry_run=true)`: lists what would move and where, changes nothing
  (no folders are created either); the result lists the ids to pass to a confirmed
  move, which then searches nothing again.
- `get_attachment`: reads one attachment by the id `get_message` lists. Text-like
  files (text, CSV, JSON, XML, HTML, SVG) come back as fenced, defanged, paged text;
  other files as an embedded resource (base64 blob); files over
  `limits.max_attachment_bytes` (default 2 MiB) are refused with their size. Part
  numbers come from the server's `BODYSTRUCTURE`, so a malformed message (where
  Python's MIME parser and the server disagree) gives the right bytes or a refusal,
  never another part's bytes. Only `BODY.PEEK[n]` is used (no `\Seen`).
- `get_message` lists attachments with their server part id and the real decoded
  size, also when only the beginning of a large message was read (marked `~` as an
  estimate); file names lose path components, control and bidi characters.
- `account_info` returns a cheap overview per account (unread/message counts of INBOX,
  Drafts and Junk, number of folders); `overview=false` skips it.
- `MailService(download_links=...)`: hook for authenticated attachment download
  links (portal in remote mode, loopback listener locally; not built yet). With a
  provider `get_message` lists a link per attachment and `get_attachment` hands out
  a link for files over the cap.
- `universal-email-mcp probe`: log in read-only to an IMAP server (`--host`,
  `--server <preset>` or `--account <name>`) and report capabilities, namespace,
  folders with detected roles and counts, quota and the strategies the bridge will
  use. Password from `UEM_PASSWORD` or a prompt; no message content is shown.
- Local-mode configuration file (TOML; `--config`, `UEM_CONFIG` or the platform
  config dir) with accounts, identities, policy and limits; passwords only via
  environment variables or the OS keyring. Example: `docs/config.example.toml`.
- Server presets (`united-domains`, generic host names) and parsing of the
  operator settings `MAIL_SERVERS` and `LOGIN_DOMAINS`.
- Read-only IMAP backend: implicit TLS and STARTTLS with certificate verification,
  SSRF-safe connections, folder roles (SPECIAL-USE, English/German names,
  overrides), structured search with UTF-8, message summaries, full messages with
  HTML-to-text conversion and attachment lists, fencing of untrusted content.
- `universal-email-mcp local`: MCP server over stdio (works with Claude Desktop
  and Claude Code via `uvx universal-email-mcp local`) with five read-only tools:
  - `account_info`: accounts, permissions, server features, quota, identities,
    policy and limits.
  - `list_folders`: the top level first, each folder with its role and number of
    direct subfolders; `parent=` drills down (approximate names; ambiguity is
    returned as a choice), `query=` searches all levels, `depth=` (≤ 3) adds
    levels; message/unread counts for the folders shown (at most 50); similar
    names when nothing matches.
  - `find_messages`: time windows (`today`, `this_week`, `last_7_days` …) and
    from/to/subject/body/unread/flagged/attachment criteria as an exact
    server-side search, plus a free-text `query`.
  - `get_message`: fenced, paged body (never marks as read); `thread=true` shows
    the conversation across INBOX, Sent and other folders (archive and folders
    named like the participants first).
  - `find_contacts`: a quick overview of recent correspondents, or with `query`
    a deeper search; `sent_to` (yes / no / unknown) marks addresses you have
    written to in the last two years.
- One `query` parameter for `find_messages`, `list_folders` and `find_contacts`:
  with `*` or `?` a case-insensitive, umlaut-folded wildcard pattern starting at
  a word start (for folders: the folder's own name, or — with `/` — its path,
  where `*` also crosses levels); otherwise fuzzy matching that tolerates typos,
  umlaut spellings and name order.
- Every list result is bounded and its footer says how to narrow it or continue.
- Searches and listings span all accounts in parallel with a per-account
  time-out; failing accounts are reported with the partial result. Cursor
  paging with signed cursors; an account that fails between pages keeps its
  position and is retried.
- Results are Markdown tables (mail text escaped: no links, images, HTML or
  table breakage from crafted subjects) plus structured content with output
  schemas; errors carry a code and a hint.
- Folder names in tools may be approximate and hierarchical
  (`clients/hubr` → `Clients/Huber`); ambiguous names return the choices.
- New limit `max_headers_scanned` (headers read per account for fuzzy search
  and contact lookup).
- Development sandbox: `scripts/dev_mailbox.py` starts a throw-away local
  Dovecot with realistic and hostile mail and a matching config, for trying the
  server without a real mailbox.
- `local` and `probe --account` name the config file they loaded on stderr.
- Organize tools (accounts with the `organize` / `delete` permission):
  - `mark_messages`: read/unread and flagged, by message id.
  - `move_messages`: into another folder (exact name after case/umlaut
    normalisation, unique leaf name, path suffix or role; a typo or an ambiguous
    name changes nothing and returns the candidates). Uses `UID MOVE`; without MOVE it copies,
    flags and `UID EXPUNGE`s exactly the copied UIDs (UIDPLUS); with neither it
    refuses. A plain `EXPUNGE` is never issued. Moved messages get new ids
    (from `COPYUID`), returned in the result.
  - `create_folder`: a folder, nested levels, with correct hierarchy delimiter and
    modified UTF-7 encoding, subscribed after creation; the parent may be
    approximate. An existing folder is reported, not an error. Names are
    validated (no wildcards, quotes, control or invisible characters, `.`/`..`).
  - `delete_messages`: moves to the Trash folder (own tool, `destructiveHint`);
    mail already in Trash is left alone, there is no permanent deletion; an
    account without a recognisable Trash folder refuses.
  - Results are per message (ok / unchanged / failed with a code); stale
    (UIDVALIDITY), forged, unknown or not permitted ids fail individually.
    Tools that no account's permissions allow (or a `read_only` policy) are not
    registered; every call also checks the permission of each message's account.
    Nothing is changed in other users' or shared namespaces.
- New limit `max_batch_messages` (default 50): messages per mark/move/delete call;
  more are refused up front.

### Changed

- The conversation search (`get_message(thread=true)`) is limited by a time budget
  (half of `limits.account_timeout`) instead of 25 folders; later rounds look only in
  INBOX, Sent, the archive, the message's folder and folders that had hits.

### Security

- Message bodies are defanged, not only fenced: images become `[image: alt]`,
  links `text (hxxps[:]//…)`, HTML tags and reference-link definitions are
  neutralised; HTML mail no longer yields Markdown links.
- Table cells also defang autolinks without a word boundary (`_https://…`),
  e-mail addresses (`＠`) and scheme prefixes (`mailto:`, `xmpp:` …); error
  results carry details only as structured content.
- Variation selectors U+E0100–E01EF (and a few more invisible format characters)
  are stripped from mail text.

### Fixed

- A timed-out account no longer blocks the server until the read time-out, and
  retries against a stalling server share one connection attempt.
- Paging no longer skips messages deleted between pages; cursors stop retrying
  persistently failing accounts after three pages.
- `has_attachment` also finds attachments in signed, related and report mail
  (results marked approximate); listings show current flags; conversations are
  in arrival order; shared folders do not get special roles; deeply nested MIME
  is reported as unparseable.
- `get_message(thread=true)`: a message that copies another's Message-ID no
  longer displaces it from the conversation. Messages that share a Message-ID
  are all kept unless they are identical copies in one account (same size,
  sender, subject, Date, In-Reply-To and References); up to five per id are
  shown (the message asked about, else the earliest arrival, first). The search
  reads a fixed number of headers, shared fairly between the folders it searches
  (both ends of each folder's matches), and each round searches only new ids.
  Only messages linked through the message asked about and each Message-ID's
  first claimant (in any account) stay in the conversation — decided after the
  search, so a forgery cannot keep conversations it pulled in. When the limit
  cuts, later claimants go first, then the oldest messages, but the message
  asked about and what it replies to stay. Shared ids are marked
  (`⚠ same Message-ID`, `shared_message_id`) with short notes, also when a
  claimant is not shown. Conversation tables show the arrival time instead of
  the Date header.
- `get_message` shows every inline text part in order (Apple Mail text–image–text,
  hidden extra parts), each after a `──── part N (…) ────` line that mail text
  cannot imitate at a line start, HTML parts converted, report parts
  (`message/delivery-status` and similar, read from the original bytes with
  base64 / quoted-printable undone) as text; body source
  `mixed` when plain and HTML parts are combined. Text parts beyond the limits
  (100 parts, the HTML size budget) are listed as attachments, the attachment list
  is capped at 100, and notes say what was left out.

## [0.0.1] - 2026-09-30

### Added

- Project skeleton, license (Apache-2.0), CI and release workflow.
- Design plan: `docs/plans/2026-09-30-design.md`.
- Placeholder release to register the package name on PyPI. Not functional yet.

[Unreleased]: https://github.com/arjoma/universal-email-mcp/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/arjoma/universal-email-mcp/releases/tag/v0.0.1
