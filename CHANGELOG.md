# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
- `get_message(thread=true)`: a message that copies another's Message-ID no longer
  displaces it from the conversation. Messages sharing a Message-ID are all shown
  (identical copies of one mail are merged; at most five per id, earliest
  arrival first), marked `⚠ same Message-ID` / `shared_message_id` with a note,
  and a later claimant's In-Reply-To/References are not followed.
- `get_message` shows every inline text part in order (Apple Mail text–image–text,
  hidden extra parts), each after a `──── part N (…) ────` line, HTML parts
  converted, bounce reports (`message/delivery-status`) as text; body source
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
