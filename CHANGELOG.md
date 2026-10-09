# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Tools renamed and merged** (tool surface of the roadmap, WP 2-0):
  `find_messages` replaces `list_messages` and `search_messages` (a time window
  is just one criterion; the `fuzzy` flag is gone — use `query`), and
  `get_message(thread=true)` replaces `get_thread`.
- One `query` parameter for `find_messages`, `list_folders` and `find_contacts`:
  with `*` or `?` a case-insensitive, umlaut-folded wildcard pattern over whole
  words (`*` crosses folder levels), otherwise fuzzy matching. Structured
  criteria (`from`, `to`, `subject`, `body`, dates, flags) stay an exact
  server-side search.
- `list_folders` shows the top level first, each folder with its number of
  direct subfolders; `parent=` drills down (approximate names, ambiguity
  returned as a choice), `query=` searches all levels, `depth=` (≤ 3) adds levels.
  Paged with a cursor; message/unread counts only for the folders shown
  (at most 50); similar names when nothing matches. The output is a flat list
  (`level`, `subfolders`, `descendants`) instead of a nested tree.
- `find_contacts` without `query` is a quick overview (last 7 days, newest 150
  messages per account, most recent first); with `query` it searches deeper
  (180 days by default). No match → similar names and how to look further back.
  Paged with a cursor.
- Every list result's footer says how to narrow it or continue.

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
  and Claude Code via `uvx universal-email-mcp local`) with the read-only tools
  `account_info`, `list_folders` (roles and counts), `find_messages` (time
  windows like `today`, `this_week`, `last_7_days`, structured criteria, fuzzy
  matching that tolerates typos, umlaut spellings and name order),
  `get_message` (fenced, paged body; never marks as read; conversations across
  INBOX, Sent and other folders) and `find_contacts` (ranked by frequency and
  recency, marks addresses you have written to).
- Searches and listings span all accounts in parallel with a per-account
  time-out; failing accounts are reported with the partial result. Cursor
  paging with signed cursors.
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

## [0.0.1] - 2026-09-30

### Added

- Project skeleton, license (Apache-2.0), CI and release workflow.
- Design plan: `docs/plans/2026-09-30-design.md`.
- Placeholder release to register the package name on PyPI. Not functional yet.

[Unreleased]: https://github.com/arjoma/universal-email-mcp/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/arjoma/universal-email-mcp/releases/tag/v0.0.1
