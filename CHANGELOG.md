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

## [0.0.1] - 2026-09-30

### Added

- Project skeleton, license (Apache-2.0), CI and release workflow.
- Design plan: `docs/plans/2026-09-30-design.md`.
- Placeholder release to register the package name on PyPI. Not functional yet.

[Unreleased]: https://github.com/arjoma/universal-email-mcp/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/arjoma/universal-email-mcp/releases/tag/v0.0.1
