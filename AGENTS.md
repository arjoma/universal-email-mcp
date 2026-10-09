# AGENTS.md — working on universal-email-mcp

Guidance for AI coding agents (and humans) working in this repository.

## Project

Vendor-neutral MCP server for IMAP, POP3 and SMTP mailboxes. Public repo
(`arjoma/universal-email-mcp`), Apache-2.0, all development in public.
Design and scope: `docs/plans/2026-09-30-design.md`; what is left and in which
order: `docs/plans/2026-10-09-roadmap.md`; parked ideas: `TODO.md`.

- **Vendor neutral.** Nothing company- or deployment-specific belongs here (no
  instance names, hostnames of real deployments, GCP project ids, secrets).
  Deployment config lives in a separate private repository.
- Stack: Python ≥ 3.12, `uv`, MCP Python SDK 2.x (`mcp.server.mcpserver.MCPServer`),
  protocol 2026-07-28 (stateless HTTP) with legacy transport support.

## Language: English only

The project is **100 % English**: code, identifiers, comments, docstrings, tool
descriptions and server instructions, error messages, logs, docs, commit
messages, PRs, issues, changelog. Conversations with the maintainer may be in
German — that stays in the chat and never ends up in the repository.

- German appears only as **data** the code has to understand: folder names
  (`Gesendet`, `Entwürfe`), fuzzy-matching synonyms (`Kunden`), test corpora.
- **End-user UI** (portal, consent, message viewer — anything a person sees in the
  browser) is built **translatable from the start** (no hard-coded strings in
  templates), but ships English only for now. Later: the operator sets the
  deployment's default language, each user can switch. German will be the second
  language. Tool output for the AI client stays English.

## Security principle: no e-mail is trusted

Every byte that comes from a mailbox — bodies, subjects, names, addresses,
headers, folder names, attachment names and content — is attacker-controlled.
Code must treat it that way everywhere:

- Never let mail content act as instructions, configuration, paths, URLs to
  fetch, or HTML/Markdown to render unescaped (chat tables, portal, logs).
- Fence mail text as untrusted in tool results; escape it in Markdown and HTML;
  defang links and images that the server did not generate itself.
- Outbound actions (send, move, delete, create) are decided by the user and the
  server's policy, never by something a mail says.
- Tests for new features include hostile input (injection text, crafted
  subjects/headers, broken encodings, oversized parts).

## Development process

- **Larger pieces of work run in a subagent** (one focused agent per feature or
  subsystem), so the main session keeps the overview and the context stays small.
- **Larger features go through a pull request** from a feature branch, so `main`
  stays clean while the work is in progress; CI must pass before merging. Small
  changes (docs, process, fixes) may be pushed directly to `main`. A guideline,
  not a hard rule.
- Every user-visible change adds a line under `## [Unreleased]` in `CHANGELOG.md`
  ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, SemVer).
- **Review whenever code was written.** After every programming task (in
  particular one done by a subagent) and before it is merged, start a separate
  review subagent on the new code: bugs, logic errors, gaps and missing cases,
  security, robustness, tests, design, docs — and opportunities to simplify.
  Serious findings are fixed right away; less relevant ones are either fixed too
  or recorded in `TODO.md`, never silently dropped.
- **Regular cleanup.** From time to time compact `TODO.md` (drop done or obsolete
  items, merge duplicates) and tidy the code base with the `simplify` routine
  (reuse, simplification, efficiency) — as its own PR.
- Commits are authored as `Harald Schilly <info@arjoma.at>` (set in the repo's
  local git config). Merge PRs with `gh pr merge --rebase` (keeps the commit
  authors); a GitHub squash merge would re-author the commit with the GitHub
  account's e-mail.

## Code layout (`src/universal_email_mcp/`)

- `models.py` — frozen dataclasses (accounts, identities, folders, `MessageRef`
  with opaque ids, summaries, messages); `errors.py` — `MailError` + stable codes.
- `presets.py` — server presets, `MAIL_SERVERS` / `LOGIN_DOMAINS` parsing.
- `config.py` — local-mode TOML config and password lookup (env / keyring).
- `mail/net.py` — SSRF-safe connect (resolve once, check every IP, connect to it,
  TLS on the host name). `mail/imap.py` — synchronous read-only `ImapSession`
  (run it via `asyncio.to_thread`). `mail/mime.py` — parsing, HTML→text,
  `fence_untrusted`. `mail/folders.py` — role detection.
- `service/` — async core behind the tools: `router.py` (per-account sessions and
  locks, worker threads, deadlines, reconnect, parallel fan-out with partial
  results; backends per account kind), `mail.py` (`MailService`: the read
  operations), `index.py` (header cache per folder + UIDVALIDITY), `fuzzy.py`
  (rapidfuzz matching, umlaut variants, folder resolution), `query.py` (**the one
  `query` parameter of all list tools: wildcard pattern or fuzzy**),
  `folder_list.py` (folder tree, the one folder-name resolver, folder search),
  `cursor.py` (signed paging cursors), `paging.py` (keyset paging over accounts,
  retry cursors), `trust.py` (per-account "sent to" sets — basis of the send-time
  recipient check), `timewindow.py` (`today`, `this_week` …).
- `server/` — MCP layer: `app.py` (`build_server()`: tools, instructions, error
  results), `schemas.py` (output schemas), `render.py` (**`escape_cell()` — the one
  place that makes mail text safe in Markdown**), `local.py` (stdio mode).
- `probe.py`, `cli.py` — command line (`probe`, `local`).

## Checks (same as CI)

```bash
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts
uv run basedpyright
uv run pytest -q
```

CI (`.github/workflows/ci.yml`) runs these on Python 3.12 and 3.14 plus
`pip-audit` of the locked dependencies.

Integration tests (`tests/integration`, marker `integration`) run against a real
Dovecot server: locally they start it with rootless **podman** (or a working
docker) and skip if neither is available; CI provides it as a service container
and sets `UEM_TEST_REQUIRE_INTEGRATION=1` so they cannot silently skip there.
Protocol behaviour is tested against the server, not mocks.

## Local testing with a real mailbox

Personal test setup lives in the checkout but is gitignored (`.env`, `*.local.toml`):

```bash
cp docs/config.example.toml config.local.toml   # trim to your accounts
cp .env.example .env                            # sets UEM_CONFIG=config.local.toml
uv run keyring set universal-email-mcp Work     # password into the OS keyring
uv run --env-file .env universal-email-mcp probe --account Work
claude mcp add email -- uv run --directory "$PWD" --env-file .env universal-email-mcp local
```

Prefer the keyring over `password_env` in `.env`: coding agents working in the
repository can read `.env`. Start with `permissions = ["read"]`; write
operations are tried on the sandbox first, not on a real mailbox.

**Sandbox mailbox** — `uv run scripts/dev_mailbox.py up|status|reset|down` runs
the integration-test Dovecot image as container `uem-sandbox` on 127.0.0.1:10993
(TLS) / 10143 (STARTTLS), seeds two accounts (`Sandbox`, `Sandbox-Private`) with
realistic and hostile mail plus a large folder tree, and writes the gitignored
`sandbox.local.toml` and `.env.sandbox` (throw-away password). It prints the
`probe` and `claude mcp add email-sandbox …` commands with an explicit `--config`
(`uv run --env-file` does not override an exported `UEM_CONFIG`). Mail is on a tmpfs: a
stopped container comes back freshly seeded. Seed dates are relative to the
seeding time, so on a long-running container `today` runs dry: `reset` seeds
afresh (also after an interrupted seed). Bump `CORPUS_VERSION` in
`tests/sandbox.py` when the corpus changes; `up` then recreates the container.
The script only removes a container carrying its label and never overwrites a
config or env file it did not generate. Corpus and config live in
`tests/sandbox.py` (hand-written attack samples in `tests/data/sandbox/*.eml`),
container helpers in `tests/dovecot.py` (shared with the integration tests);
hostile mails carry `X-UEM-Sandbox: hostile <kind>`.

## Releases

1. Move the `[Unreleased]` entries in `CHANGELOG.md` to a new `## [X.Y.Z] - YYYY-MM-DD`
   section and update the compare links.
2. Set `version` in `pyproject.toml` (`uv version X.Y.Z`), commit via PR.
3. Tag `vX.Y.Z` on a commit that is on `main` (enforced) and push the tag. `.github/workflows/release.yml` runs
   CI, checks that tag, `pyproject.toml` and `CHANGELOG.md` agree, builds, publishes
   to PyPI via Trusted Publishing (GitHub environment `pypi`, no API tokens) and
   creates the GitHub release with the changelog section as notes.
