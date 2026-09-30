# AGENTS.md — working on universal-email-mcp

Guidance for AI coding agents (and humans) working in this repository.

## Project

Vendor-neutral MCP server for IMAP, POP3 and SMTP mailboxes. Public repo
(`arjoma/universal-email-mcp`), Apache-2.0, all development in public.
Design and scope: `docs/plans/2026-09-30-design.md`; parked ideas: `TODO.md`.

- **Vendor neutral.** Nothing company- or deployment-specific belongs here (no
  instance names, hostnames of real deployments, GCP project ids, secrets).
  Deployment config lives in a separate private repository.
- Stack: Python ≥ 3.12, `uv`, MCP Python SDK 2.x (`mcp.server.mcpserver.MCPServer`),
  protocol 2026-07-28 (stateless HTTP) with legacy transport support.

## Development process

- **Larger pieces of work run in a subagent** (one focused agent per feature or
  subsystem), so the main session keeps the overview and the context stays small.
- **New features go through a pull request** from a feature branch; CI must pass
  before merging. No direct feature commits to `main`.
- Every user-visible change adds a line under `## [Unreleased]` in `CHANGELOG.md`
  ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, SemVer).
- **Review after every larger piece of work.** Once the work is done and CI is
  green, start a separate review subagent on the recent commits (a second pair of
  eyes on all aspects: correctness, security, robustness, tests, design, docs).
  Act on the high-priority findings right away; lower-priority ones are either
  skipped or noted in `TODO.md`.
- **Regular cleanup.** From time to time compact `TODO.md` (drop done or obsolete
  items, merge duplicates) and tidy the code base with the `simplify` routine
  (reuse, simplification, efficiency) — as its own PR.
- Commits are authored as `Harald Schilly <info@arjoma.at>` (set in the repo's
  local git config).

## Checks (same as CI)

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run basedpyright
uv run pytest -q
```

CI (`.github/workflows/ci.yml`) runs these on Python 3.12 and 3.14 plus
`pip-audit` of the locked dependencies.

## Releases

1. Move the `[Unreleased]` entries in `CHANGELOG.md` to a new `## [X.Y.Z] - YYYY-MM-DD`
   section and update the compare links.
2. Set `version` in `pyproject.toml` (`uv version X.Y.Z`), commit via PR.
3. Tag `vX.Y.Z` on `main` and push the tag. `.github/workflows/release.yml` runs
   CI, checks that tag, `pyproject.toml` and `CHANGELOG.md` agree, builds, publishes
   to PyPI via Trusted Publishing (GitHub environment `pypi`, no API tokens) and
   creates the GitHub release with the changelog section as notes.
