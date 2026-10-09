# universal-email-mcp

> **Status: under development — not usable yet.** Version 0.0.1 only reserves the
> package name. Follow the [design plan](https://github.com/arjoma/universal-email-mcp/blob/main/docs/plans/2026-09-30-design.md).

A vendor-neutral [Model Context Protocol](https://modelcontextprotocol.io) server that
connects AI assistants (Claude, ChatGPT, any MCP client) to ordinary mailboxes over
**IMAP, POP3 and SMTP** — for everyone whose mail is not on Gmail: web hosters,
self-hosted servers, Exchange on-prem, and the like.

Planned highlights:

- **Several accounts per user** — search across all IMAP/POP3 mailboxes at once, send
  from the right identity automatically, per-account permissions (e.g. read-only).
- **Smart retrieval** — time windows, fuzzy matching of people, subjects and folders,
  contact lookup from your mail history.
- **Two modes** — a local single-user server (stdio) and a multi-user remote server
  with built-in OAuth 2.1 and a self-service portal.
- **Safe by design** — mail is treated as untrusted input; the server checks
  recipients (new or look-alike addresses) before anything is sent; no permanent
  deletion.
- **Operable** — encrypted credentials, pseudonymous audit logging, admin policy;
  reference deployment on Google Cloud Run.

## Try the probe

The first working piece is a read-only diagnostic that logs in to an IMAP server
and shows what it supports (no message content is displayed). From a checkout:

```bash
UEM_PASSWORD=... uv run universal-email-mcp probe --server mail.example.com --user alice@example.com
```

`--server` takes a preset name (e.g. `united-domains`) or a host name; `--starttls`
and `--port` select other connection modes, `--account NAME` uses an account from
the local config file (see [`docs/config.example.toml`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/config.example.toml)).

## Local mode (stdio)

`universal-email-mcp local` runs the MCP server over stdio for one user, with the
accounts from the config file ([`docs/config.example.toml`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/config.example.toml);
default `~/.config/universal-email-mcp/config.toml`, or `--config PATH` / `UEM_CONFIG`).
Passwords come from environment variables (`password_env`) or the OS keyring —
never from the file. The server is **read-only** so far, with six tools:

| Tool | What it does |
|---|---|
| `account_info` | accounts, permissions, server features, quota, identities, limits, plus a cheap overview (unread in INBOX, Drafts/Junk counts, number of folders) |
| `list_folders` | top level first with subfolder counts (`Clients ▸ 87`); `parent=` drills down, `query=` searches all levels, `depth=` (≤ 3) |
| `find_messages` | time window (`today`, `this_week` …), from/to/subject/body, unread/flagged/attachments — exact, server-side; plus `query` (wildcard or fuzzy) |
| `get_message` | headers, text body (paged, fenced as untrusted), attachments; `thread=true` for the conversation |
| `get_attachment` | one attachment by the id `get_message` lists: text-like files inline (fenced, paged), other files as an embedded resource up to `limits.max_attachment_bytes` (default 2 MiB); never marks mail as read |
| `find_contacts` | recent correspondents; `query=` finds a person (deeper search); `sent_to` (yes/no/unknown) marks people you wrote to |

`query` works the same everywhere: with `*` or `?` it is a case-insensitive,
umlaut-folded wildcard pattern that starts at a word start (`hub*` finds "Anna
Huber", `*gmbh`; inside a word: `*ub*`). For folders a pattern without `/`
matches the folder's own name at any level, one with `/` its path, where `*`
also crosses levels (`clients/m*`, `*/2025`). Anything else is matched fuzzily
(typos, `Müller`/`Mueller`, name order). Lists are bounded; each result's footer says how
to narrow it or fetch the next page (`cursor`).

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "email": {
      "command": "uvx",
      "args": ["universal-email-mcp", "local"],
      "env": { "UEM_WORK_PASSWORD": "…" }
    }
  }
}
```

Claude Code:

```bash
claude mcp add email -e UEM_WORK_PASSWORD=… -- uvx universal-email-mcp local
```

Add `"--config", "/path/to/config.toml"` to the arguments for a non-default config
file. Until the first functional release is on PyPI, run it from a checkout
instead: `"command": "uv", "args": ["run", "--directory", "/path/to/universal-email-mcp", "universal-email-mcp", "local"]`.

Results come as Markdown tables (mail text escaped, links defanged) plus
structured JSON; message bodies are fenced as untrusted content, so the assistant
can tell mail from instructions.

## Development

To try the server without a real mailbox, start the sandbox: a throw-away local
Dovecot (podman or docker) with a few weeks of realistic German/English mail and
hostile samples (prompt injection, crafted headers, broken encodings):

```bash
uv run scripts/dev_mailbox.py up      # prints the probe and `claude mcp add` commands
uv run scripts/dev_mailbox.py down
```

Contributor guidelines and checks: [AGENTS.md](https://github.com/arjoma/universal-email-mcp/blob/main/AGENTS.md).

## License

Apache License 2.0 — see [LICENSE](https://github.com/arjoma/universal-email-mcp/blob/main/LICENSE) and [NOTICE](https://github.com/arjoma/universal-email-mcp/blob/main/NOTICE).
Copyright 2026 ARJOMA FlexCo.
