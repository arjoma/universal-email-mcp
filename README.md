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

## License

Apache License 2.0 — see [LICENSE](https://github.com/arjoma/universal-email-mcp/blob/main/LICENSE) and [NOTICE](https://github.com/arjoma/universal-email-mcp/blob/main/NOTICE).
Copyright 2026 ARJOMA FlexCo.
