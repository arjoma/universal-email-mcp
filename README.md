# universal-email-mcp

> **Status: under development — not usable yet.** Version 0.0.1 only reserves the
> package name. Follow the [design plan](docs/plans/2026-09-30-design.md).

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

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
Copyright 2026 ARJOMA FlexCo.
