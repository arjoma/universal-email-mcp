# Operator environment (remote mode)

`universal-email-mcp serve` is configured by environment variables - the
deployment-level settings of design section 11. The local TOML config
(`docs/config.example.toml`) describes one user's accounts; these variables describe
the service. Invalid values stop the server at startup with a message naming the
variable. Secrets are read from the environment (a secret manager mounts them as
variables) and never logged.

> **Status: preview (work package 3a).** Until OAuth (3c) and the per-user service
> (3e) exist, `serve` is a dev/test mode: it serves the accounts of a local TOML
> config (`--config` / `UEM_CONFIG`) and guards `/mcp` with one static bearer token.
> Do not expose it to users. The variables marked *(later)* are parsed and
> validated now but only take effect with the later work packages.

## Listening and security

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | TCP port (Cloud Run sets it). `--port` wins. |
| `UEM_DEV_TOKEN` | - | Static bearer token for `/mcp`, at least 32 characters. **Required** unless `--insecure-local`. Temporary (replaced by OAuth in 3c). |
| `PUBLIC_URL` | - | Externally visible origin, e.g. `https://mcp.example.com` (no path; `http` only for localhost). Its host is allowed as `Host`, its origin as `Origin`; HSTS is sent when it is `https`. *(OAuth issuer and metadata URLs later.)* |
| `ALLOWED_HOSTS` | - | More host names (comma separated, no ports) the server answers to, e.g. the platform's default URL host. Any other `Host` gets 421. `/health` and `/ready` are exempt (probes). **At least one of `PUBLIC_URL` / `ALLOWED_HOSTS` is required.** |
| `ALLOWED_ORIGINS` | - | More origins accepted in an `Origin` header (a request without `Origin` is fine). Any other gets 403. |
| `UEM_MAX_REQUEST_BYTES` | `4194304` | Largest request body; more gets 413. |
| `UEM_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. Logs are JSON lines on stdout. |

Command line: `serve [--config FILE] [--host ADDR] [--port N] [--insecure-local]`.
The default bind address is `0.0.0.0` (container); `--insecure-local` binds
`127.0.0.1` only, needs no token and leaves `/mcp` **open** - for trying things
out on your own machine, and nothing else.

## Mail servers and login domains *(portal: later)*

| Variable | Meaning |
|---|---|
| `MAIL_SERVERS` | Servers users may add: preset names or host names, comma separated (`united-domains,mail.example.com`). Empty = free entry with SSRF guards. |
| `LOGIN_DOMAINS` | `domain=server,...` - e-mail domains that may sign in to the portal and the server each uses. A bare `domain` uses the single `MAIL_SERVERS` entry. |
| `UEM_ALLOW_PRIVATE_NETWORKS` | `false` by default in remote mode (mail servers on private/loopback addresses are refused). In dev mode the TOML `[settings]` value is the default. |

## Limits and policy

Same meaning as `[limits]` and `[policy]` in the TOML config; a set variable
overrides the TOML value.

| Variable | Config key |
|---|---|
| `UEM_MAX_RESULTS`, `UEM_MAX_BODY_CHARS`, `UEM_MAX_MESSAGE_BYTES`, `UEM_MAX_ATTACHMENT_BYTES`, `UEM_MAX_ACCOUNTS_PER_CALL`, `UEM_MAX_HEADERS_SCANNED`, `UEM_MAX_BATCH_MESSAGES`, `UEM_MAX_SEND_BYTES` | `[limits] max_results`, ... |
| `UEM_ACCOUNT_TIMEOUT` (seconds) | `[limits] account_timeout` |
| `UEM_READ_ONLY` (`true`/`false`) | `[policy] read_only` |
| `UEM_SEND_POLICY` (`off`, `draft`, `confirm`, `confirm-external`, `on`) | `[policy] send` |
| `UEM_ALLOWED_RECIPIENT_DOMAINS`, `UEM_INTERNAL_DOMAINS` (comma separated) | `[policy] allowed_recipient_domains`, `internal_domains` |
| `UEM_MAX_RECIPIENTS`, `UEM_MAX_SENDS_PER_HOUR`, `UEM_MAX_SENDS_PER_DAY` | `[policy] max_recipients`, ... |

## Endpoints

| Path | Purpose |
|---|---|
| `/mcp` | MCP over Streamable HTTP, **stateless**: clients of protocol 2026-07-28 get the sessionless transport, older clients (<= 2025-11-25) the legacy transport without sessions (no back-channel, so no in-chat confirmation for them). Needs `Authorization: Bearer <UEM_DEV_TOKEN>`; otherwise 401 with `WWW-Authenticate: Bearer`. |
| `/health` | Liveness: `200 {"status":"ok"}`, no dependencies. |
| `/ready` | Readiness: `200` when all checks pass, else `503`; the body lists check names and booleans only. Today only the loaded config; the store joins in 3b. |

Every response carries `X-Request-Id`; the same id is on the JSON log lines of
that request. Non-MCP responses get `nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a restrictive CSP and `Cache-Control: no-store`.
No CORS headers are ever sent. Errors are generic JSON; stack traces only go to the
log.

## Container

```bash
podman build -t universal-email-mcp .        # or: docker build ...
podman run --rm -p 8080:8080 \
  -e UEM_DEV_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  -e PUBLIC_URL=http://localhost:8080 \
  -e UEM_CONFIG=/config/config.toml -v ./config.local.toml:/config/config.toml:ro \
  universal-email-mcp
```

The image is multi-stage (`uv` build, no dev dependencies), runs as an unprivileged
user (uid 10001), honours `PORT` and has a `/health` healthcheck (Docker image
format). `--build-arg EXTRAS=gcp` adds the Firestore client for later.
