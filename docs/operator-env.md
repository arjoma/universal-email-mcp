# Operator environment (remote mode)

`universal-email-mcp serve` is configured by environment variables - the
deployment-level settings of design section 11. The local TOML config
(`docs/config.example.toml`) describes one user's accounts; these variables describe
the service. Invalid values stop the server at startup with a message naming the
variable. Secrets are read from the environment (a secret manager mounts them as
variables) and never logged.

> **Status: preview.** `serve` has two modes. **OAuth mode** (work package 3c) is the
> default: set `STORE_BACKEND`, `PUBLIC_URL` and `LOGIN_DOMAINS`; users sign in, clients
> are authorized, and `/mcp` needs an access token (see [oauth.md](oauth.md)). Until the
> per-user service (3e) `/mcp` offers only `account_info`; the mail tools, the limits and
> the policy below apply per user from 3e on. The temporary **dev mode** (`UEM_DEV_TOKEN`
> or `--insecure-local`) serves the accounts of a local TOML config (`--config` /
> `UEM_CONFIG`) behind one static bearer token; do not expose it to users. The two modes
> are exclusive (setting both is an error).

## Listening and security

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | TCP port (Cloud Run sets it). `--port` wins. |
| `UEM_DEV_TOKEN` | - | Dev mode only: static bearer token for `/mcp`, at least 32 characters. Without it (and without `--insecure-local`) the server runs in OAuth mode and needs `STORE_BACKEND`. |
| `PUBLIC_URL` | - | Externally visible origin, e.g. `https://mcp.example.com` (no path; `http` only for localhost). Its host is allowed as `Host`, its origin as `Origin`; HSTS is sent when it is `https`. **Required in OAuth mode:** it is the OAuth issuer (`iss`) and the base of the metadata URLs and of the resource (`PUBLIC_URL/mcp`). |
| `ALLOWED_HOSTS` | - | More host names (comma separated, no ports) the server answers to, e.g. the platform's default URL host. Any other `Host` gets 421. `/health` and `/ready` are exempt (probes). **At least one of `PUBLIC_URL` / `ALLOWED_HOSTS` is required.** |
| `ALLOWED_ORIGINS` | - | More origins accepted in an `Origin` header (a request without `Origin` is fine). Any other gets 403. |
| `UEM_MAX_REQUEST_BYTES` | `4194304` | Largest request body; more gets 413. |
| `UEM_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. Logs are JSON lines on stdout. |

Command line: `serve [--config FILE] [--host ADDR] [--port N] [--insecure-local]`.
The default bind address is `0.0.0.0` (container); `--insecure-local` binds
`127.0.0.1` only, needs no token and leaves `/mcp` **open** - for trying things
out on your own machine, and nothing else.

## Mail servers and login domains

| Variable | Meaning |
|---|---|
| `MAIL_SERVERS` | Servers users may add in the portal: preset names or host names, comma separated (`united-domains,mail.example.com`). One entry = fixed, several = a list to choose from, **empty = free entry**: users type a host name (public addresses only, ports 993/995/465/587, verified TLS - see [portal.md](portal.md)). To forbid free entry, list at least one server. |
| `LOGIN_DOMAINS` | `domain=server,...` - e-mail domains that may sign in (OAuth mode: **required**) and the server each uses for the login check. A bare `domain` uses the single `MAIL_SERVERS` entry. |
| `UEM_ALLOW_PRIVATE_NETWORKS` | `false` by default in remote mode (mail servers on private/loopback addresses are refused). In dev mode the TOML `[settings]` value is the default. |

## Store and keys (OAuth mode)

| Variable | Default | Meaning |
|---|---|---|
| `STORE_BACKEND` | - | `memory` (development; state and generated keys are lost on restart) or `firestore` (`pip install universal-email-mcp[gcp]`). **Required** in OAuth mode. |
| `STORE_KEYS` / `STORE_KEYS_FILE` | - | Key ring `k1=<base64 32 bytes>[,k2=...]` (or a mounted file). Required with `firestore`; `memory` generates one when unset. See [stored-data.md](stored-data.md). |
| `STORE_ACTIVE_KEY` | highest | Key for new blobs. |
| `PSEUDONYM_KEY` / `PSEUDONYM_KEY_FILE` | - | Base64, at least 32 bytes: the secret that turns a mail address into the pseudonymous user id (`u_...`) used in the store and logs. Required with `firestore`. **Never change it** (users are keyed by it). |
| `FIRESTORE_PROJECT`, `FIRESTORE_DATABASE`, `FIRESTORE_PREFIX` | ADC project, default DB, - | Firestore location; the prefix lets several instances share a project. |

`/ready` reports a `store` check (one read round trip).

## OAuth and sign-in (OAuth mode)

| Variable | Default | Meaning |
|---|---|---|
| `UEM_ACCESS_TOKEN_TTL` | `3600` | Access token lifetime in seconds. |
| `UEM_REFRESH_TOKEN_TTL` | `2592000` (30 days) | Refresh token, sliding (each refresh extends it). `0` = never expires on its own - weaker, a leaked token then lives until revoked. |
| `UEM_SESSION_MAX_AGE` | `7776000` (90 days) | Absolute lifetime of a connected client, however often it refreshes. `0` = unlimited. |
| `UEM_PORTAL_IDLE_TIMEOUT` / `UEM_PORTAL_SESSION_MAX` | `1800` / `43200` | Browser sign-in session: idle timeout and absolute maximum, seconds. |
| `UEM_REAUTH_WINDOW` | `300` | Seconds after typing the password again during which sensitive portal actions and granting `send` need no new entry (see [portal.md](portal.md)). Signing in counts. |
| `UEM_MAX_ACCOUNTS_PER_USER` / `UEM_MAX_IDENTITIES_PER_USER` | `10` / `10` | How many mail accounts and sender identities one user may have. |
| `UEM_DCR` | `true` | Offer `/register` (Dynamic Client Registration) as fallback to Client ID Metadata Documents. |
| `UEM_DCR_REDIRECT_HOSTS` | any | Comma separated hosts a dynamically registered `https` redirect URI may use (loopback is always allowed). |
| `UEM_TRUSTED_PROXY_HOPS` | `0` | Reverse proxies in front (Cloud Run: `1`). Decides which `X-Forwarded-For` entry is the client address for rate limits; `0` uses the socket peer. Set it wrong and rate limits count the proxy, or can be dodged by a forged header. |
| `UEM_DEFAULT_LANGUAGE` | `en` | Default language of the sign-in and consent pages (needs a catalog; falls back to English). |

The scopes clients can obtain follow the policy: with `UEM_READ_ONLY=true` only
`mail.read`, `mail.send` is not offered when `UEM_SEND_POLICY=off`.

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
| `/mcp` | MCP over Streamable HTTP, **stateless**: clients of protocol 2026-07-28 get the sessionless transport, older clients (<= 2025-11-25) the legacy transport without sessions (no back-channel, so no in-chat confirmation for them). OAuth mode: needs an access token issued for this resource; otherwise 401 with `WWW-Authenticate: Bearer resource_metadata="..."`. Dev mode: `Authorization: Bearer <UEM_DEV_TOKEN>`. |
| `/.well-known/oauth-*`, `/authorize`, `/token`, `/revoke`, `/register`, `/portal/assets/*` | OAuth mode: the authorization server, see [oauth.md](oauth.md). |
| `/portal`, `/portal/*` | OAuth mode: the user portal (accounts, identities, connected applications), see [portal.md](portal.md). |
| `/health` | Liveness: `200 {"status":"ok"}`, no dependencies. |
| `/ready` | Readiness: `200` when all checks pass, else `503`; the body lists check names and booleans only. The loaded config and, in OAuth mode, the store. |

Every response carries `X-Request-Id`; the same id is on the JSON log lines of
that request. Non-MCP responses get `nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, a restrictive CSP and `Cache-Control: no-store`.
CORS is off in dev mode. In OAuth mode only the cookie-less endpoints (`/.well-known/*`,
`/register`, `/token`, `/revoke`, `/mcp`) answer preflights and send
`Access-Control-Allow-Origin: *` (never credentials) so browser-based MCP clients can connect;
the portal and `/authorize` never send CORS headers and keep the strict `Origin` check. Errors are generic JSON; stack traces only go to the
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
