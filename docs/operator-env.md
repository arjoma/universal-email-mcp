# Operator environment (remote mode)

`universal-email-mcp serve` is configured by environment variables - the
deployment-level settings of design section 11. The local TOML config
(`docs/config.example.toml`) describes one user's accounts; these variables describe
the service. Invalid values stop the server at startup with a message naming the
variable. Secrets are read from the environment (a secret manager mounts them as
variables) and never logged.

> **Status: preview.** `serve` has two modes. **OAuth mode** (work package 3c) is the
> default: set `STORE_BACKEND`, `PUBLIC_URL` and `LOGIN_DOMAINS`; users sign in, clients
> are authorized, and `/mcp` needs an access token (see [oauth.md](oauth.md)); it serves each
> user's own accounts (per-user service, 3e) with the limits and policy below. The temporary **dev mode** (`UEM_DEV_TOKEN`
> or `--insecure-local`) serves the accounts of a local TOML config (`--config` /
> `UEM_CONFIG`) behind one static bearer token; do not expose it to users. The two modes
> are exclusive (setting both is an error).

## Listening and security

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | TCP port (Cloud Run sets it). `--port` wins. |
| `UEM_DEV_TOKEN` | - | Dev mode only: static bearer token for `/mcp`, at least 32 characters. Without it (and without `--insecure-local`) the server runs in OAuth mode and needs `STORE_BACKEND`. |
| `PUBLIC_URL` | - | Externally visible origin, e.g. `https://mcp.example.com` (no path; `http` only for localhost). Its host is allowed as `Host`, its origin as `Origin`; HSTS is sent when it is `https`. **Required in OAuth mode:** it is the OAuth issuer (`iss`) and the base of the metadata URLs and of the resource (`PUBLIC_URL/mcp`). |
| `CONTENT_ORIGIN` | - | Optional, **recommended**: a second origin with its own host name (e.g. `https://mcp-content.example.com`, same scheme as `PUBLIC_URL`) that serves the sandboxed HTML of mail for the portal's message viewer, so that mail HTML never shares an origin with the portal. Its host is added to the allowed hosts; route the host name to the same service (only `/c/*` is used there). The addresses are signed with a key derived from `PSEUDONYM_KEY` - with several instances all need the same key. See [portal.md](portal.md). |
| `ALLOWED_HOSTS` | - | More host names (comma separated, no ports) the server answers to, e.g. the platform's default URL host. Any other `Host` gets 421. `/health` and `/ready` are exempt (probes). **At least one of `PUBLIC_URL` / `ALLOWED_HOSTS` is required.** |
| `ALLOWED_ORIGINS` | - | More origins accepted in an `Origin` header (a request without `Origin` is fine). Any other gets 403. |
| `UEM_MAX_REQUEST_BYTES` | `4194304` | Largest request body; more gets 413. |
| `UEM_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`. Logs are JSON lines on stdout. |
| `AUDIT_LOG_CLIENT_IP` | `false` | Audit events of sign-ins and rate limits get `ip`: a keyed pseudonym of the client's network (IPv4 /24, IPv6 /48), never the address. Audit events themselves are always on (JSON lines on stdout, see [audit.md](audit.md)); the pseudonym key is `PSEUDONYM_KEY`, the `instance` field is Cloud Run's `K_REVISION`. |

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
| `UEM_APPROVAL_TTL` | `600` | Seconds a send waits for the user's approval in the portal (see `SEND_FALLBACK` below). |
| `UEM_REAUTH_WINDOW` | `300` | Seconds after typing the password again during which sensitive portal actions and granting `send` need no new entry (see [portal.md](portal.md)). Signing in counts. |
| `UEM_MAX_DOWNLOAD_BYTES` | `104857600` (100 MiB) | Largest attachment or `.eml` the portal viewer streams (decoded size); bigger ones answer 413. |
| `UEM_MAX_ACCOUNTS_PER_USER` / `UEM_MAX_IDENTITIES_PER_USER` | `10` / `10` | How many mail accounts and sender identities one user may have. |
| `UEM_DCR` | `true` | Offer `/register` (Dynamic Client Registration) as fallback to Client ID Metadata Documents. |
| `UEM_DCR_REDIRECT_HOSTS` | any | Comma separated hosts a dynamically registered `https` redirect URI may use (loopback is always allowed). |
| `UEM_TRUSTED_PROXY_HOPS` | `0` | Reverse proxies in front (Cloud Run: `1`). Decides which `X-Forwarded-For` entry is the client address for rate limits; `0` uses the socket peer. Set it wrong and rate limits count the proxy, or can be dodged by a forged header. |
| `UEM_DEFAULT_LANGUAGE` | `en` | Default language of the sign-in and consent pages (needs a catalog; falls back to English). |

The scopes clients can obtain follow the policy: with `UEM_READ_ONLY=true` only
`mail.read`, `mail.send` is not offered when `UEM_SEND_POLICY=off`.

## Limits and policy

Same meaning as `[limits]` and `[policy]` in the TOML config; a set variable
overrides the TOML value. In OAuth mode they apply to every user's service; a grant can
only narrow them (the effective permissions are the intersection with `UEM_READ_ONLY`).
`send_message` is offered when the grant, the identity and the policy all allow it (see
[oauth.md](oauth.md)); the send settings apply per user: `UEM_MAX_SENDS_PER_HOUR` / `_DAY` are
counted per user in the store (shared by all instances), not per SMTP account.

| Variable | Config key |
|---|---|
| `UEM_MAX_RESULTS`, `UEM_MAX_BODY_CHARS`, `UEM_MAX_MESSAGE_BYTES`, `UEM_MAX_ATTACHMENT_BYTES`, `UEM_MAX_ACCOUNTS_PER_CALL`, `UEM_MAX_HEADERS_SCANNED`, `UEM_MAX_BATCH_MESSAGES`, `UEM_MAX_SEND_BYTES` | `[limits] max_results`, ... |
| `UEM_ACCOUNT_TIMEOUT` (seconds) | `[limits] account_timeout` |
| `UEM_READ_ONLY` (`true`/`false`) | `[policy] read_only` |
| `UEM_SEND_POLICY` (`off`, `draft`, `confirm`, `confirm-external`, `on`) | `[policy] send` |
| `UEM_ALLOWED_RECIPIENT_DOMAINS`, `UEM_INTERNAL_DOMAINS` (comma separated) | `[policy] allowed_recipient_domains`, `internal_domains` |
| `UEM_MAX_RECIPIENTS`, `UEM_MAX_SENDS_PER_HOUR`, `UEM_MAX_SENDS_PER_DAY` | `[policy] max_recipients`, ... |

### Sending without a question: `SEND_FALLBACK`

When the policy wants the user's confirmation but the client cannot ask (legacy protocol over
stateless HTTP, or a client without form elicitation), `SEND_FALLBACK` decides. Nothing is ever
sent for a look-alike without a human; under `confirm` / `confirm-external` nor to a new address (with `UEM_SEND_POLICY=on` a new address needs no question).

| Value | Effect |
|---|---|
| `portal` (**default in OAuth mode**) | The message stays a draft, a pending approval is created and the tool result carries a link to `PUBLIC_URL/portal/approvals/...`; nothing is sent until the signed-in user approves it there. |
| `send-unless-flagged` | Sends directly unless the recipient check flags something (an address never written to, or a look-alike): flagged sends go to the portal as above. Recipients that are internal or written to before go out without a question - an explicit trade for deployments whose clients cannot ask (the design plan names this the default; the implementation defaults to the safer `portal`). |
| `draft` | The message stays in Drafts; the user sends it from their mail client (the only value in dev mode, which has no portal). |

There is deliberately no value that sends unconfirmed in every case. `UEM_APPROVAL_TTL`
(seconds, default `600`) is how long an approval waits in the portal before it shows as expired.

## Per-user service: connections and calls (OAuth mode)

Caps of the per-instance pool of mail connections and per-user services (design section 4,
"Connections"). Each connected client (grant) has its own set of connections, at most one per
account; hosters often cap connections per mailbox, so keep the idle time short.

| Variable | Default | Meaning |
|---|---|---|
| `UEM_MAX_CONNECTIONS` | `200` | Open mail-server connections in this process. When reached, the longest idle connection of anybody is closed; if none is idle the call fails with `BUSY`. |
| `UEM_MAX_CONNECTIONS_PER_USER` | `8` | The same per user (all of the user's clients together). |
| `UEM_MAX_CONCURRENT_CALLS_PER_USER` | `8` | Tool calls of one user running at once; more are refused with `BUSY` (clients can retry). Calls to one account are serialised anyway. |
| `UEM_CONNECTION_IDLE_TTL` | `120` | Seconds an unused connection stays open (swept every 30 s). |
| `UEM_USER_IDLE_TTL` | `900` | Seconds an unused per-user service (decrypted accounts, header caches) stays in memory. |
| `UEM_MAX_CACHED_USERS` | `500` | Per-user services kept in memory; the least recently used idle ones go first. |
| `UEM_REAUTH_RETRY_AFTER` | `600` | After a rejected login (`REAUTH_REQUIRED`) the account is not tried again for this long, unless its password or user name changed. |

The sealed `requestState` of send confirmations needs no variable of its own: its keys are
derived from `STORE_KEYS` (so every instance agrees and the state follows key rotation).

A deployment with several instances multiplies the connection caps; size
`--max-instances` and these values so that `instances x UEM_MAX_CONNECTIONS` stays within what
the mail servers accept. The caps are per process; see "Rate limits" below for the call limits.

## Rate limits

OAuth mode limits attempts and calls so a stolen session, a looping client or a password
guesser cannot do unbounded work. Every limit is `COUNT/WINDOW` - `20/15m` is 20 per 15
minutes; units `s`, `m`, `h`, `d` (a bare number is seconds); count 1 to 100000, window 1
second to 7 days. An invalid value, or an unknown `UEM_RATE_*` name, stops the server at
startup. There is deliberately no way to switch a limit off; raise it instead.

| Variable | Default | Counted per | What it limits |
|---|---|---|---|
| `UEM_RATE_SIGNIN_ADDRESS` | `5/15m` | user / mailbox address | Wrong passwords at sign-in **and** portal re-authentication (they check the same password, so they share the counter). Counts failures only; a success resets it. |
| `UEM_RATE_SIGNIN_IP` | `20/15m` | network | Sign-in and re-authentication attempts, every one counted. |
| `UEM_RATE_AUTHORIZE_IP` | `120/10m` | network | POSTs to `/authorize` (sign-in, consent, deny, sign-out). |
| `UEM_RATE_REGISTER_IP` | `10/1h` | network | Dynamic Client Registration. |
| `UEM_RATE_REGISTER_GLOBAL` | `200/1h` | whole instance | Dynamic Client Registration, all callers together. |
| `UEM_RATE_TOKEN_IP` | `300/1m` | network | `/token` and `/revoke`. |
| `UEM_RATE_CLIENT_FETCH_IP` | `30/1m` | network | Downloads of Client ID Metadata Documents (outbound fetches triggered by `/authorize`). |
| `UEM_RATE_PORTAL_USER` | `60/10m` | user | State-changing portal requests (every POST: accounts, identities, clients, re-authentication). |
| `UEM_RATE_PORTAL_IP` | `120/10m` | network | The same, per network. |
| `UEM_RATE_TEST_USER` | `10/10m` | user | Connection tests and tested logins when adding an account/identity (they open outbound connections). |
| `UEM_RATE_TEST_IP` | `30/10m` | network | The same, per network. |
| `UEM_RATE_TEST_TARGET` | `5/15m` | mailbox (host, port, user name) | The same, per target mailbox - stops password guessing through the portal. |
| `UEM_RATE_VIEWER_USER` | `120/1m` | user | Message viewer pages and HTML frames (`/m/...`, `/c/...`). |
| `UEM_RATE_DOWNLOAD_USER` | `60/10m` | user | Raw `.eml` and attachment downloads. |
| `UEM_RATE_TOOL_USER_BURST` | `30/10s` | user | MCP tool calls of one user, all connected clients together - short burst window. |
| `UEM_RATE_TOOL_USER` | `600/10m` | user | The same, sustained window. |
| `UEM_RATE_TOOL_GRANT_BURST` | `20/10s` | grant (one connected client) | MCP tool calls of one grant - burst. |
| `UEM_RATE_TOOL_GRANT` | `300/10m` | grant | The same, sustained. |
| `UEM_RATE_TOOL_WRITE_BURST` | `10/10s` | user | Extra limit on tools that change something (`mark_messages`, `move_messages`, `create_folder`, `delete_messages`, `save_draft`, `send_message`) - burst. |
| `UEM_RATE_TOOL_WRITE` | `60/10m` | user | The same, sustained. |

How they behave:

* **Per instance.** These counters live in the memory of one process. With `n` instances
  (Cloud Run scales out) a caller can use up to `n` times the limit, and a restart forgets
  the counts. The send limit (`UEM_MAX_SENDS_PER_HOUR` / `_DAY`) is the one shared limit: it
  is counted in the store. A shared counter for the sign-in limits is a TODO; until then keep
  `--max-instances` small or put a rate limiter in front (load balancer / Cloud Armor).
* **Network** = the client address, IPv4 as is and IPv6 grouped per /64 (one subscriber
  owns a /64, so single addresses cannot be rotated to dodge a limit). The address is the
  socket peer, or - with `UEM_TRUSTED_PROXY_HOPS` set - the `X-Forwarded-For` entry that
  many places from the right (the one the first trusted proxy saw; entries to its left are
  client claims and ignored). Anything that is not an IP address shares one bucket. Set the
  hop count to what you really have: too low counts your proxy as the client, too high lets
  callers forge their address.
* **Sliding windows.** A refused request is not counted, so waiting as told is enough.
  Refusals say how long: `429` with `Retry-After` (HTTP, portal pages translated), and for
  tool calls the error `RATE_LIMITED` with `retry_after` seconds in the structured error and
  an English hint for the AI client. A refused tool call never takes a connection or reaches
  a mail server.
* **Bounded memory.** Each limiter tracks at most 20000 keys and each key at most `COUNT`
  timestamps; when full, expired keys go first, then the oldest. Keys (addresses, user ids)
  exist only in memory and are never logged.
* **Audit.** Every refusal is a `ratelimit.hit` event with a `scope` (see [audit.md](audit.md)).

## Endpoints

| Path | Purpose |
|---|---|
| `/mcp` | MCP over Streamable HTTP, **stateless**: clients of protocol 2026-07-28 get the sessionless transport, older clients (<= 2025-11-25) the legacy transport without sessions (no back-channel, so no in-chat confirmation for them). OAuth mode: needs an access token issued for this resource, and serves the tools of the token's grant; otherwise 401 with `WWW-Authenticate: Bearer resource_metadata="..."`. Dev mode: `Authorization: Bearer <UEM_DEV_TOKEN>`. |
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
format). `--build-arg EXTRAS=gcp` adds the Firestore client (needed for `STORE_BACKEND=firestore`). The base
image is pinned by digest. `scripts/smoke_container.sh IMAGE` is the check CI runs. Deployment on
Google Cloud: [deploy-gcp.md](deploy-gcp.md).
