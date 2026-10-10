# Administrator guide

For the person who installs and runs universal-email-mcp: on one laptop for yourself, or as a
multi-user service for an organisation. This guide is the map; it links to the reference pages
instead of repeating them. Users read the [user guide](user-guide.md); data protection is in
[gdpr.md](gdpr.md) and [dpia-template.md](dpia-template.md).

> **Status.** The package on PyPI is still the 0.0.1 name reservation. Until 0.1.0 is released,
> run everything from a checkout (`uv run universal-email-mcp ...`). Wherever this guide says
> `uvx universal-email-mcp`, read `uv run --directory /path/to/checkout universal-email-mcp`
> for now. The remote mode has not been run against a real cloud project yet (see
> [TODO.md](../TODO.md), "3i Deployment").

## 1. Local or remote mode?

| | Local mode (`local`) | Remote mode (`serve`) |
|---|---|---|
| For | one person on their own machine | an organisation, several users |
| Transport | stdio, started by the MCP client | HTTPS (Streamable HTTP), `/mcp` |
| Accounts | TOML file, passwords from environment or OS keyring | per user in the portal, stored encrypted in a store |
| Sign-in / consent | none (the client starts the process) | OAuth 2.1 with browser sign-in and consent page |
| Permissions | per account in the TOML file | account, grant, token and operator policy |
| Send approval | in-chat confirmation, else a draft | in-chat confirmation, else portal approval or draft |
| Message viewer | no (attachments via loopback download links) | yes, in the portal (`/m/...`) |
| State kept | nothing, except the audit key file | users, accounts, grants, activity (no mail) |
| Audit lines | stderr | stdout (Cloud Logging) |

Choose local mode when only you use it. Choose remote mode when people should not edit TOML
files, when several AI clients (Claude.ai, ChatGPT) must reach the server over the internet, or
when you need central policy and audit. There is also a temporary **dev mode** of `serve`
(`UEM_DEV_TOKEN` or `--insecure-local`): one static token, accounts from a TOML file, no portal.
It exists for trying things out; never expose it to users.

## 2. Local mode

### Install and configure

```bash
uvx universal-email-mcp probe --server mail.example.org --user alice@example.org   # check a login
mkdir -p ~/.config/universal-email-mcp
cp docs/config.example.toml ~/.config/universal-email-mcp/config.toml           # then edit
```

The config file is found in this order: `--config PATH`, the `UEM_CONFIG` variable, then
`config.toml` in the platform config directory (Linux: `~/.config/universal-email-mcp/`).
Every key is explained in [`config.example.toml`](config.example.toml). The main parts:

* `[[accounts]]`: `name`, `kind` (`imap` default, or `pop3`), `server` (a preset or a host name),
  `username`, the credential, and `permissions` (`read`, `organize`, `delete`, `drafts`; default
  `read` only). `[accounts.imap]`, `[accounts.pop3]`, `[accounts.smtp]` override host, port and
  `tls` (`tls` or `starttls`).
* `[[identities]]`: sender addresses; `send = true` lets `send_message` use one (it needs an SMTP
  account and a `store_account` with the `drafts` permission).
* `[policy]` and `[limits]`: see sections 5 and 6 below. `[settings]` holds `allow_private_networks`
  and the connect and read timeouts. `[downloads]` configures the loopback download links
  (`enabled`, `port` 0 = random, `link_ttl` 86400 s, `max_download_bytes`).

**Passwords are never written to the file.** Either name an environment variable
(`password_env = "UEM_WORK_PASSWORD"`), or leave both out and use the OS keyring
(service `universal-email-mcp`, key = the account name or `keyring_key`):

```bash
keyring set universal-email-mcp Work      # or: uv run keyring set ... from a checkout
```

Prefer the keyring: environment variables put the password into the MCP client's configuration
and into the process environment of anything it starts. Keep the config file private; it names
your servers and user names.

### Check, then register with a client

```bash
uvx universal-email-mcp probe --account Work     # read-only: capabilities, folders, quota; no message content
```

`probe` accepts `--server PRESET_OR_HOST --user NAME` instead of `--account` (the password comes from `UEM_PASSWORD` or a prompt), plus `--host`, `--port`,
`--starttls`, `--config`, `--ca-file` (self-signed servers), `--public-only`, `--timeout`,
`--no-counts`, `--json`. `--insecure` turns TLS
verification off and exists for local test servers only.

```bash
claude mcp add email -- uvx universal-email-mcp local                  # Claude Code
claude mcp add email -e UEM_WORK_PASSWORD=... -- uvx universal-email-mcp local   # password from env
```

For Claude Desktop add an entry with `"command": "uvx"` and `"args": ["universal-email-mcp", "local"]`
to its `mcpServers` configuration (README, "Local mode"). For a non-default config add
`"--config", "/path/to/config.toml"` to the arguments. Other MCP clients that can start a stdio
server work the same way; how they are configured is up to the client.

Start with `permissions = ["read"]` and widen per account only when needed. Try write operations
on the sandbox mailbox first (`uv run scripts/dev_mailbox.py up`, see [AGENTS.md](../AGENTS.md)).

## 3. Remote mode: deployment overview

Remote mode needs a public https URL, a store, two secrets and a few settings:

1. Decide `PUBLIC_URL` once (it is the OAuth issuer; changing it logs everybody out), a second
   host name for `CONTENT_ORIGIN`, the e-mail domains that may sign in (`LOGIN_DOMAINS`) and the
   servers users may add (`MAIL_SERVERS`).
2. Create the store and the keys: Firestore plus a key ring (`STORE_KEYS`) and a pseudonym key
   (`PSEUDONYM_KEY`). [`deploy-gcp.md`](deploy-gcp.md) walks through Google Cloud Run and
   Firestore end to end (`deploy/gcp/bootstrap.sh`, `cloudbuild.yaml`); the container is not
   Google specific.
3. Set the policy (`UEM_READ_ONLY`, `UEM_SEND_POLICY`, ...). Start restrictive: read-only, or
   `UEM_SEND_POLICY=draft`.
4. Deploy, check `/health` and `/ready`, connect a client (MCP Inspector first), then roll out
   to users with the [user guide](user-guide.md).

All variables, defaults, endpoints and the container: [`operator-env.md`](operator-env.md).
The OAuth flow and the per-user service: [`oauth.md`](oauth.md). The portal:
[`portal.md`](portal.md). The security checklist at the end of `deploy-gcp.md` (section 13) is
the pre-launch list. Invalid settings stop the server at startup with a message that names the
variable. `STORE_BACKEND=memory` loses everything on restart: development only. A SQLite store
for a single VM is not available yet.

## 4. Mail servers and sign-in domains

A *server entry* is a preset name or a host name. A preset bundles IMAP, POP3 and SMTP endpoints
(today only `united-domains`); a bare host name means the same host on 993 (IMAP), 995 (POP3)
and 465 (SMTP), implicit TLS. In local mode `server = "..."` takes an entry, and
`[accounts.imap|pop3|smtp]` tables override single endpoints. More presets are added only with
`probe` evidence from a real provider.

In remote mode two variables decide which servers are reachable:

* `LOGIN_DOMAINS=example.org=imap.example.org,other.org=imap.other.org`: only users with an
  address in one of these domains can sign in, and the password is verified against **the server
  you assign to the domain**, never one the user names. This is what stops someone from claiming
  `alice@example.org` against a server of their own. A bare `domain` (no `=server`) uses the
  single `MAIL_SERVERS` entry. Required in OAuth mode.
* `MAIL_SERVERS=imap.example.org` (comma separated): the servers users may use for accounts they
  add in the portal. One entry is fixed, several are a choice, **empty is free entry** of any
  public host name (ports 993/995/465/587 only, verified TLS, no private, loopback or metadata
  addresses). Prefer a fixed list.

Outbound connections (mail servers, OAuth client metadata) resolve the name once, check every
address and connect to the checked one, so a user-supplied host cannot reach your internal
network. `UEM_ALLOW_PRIVATE_NETWORKS` (default `false` in remote mode) relaxes this for servers
you list yourself; do not turn it on for free entry.

## 5. Policy and permissions

### Who may do what

The rights a tool call really has are the **intersection of four things**, checked on every call
and per account:

```
effective right  =  account permissions        (what the account owner allows at most)
                 ∩  grant                      (what the user ticked at consent for this client)
                 ∩  token scope                (what the issued token carries; a refresh never widens it)
                 ∩  operator policy            (UEM_READ_ONLY, UEM_SEND_POLICY, ...)
```

Local mode has only the account's `permissions` and `[policy]`. A tool that nothing allows is not
even offered to the client, and a call to a tool that was not offered is refused. POP3 accounts
are always read-only. Permissions:

| Permission | Tools it adds | Notes |
|---|---|---|
| `read` | `account_info`, `list_folders`, `find_messages`, `get_message`, `get_attachment`, `find_contacts` | default; reading never marks mail as read |
| `organize` | `mark_messages`, `move_messages`, `create_folder` | UID-scoped, checked against UIDVALIDITY, never a plain `EXPUNGE` |
| `delete` | `delete_messages` | moves to Trash; there is no permanent deletion |
| `drafts` | `save_draft` | writes to Drafts, never sends |
| send (on an *identity*) | `send_message` | grant, identity, `drafts` account and policy must all allow it |

### Operator policy

Same meaning in the TOML `[policy]` / `[limits]` and in the environment (`UEM_*` variables, a
set variable overrides TOML; table in [operator-env.md](operator-env.md#limits-and-policy)):

| Setting | Default | Effect |
|---|---|---|
| `read_only` / `UEM_READ_ONLY` | false | only `read` is possible, whatever accounts and grants say |
| `send` / `UEM_SEND_POLICY` | `confirm` | `off` (tool removed), `draft`, `confirm`, `confirm-external`, `on` |
| `allowed_recipient_domains` / `UEM_ALLOWED_RECIPIENT_DOMAINS` | any | hard allow-list for recipients |
| `internal_domains` / `UEM_INTERNAL_DOMAINS` | none | whole domains counted as internal; never list a public provider |
| `max_recipients` | 20 | per message |
| `max_sends_per_hour`, `max_sends_per_day` | 20, 100 | per SMTP account in local mode (memory, while running); per user in remote mode (store, all instances) |
| `[limits]` / `UEM_MAX_*` | see example config | result sizes, batch sizes, message and attachment sizes, `max_send_bytes` |

Users can never get more than the operator policy offers; in the portal they can only restrict
further.

## 6. Send safety

Sending is the riskiest tool: mail content is untrusted and could talk the AI client into sending
something. Every send therefore follows the same path:

1. The message is saved as a **draft** first (a declined or failed send leaves it in Drafts).
2. Each recipient is classified: **internal** (own identity addresses and `internal_domains`),
   **known** (you wrote to it within 2 years), **new**, or **look-alike** (typo, confusable
   characters, another top-level domain of a known address). Hard limits (allowed domains, maximum
   recipients, send rate, size) apply.
3. The policy decides whether the user must confirm:

| `send` | Behaviour |
|---|---|
| `off` | `send_message` is not offered |
| `draft` | composes and keeps drafts, never sends |
| `confirm` (default) | the user confirms every send in the AI client (MCP elicitation) |
| `confirm-external` | confirms unless every recipient is internal |
| `on` | confirms only look-alike recipients (always confirmed) |

4. If the client **cannot ask** (no elicitation support, or the legacy protocol over stateless
   HTTP), the fallback applies. A client that declares elicitation is trusted to really ask the
   user; one that auto-accepts defeats the question. Local mode keeps a draft. In remote mode
   `SEND_FALLBACK` decides:
   `portal` (default): the draft stays, a pending approval is created, and the user reads exactly
   what would go out on the portal page *Pending approvals* and approves it with a password check;
   `send-unless-flagged`: sends directly unless a recipient is new or a look-alike (those go to the
   portal), a trade-off for deployments whose clients cannot ask; `draft`: only a draft. There is
   deliberately no mode that sends unconfirmed in every case, and a look-alike recipient is never
   sent without a human. Note that `send-unless-flagged` and `UEM_SEND_POLICY=on` do send to
   internal or known recipients (and, under `on`, new ones) without a question.

Replay protection: a confirmation is sealed (AES-256-GCM, 10 minutes, bound to user, grant, tool
and arguments), a send claims its content hash in the store for 10 minutes (`ALREADY_SENT`), and an
approval is consumed once. The send itself uses TLS 1.2 or newer with a verified certificate
(465 implicit TLS or 587 STARTTLS; there is no plain-text mode), never transmits `Bcc`, and sends
nothing if any recipient is refused. A connection that breaks after the body went out is reported
as `SEND_OUTCOME_UNKNOWN` and never retried.

Recommended start for a pilot: `UEM_READ_ONLY=true`; then `UEM_SEND_POLICY=confirm` with
`SEND_FALLBACK=portal` once users know the approval page.

## 7. Keys and secrets

| Secret | Variable | Used for | Rotation today |
|---|---|---|---|
| Store key ring | `STORE_KEYS` or `STORE_KEYS_FILE`, `STORE_ACTIVE_KEY` | AES-256-GCM sealing of mail passwords, server settings, activity; the MAC of every record and the keyed ids of tokens and sessions; also (derived from the ring, one key per purpose) the sealed `requestState` of send confirmations, the paging cursors, the opaque viewer ids and the content-origin addresses | supported, below |
| Pseudonym key | `PSEUDONYM_KEY` or `PSEUDONYM_KEY_FILE` | HMAC that turns a mail address into the user id (`u_...`) and the pseudonyms in logs - **nothing else**; an analyst who runs `audit --user` needs it and gets no way to forge cursors, viewer links or tokens | **not supported** |
| Local audit key | file `audit.key` in the platform state directory (mode 0600) | pseudonyms in local-mode audit lines | delete the file to get a new one (old log lines can then no longer be matched) |
| Mailbox passwords | portal, stored sealed (remote); keyring or env (local) | logging in to mail servers | users change them (portal "Password" action) |

Generate a key with `python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`.
Keep both secrets in a secret manager, readable only by the runtime identity, never in the
repository, a ticket or a command line. Both are required with the Firestore backend.

**Store key ring rotation** (no logouts, no downtime; the Google Cloud commands are in
[deploy-gcp.md](deploy-gcp.md#8-key-rotation)):

1. Pin the active key to the current one (`STORE_ACTIVE_KEY=k1`) and deploy, so instances that
   start later do not pick up a new key early.
2. Add `k2` to the ring, set `STORE_ACTIVE_KEY=k2`, deploy: new and changed records use `k2`.
3. Re-seal what nobody has written since: `universal-email-mcp admin rotate-keys` (the same
   environment as `serve`; add `--dry-run` to only count). It prints counts per record kind and
   is safe to repeat. Records it cannot read are reported as `UNREADABLE` (exit status 3) and
   skipped; look at them before you remove the old key.
4. When a second run reports 0, remove `k1` from the ring. Keep the old secret version until
   backups sealed with `k1` have expired: a restored backup needs the key that sealed it.

Losing a key makes the blobs sealed with it unreadable: users must add their mail accounts again.

**Pseudonym key.** Users are keyed by it, so changing it makes every user a stranger: their
records stay behind under the old ids and they start from scratch. There is no migration tool.
Treat the key as permanent; if it leaks, someone with a list of addresses can test which of them use
the service and recognise them in logs. It gives no direct access to mail, but it is also the
signing key of paging cursors and of the content-origin addresses, so with it and a guessable
message id an attacker could forge a `/c/...` address and read the sanitised HTML of that message. Rotating it
today means a planned reset of all users.

**Request-state keys** need no variable: they derive from the store ring and follow its rotation.

Not covered by any of this: a compromised running instance holds the keys and decrypted
passwords in memory.

## 8. Backups

With Firestore (reference deployment): point-in-time recovery (7 days) and scheduled backups, see
[deploy-gcp.md](deploy-gcp.md#9-backups). What the store holds is small and **contains no mail**.
What you lose without a backup is configuration work, not mail: users' accounts (they re-enter
mailbox passwords), sender identities, connected applications (clients must connect again),
the 30-day activity feed and pending approvals. Mail itself stays on the mail servers.

A backup is useless without **both** secrets (ring and pseudonym key): keep their versions and
back up access by policy. Local mode: back up `config.toml`; passwords are in the keyring or your
environment, and nothing else is stored. Test a restore once into a scratch database.

## 9. Monitoring and audit

* **Audit lines** are JSON on stdout (remote) or stderr (local) with pseudonymous ids, outcome
  codes, counts and size buckets, never addresses, subjects, bodies or tool arguments. Event
  reference: [audit.md](audit.md). `UEM_LOG_LEVEL=DEBUG` stays off in production.
* **`universal-email-mcp audit`** summarises audit lines from files, stdin or a
  `gcloud logging read --format=json` export, with no server or network needed:

```bash
gcloud logging read 'resource.type="cloud_run_revision" AND jsonPayload.event:*' \
  --freshness=7d --format=json > audit-export.json
universal-email-mcp audit --since 7d audit-export.json                     # per event, tool, sends, failures
export PSEUDONYM_KEY_FILE=/secure/pseudonym-key
universal-email-mcp audit --user alice@example.org --since 7d audit-export.json
universal-email-mcp audit --event 'send.*' --json audit-export.json
universal-email-mcp audit --local --account Work audit.log               # local mode
universal-email-mcp audit pseudonym user alice@example.org                # for Logs Explorer filters
```

* **Metrics and alerts**: log-based metrics for failed sign-ins, token replay, send failures,
  rate-limit hits, auth refusals and 5xx, plus an alert policy and suggested thresholds are in
  [deploy-gcp.md](deploy-gcp.md#10-logging-audit-events-and-alerting). Add an uptime check on
  `/ready`, a Secret Manager access alert and a budget alert.
* **Log retention.** The pseudonymous user id is personal data for whoever holds the key. Route
  the logs to a dedicated bucket with a defined retention, restrict access, and document the
  purpose ([gdpr.md](gdpr.md)).
* **Users see their own side** on the portal pages *Activity* (30 days) and *Privacy*.

## 10. Rate limits

Every limit is `COUNT/WINDOW` (`20/15m`), set through `UEM_RATE_*` variables; none can be
switched off. They cover sign-in and re-authentication (per address and per network), `/authorize`,
`/token`, client registration, client-metadata fetches, portal actions, connection tests, viewer
pages, downloads and MCP tool calls (per user and per grant, burst and sustained; tools that change
something are limited harder). Table, units and behaviour:
[operator-env.md](operator-env.md#rate-limits). Points to know:

* **The counters live in the memory of one instance; sign-in limits are per instance.** With
  *n* instances a caller gets up to *n* times the limit - a password guesser up to
  `n x 5` guesses per 15 minutes against one mailbox - and a restart forgets the counts. Only the
  send limit is shared (stored). **For the pilot run one or two instances**
  (`--min-instances=1 --max-instances=2` on Cloud Run; one is safest for this), lower
  `UEM_RATE_SIGNIN_ADDRESS` if you allow more, and put a limiter in front of anything public
  (load balancer, Cloud Armor). A shared counter is in `TODO.md`; it is not built for 0.1.0.
* Set `UEM_TRUSTED_PROXY_HOPS` to the real number of proxies (Cloud Run: 1; with an external load
  balancer verify it from the logs). Wrong values make the limits count your proxy or let
  callers forge their address.
* A refused request answers `429` with `Retry-After`; a refused tool call returns `RATE_LIMITED`
  with `retry_after` and never reaches a mail server.

## 11. Incident response checklist

There is **no operator admin console or command** yet for revoking one user or one client
(listed in `TODO.md`). What exists today is below; the user-side actions are quick and complete,
the operator-side ones are manual.

**A. A user's AI client or session is compromised (the user can act)**
1. The user signs in to the portal and, under *Connected applications*, disconnects the client
   (tokens stop working at once), or uses *Privacy* > delete everything.
2. If the mailbox password may be known, change it at the mail provider, then enter the new one
   under *Mail accounts* > Password. The next call shows `REAUTH_REQUIRED` until the stored copy is updated (signing in with the new
   password refreshes "Main"; other accounts need the Password action).

**B. The operator must cut a user off**
1. Find the user's activity: compute the pseudonym and read the audit lines (section 9):
   `audit --user alice@example.org --since 7d export.json`.
2. Revoke their grants by deleting the user's documents in the Firestore collection `grants`
   (query the plain field `user_id`; document ids are hashes and cannot be guessed). An access or
   refresh token is valid only while its grant exists, so every client of that user stops on the
   next request. Grants, browser sessions (`portal_sessions`, also by `user_id`) and accounts are
   separate records: also delete the user's `portal_sessions`, otherwise the user can still
   consent again with a live session (up to 30 minutes idle / 12 hours). `Store.delete_user`
   removes everything in the right order. The full user id is `u_` plus 32 hex digits;
   `audit pseudonym` prints only the 14-character form used in logs. Compute the full one from a
   checkout (`uv run`) on a trusted machine with the key in the environment; the address must be
   written lowercase:

```bash
PSEUDONYM_KEY="$(gcloud secrets versions access latest --secret=uem-pseudonym-key)" uv run python -c "
import base64, os
from universal_email_mcp.oauth.identity import Pseudonyms
print(Pseudonyms(base64.b64decode(os.environ['PSEUDONYM_KEY'])).user_id('alice@example.org'))"
```

   (With `FIRESTORE_PREFIX` the collection is named `<prefix>grants` - check the console.) To
   remove all of the user's records the supported path is the user's own *Privacy* page, or
   `Store.delete_user(user_id)` from a one-off job like the rotation job; it is not packaged as a
   command.
3. To stop a user from signing in again, remove their domain from `LOGIN_DOMAINS` (affects the
   whole domain) or disable the mailbox at the mail provider (the sign-in verifies the password
   against that server). There is no per-user block list.

**C. A client application must be disabled**
There is no deny list of clients. Delete the `grants` documents with that `client_id`
(tokens die with them) and also delete its record in `oauth_clients` (field `_id` = client id): an already registered
client keeps working at `/authorize` until that record expires (30 days unused, extended on use).
Set `UEM_DCR=false` so that no new registrations are accepted (`UEM_DCR_REDIRECT_HOSTS` only
checks redirect hosts at registration). A client identified by a metadata document URL can still be authorised
anew by users; tell them not to.

**D. Stop the damage first, investigate second**
* Redeploy with `UEM_READ_ONLY=true` (no write tools for anyone) and/or `UEM_SEND_POLICY=off`
  (no sending), or pause the service. Settings are read at start, so this needs a new revision.
* Pending approvals expire after `UEM_APPROVAL_TTL` (10 minutes) by themselves.

**E. Keys**
* Store key ring suspected leaked: rotate (section 7) and, if the database was copied too,
  ask users to change their mailbox passwords.
* Pseudonym key leaked: see section 7 (linking addresses to pseudonyms, forged cursor and content-origin signatures).
* Both keys and a database copy leaked: treat mailbox passwords as compromised for all users.

**F. Afterwards**
Keep the exported audit lines, note times and affected pseudonyms, and decide whether the
authorities and the persons concerned must be informed; the 72 hour clock of Art. 33 GDPR starts
when you become aware ([gdpr.md](gdpr.md), not legal advice).

## 12. Upgrading

1. Read `CHANGELOG.md` for the versions in between. Variables and defaults change in the
   `Changed` and `Added` sections.
2. Take a backup (section 8). Stored records carry a format version (`_v`); new versions read old
   records, but a rollback across a release that changed the stored format may not read what the
   newer version wrote. Roll back only within releases that did not change the store.
3. Local mode: upgrade the package (`uvx` fetches the newest unless pinned); restart the client.
4. Cloud Run: a new revision only takes traffic after its startup probe (`/ready`) passes; a
   canary tag lets you test first; rollback is `gcloud run services update-traffic` (commands in
   [deploy-gcp.md](deploy-gcp.md#11-upgrade-and-rollback)). Settings and secrets are read at start,
   so a new secret version or variable needs a new revision.
5. Rebuild regularly to pick up the pinned base image updates (CI scans the image).

## 13. Troubleshooting

Tool errors carry a stable `code`, a message and a hint (the AI client sees them). Command line
tools print `error [CODE]: ...`.

| Code | Meaning and what to do |
|---|---|
| `CONFIG_INVALID` | the TOML file is wrong; the message names the key |
| `CREDENTIAL_MISSING` | local: the `password_env` variable is unset or the keyring has no entry; `keyring set universal-email-mcp <account>` |
| `AUTH_FAILED` | the mail server rejected the login; check user name and password (some providers need an app password) |
| `REAUTH_REQUIRED` | remote: the stored password stopped working; the user enters it again under *Mail accounts*. No login is retried for `UEM_REAUTH_RETRY_AFTER` (600 s) unless the password changed |
| `SERVER_UNREACHABLE`, `TIMEOUT` | host, port or network problem; the provider may be down. `UEM_ACCOUNT_TIMEOUT` / `account_timeout` bounds one account |
| `TLS_ERROR` | certificate or handshake failure; check the port (993/995/465 implicit TLS, 143/110/587 STARTTLS); self-signed servers need `tls_ca_file` (local) |
| `ADDRESS_NOT_ALLOWED` | the host resolves to a private, loopback or otherwise non-public address; local mode: `allow_private_networks = true`; remote: `UEM_ALLOW_PRIVATE_NETWORKS` for servers you list |
| `SERVER_ERROR`, `UNSUPPORTED_BY_SERVER` | the server refused or lacks a needed capability (move needs `MOVE` or `UIDPLUS`; POP3 needs `UIDL` and `TOP`); run `probe` |
| `UIDVALIDITY_CHANGED` | the folder was rebuilt; ids are void, search again |
| `NOT_PERMITTED` | account permission, grant, token or policy does not allow it; see section 5 |
| `FOLDER_NOT_FOUND`, `AMBIGUOUS_FOLDER`, `NO_ARCHIVE_FOLDER`, `NO_TRASH_FOLDER`, `NO_DRAFTS_FOLDER` | folder resolution; set `[accounts.folders]` roles (`sent`, `drafts`, `trash`, `junk`, `archive`) when detection fails |
| `MESSAGE_NOT_FOUND`, `INVALID_REF`, `INVALID_CURSOR`, `STALE_CURSOR`, `ATTACHMENT_NOT_FOUND`, `INVALID_ARGUMENT`, `INVALID_FOLDER_NAME` | wrong or outdated ids or arguments; the client should list or search again |
| `TOO_LARGE` | a configured size limit was exceeded |
| `BUSY` | remote: too many connections or parallel calls for this user or instance; retry. Raise `UEM_MAX_CONNECTIONS*` / `UEM_MAX_CONCURRENT_CALLS_PER_USER` only within what the mail servers accept |
| `RATE_LIMITED` | send limit of the policy or a `UEM_RATE_*` limit; `retry_after` says when |
| `RECIPIENT_REFUSED` | the SMTP server refused a recipient; nothing was sent |
| `SEND_OUTCOME_UNKNOWN` | connection broke after the body went out; do not resend, check Sent |
| `ALREADY_SENT` | the replay guard blocked a repeat of the same message |
| `NOT_SUPPORTED_YET` | account type or operation not implemented |

HTTP side (remote): `401` on `/mcp` without a valid token (clients discover sign-in from the
`WWW-Authenticate` header); `421` wrong `Host` (add it to `PUBLIC_URL` / `ALLOWED_HOSTS`; `/health`
and `/ready` are exempt); `403` foreign `Origin` (`ALLOWED_ORIGINS`); `413` body over
`UEM_MAX_REQUEST_BYTES`; `429` rate limit; `503` on `/ready` means a check failed (the body lists
check names: config, store). A revision that never becomes ready usually has a missing key or
missing store permission. Startup errors name the variable. Sign-in refused for a domain: it is not
in `LOGIN_DOMAINS`. Rate limits seem shared by everybody: `UEM_TRUSTED_PROXY_HOPS` is 0 behind a
proxy. Local mode prints progress on stderr with `-v`; stdout belongs to the MCP protocol.
