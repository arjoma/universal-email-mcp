# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- German translation of the whole end-user UI (portal, sign-in, consent, message viewer,
  approvals): formal "Sie", chosen by cookie, `Accept-Language` (`de-AT` works) or the
  operator's `UEM_DEFAULT_LANGUAGE`; the language switch now appears in the footer. Times
  follow the language (`09.10.2026 14:30 UTC`); notes the service layer builds (recipient
  warnings on the approval page, viewer notes) are translated by pattern. A completeness test
  lists missing German ids after any UI change (`docs/portal.md#language`).

### Changed

- Audit events: one pipeline for local and remote mode (`docs/audit.md`). Lines are JSON with a
  stable shape (`event`, `message`, `severity`, `ts`, `instance`, `request_id`, ...), written to
  **stdout** by `serve` (Cloud Logging reads `severity`) and to stderr by the local stdio server. A
  per-event allow-list drops unknown fields and replaces values that do not look like short
  tokens, so mail text cannot reach the log by mistake. Ids are keyed pseudonyms (`PSEUDONYM_KEY`,
  a per-install key in local mode): account names, client ids and grant/approval ids are no longer
  logged in clear. IP addresses are never logged; with `AUDIT_LOG_CLIENT_IP` sign-in and
  rate-limit events carry a keyed pseudonym of the network.
- Firestore backend: creates and unconditional deletes are written as precondition-free batches
  that retry when Firestore aborts them under contention, and `Store.get_or_create_user`
  retries; two intermittent failures under load (concurrent sign-in of one user, concurrent
  redemption of one authorization code) are fixed.
- Remote mode: signing in (portal and OAuth) now only verifies the password. The mailbox
  password is stored sealed, and the account "Main" plus a sender identity created, only if
  the user ticks the pre-ticked opt-in checkbox "Use this mailbox with AI clients (stores the
  password encrypted)". Unticked, nothing is stored; an existing "Main" still has its password
  refreshed at later sign-ins.

### Added

- Documentation: administrator guide, user guide, GDPR notes for operators and a DPIA template
  (`docs/admin-guide.md`, `docs/user-guide.md`, `docs/gdpr.md`, `docs/dpia-template.md`), linked
  from the README.

- Rate limits (`docs/operator-env.md#rate-limits`): every in-memory limit is now one `RateLimits`
  inventory with `UEM_RATE_*` variables (`COUNT/WINDOW`, validated). New: MCP tool calls per user
  and per grant (burst and sustained windows, tighter for tools that change something; the
  error is `RATE_LIMITED` with `retry_after`, and the call never reaches a mail server), portal
  POSTs per user and network, viewer pages and downloads per user (translated 429 page),
  `/authorize` POSTs per network. IPv6 clients are limited per /64, `Retry-After` is sent with
  every 429, limiter memory is bounded, `ratelimit.hit` carries `grant` and the new scopes.
- Portal page **Privacy** (`/portal/privacy`): what is stored about the user with live counts
  and the retention from the running configuration; **download my data** (one JSON file with the
  user's own records, never passwords, token digests or keys); **delete all my data** (needs a
  recent password entry, the typed address and the CSRF token; revokes every grant and token
  first, then removes all records of the user and closes their pooled mail connections).
  Audit events `portal.export` and `portal.delete_all`.
- `universal-email-mcp audit`: summarises audit lines from files or stdin (raw lines, Cloud Logging
  JSON arrays or NDJSON) per event, tool (error rate, duration buckets), send outcome, failed
  sign-in network and rate-limit scope; filters `--user ADDRESS` (pseudonym recomputed from
  `PSEUDONYM_KEY`, `--key-file` or `--local`), `--client`, `--account`, `--grant`, `--event`,
  `--since`/`--until`, `--json`; `audit pseudonym KIND VALUE` prints a pseudonym for log filters.
  Values from the log are sanitised before printing; the key is never printed or taken as an
  argument value.
- Own-activity feed and the portal page **Activity** (`/portal/activity`): the user's recent
  events in plain words - sign-in, connecting and disconnecting applications, account and
  identity changes, what applications did (a `tool.call` audit event per MCP tool call in OAuth
  mode, with counts for changes; reads merged per hour), sends, approvals, viewer use. Names are
  resolved from the user's own records when the page renders; 30 days; translatable.
- Documentation of log-based metrics and alert policies for failed sign-ins, token replay, send
  failures, rate limits and 5xx (`docs/deploy-gcp.md`).
- The send confirmation (elicitation prompt and portal approval page) now covers every body the
  recipients get: an HTML version that differs from the plain text, or is the only body, is shown
  as text under its own heading, remote images are warned about, and cuts (also the 300000
  character preview limit) are announced. Defanging of the shown text no longer takes minutes
  on very long unbroken runs.
- Sending in remote mode (work package 3f; `docs/oauth.md`, `docs/portal.md`,
  `docs/operator-env.md`): `send_message` is offered when the grant (`mail.send` for an
  identity), the identity ("sending allowed", complete outgoing login, copies to an account
  with `drafts`) and the operator policy all allow it - rebuilt from the store on every
  request and enforced again per call. The confirmation question of protocol 2026-07-28
  rides a **sealed `requestState`** (SDK `RequestStateSecurity`, keys derived from
  `STORE_KEYS`, bound to tool, arguments, user and grant, 10 minutes): forged, edited,
  replayed, expired or foreign state is refused, and a replay guard in the store (user +
  content hash) makes a confirmed message go out once. **`SEND_FALLBACK`** for clients that
  cannot ask: `portal` (default; the draft is kept and the result links to the approval
  page), `send-unless-flagged` (new addresses and look-alikes go to the portal; a look-alike
  never goes out without a human) or `draft`. New portal page **Pending approvals**
  (`/portal/approvals`): shows sender, recipients with class and warnings, subject,
  attachments and the new text (same truncation as the prompt, quoted original folded),
  approve (password within the re-auth window, CSRF) sends exactly the stored draft whose
  content hash matches, reject keeps the draft, old ones show as expired, other users' are
  404. Sends per hour/day are counted per user in the store. Audit events `send.*`,
  `approval.*` without addresses or subjects. `UEM_APPROVAL_TTL`.
- Deployment on Google Cloud (work package 3i; `docs/deploy-gcp.md`): `deploy/gcp/` with an
  idempotent `bootstrap.sh` (APIs, least-privilege service accounts, Artifact Registry,
  Firestore with PITR, delete protection and TTL policies, generated secrets that are never
  printed), `cloudbuild.yaml` (build with the `gcp` extra, push, deploy by digest) and a Cloud
  Run `service.yaml` template (secrets from Secret Manager, probes, gen2, no IAM gate for the
  public OAuth server). The guide covers domains and load balancer, static egress, key
  rotation, backups, logging, alerting, rollback, cost and a security checklist.
- CI builds the production image, smoke-tests it (`scripts/smoke_container.sh`: `/health`,
  `/ready`, `/mcp` refused without a token, Host check, non-root user) and scans it with
  Trivy; the container image base is now pinned by digest and carries OCI labels.

- Message viewer in the portal (work package 3g; `docs/portal.md`): every message in a tool
  result of remote mode links to `PUBLIC_URL/m/<id>` (attachments `/m/<id>/a/<part>`, source
  `/m/<id>/eml`; no tokens in the links - the portal session authorises, a signed-out visitor
  is sent to sign-in and back). Pages: message (headers, text, attachment list), conversation,
  raw headers with the authentication results, `.eml` download. Messages are resolved only
  inside the signed-in user's own accounts that grant `read` (another user's or a forged id
  answers the same 404 as a deleted message); nothing is marked as read. **HTML mail** is
  shown only in a sandboxed iframe (no scripts, no same-origin) served by its own route with a
  strict CSP (`default-src 'none'`, `img-src data:`), cleaned by an allow-list sanitizer
  (`nh3`) and an own CSS filter; `cid:` images are inlined, remote images load only after an
  explicit click for that view, links open in a new tab with `noopener noreferrer` and are
  listed defanged. Optional `CONTENT_ORIGIN` serves that document from a separate origin via
  signed two minute addresses. Attachments stream from IMAP chunk by chunk (reusing the
  verified part lookup and incremental decoders of the local download server) with
  `Content-Disposition: attachment`, `nosniff`, a sandbox CSP and the passive type allow-list;
  `UEM_MAX_DOWNLOAD_BYTES` caps them. POP3 messages work too (read whole). Audit events
  `viewer.open`, `viewer.raw`, `attachment.download`.
- User portal (work package 3d; `docs/portal.md`), server-rendered at `/portal` without
  scripts: **mail accounts** (add IMAP or POP3 from the operator's `MAIL_SERVERS` or - only if
  that list is empty - by host name with SSRF guards and encrypted ports only; the login is
  tested before anything is stored; test button for IMAP/POP3 and SMTP; per-account
  permissions read / organize / delete / drafts as the user's own upper bound; password
  change; removal deletes the credentials and disconnects the clients that could use the
  account), **sender identities** (address, display name, signature, sending account, account
  for drafts and sent copies, default, "sending allowed"; header-injection-safe), **connected
  applications** (list with fenced name, host, created, last used, scopes; reduce or
  disconnect), a **language switch** (`uem_lang` cookie; English ships, the mechanism is
  tested with a catalog) and a portal sign-in. The sign-in mailbox becomes a real account
  ("Main") on the first sign-in; grants that referenced the 3c pseudo account `primary` are
  rewritten. **Re-authentication**: adding or removing accounts, changing a password, raising
  permissions, allowing an identity to send and granting `send` at the consent page need the
  password again within `UEM_REAUTH_WINDOW` (default 5 minutes). The consent page now lists
  the user's real accounts and the identities that may send. Connection tests are rate limited
  per user, address and target and never show server text. Audit events `portal.*`.
- CORS for the cookie-less endpoints (`/.well-known/*`, `/register`, `/token`, `/revoke`,
  `/mcp`) in OAuth mode, so browser-based MCP clients (MCP Inspector) can connect: preflight
  answered, `Access-Control-Allow-Origin: *` without credentials, `Authorization` and
  `Mcp-Protocol-Version` allowed. Portal and `/authorize` routes keep the strict `Origin`
  check and never send CORS headers.
- Operator variables `UEM_REAUTH_WINDOW`, `UEM_MAX_ACCOUNTS_PER_USER`,
  `UEM_MAX_IDENTITIES_PER_USER`.
- `Identity` store record: `send` and `smtp_account_id` fields.
- `mail.smtp.check_login()`: connect and authenticate without sending.
- Per-user service for remote mode (work package 3e; `docs/oauth.md`, "What `/mcp` serves").
  In OAuth mode `/mcp` now serves the signed-in user's own accounts from the store instead of
  the one-tool preview: the tool list is computed per request from the connected client's grant
  (a read-only grant sees the six read tools, organize/delete/drafts add theirs), instructions
  and folder map are per user, permissions are enforced on every call as account permission
  ∩ grant scope ∩ token scope ∩ operator policy, and users are isolated from each other
  (per-user cursor keys, queries and checks by user id). Credentials are decrypted only in
  memory and never logged. `send_message` is not offered in remote mode until 3f.
- Resource caps of the per-user pool: `UEM_MAX_CONNECTIONS`, `UEM_MAX_CONNECTIONS_PER_USER`,
  `UEM_MAX_CONCURRENT_CALLS_PER_USER` (`BUSY` tool error), `UEM_CONNECTION_IDLE_TTL`,
  `UEM_USER_IDLE_TTL`, `UEM_MAX_CACHED_USERS`; pooled connections are closed when idle or when
  the account record changes.
- `REAUTH_REQUIRED`: a mail password the server rejects is reported per account with a pointer to
  the portal, the account record is marked (`auth_failed_at`, sealed `auth_failed_mark`) and not
  tried again for `UEM_REAUTH_RETRY_AFTER` seconds unless the login changed.

- OAuth 2.1 authorization server for remote mode (work package 3c; `docs/oauth.md`).
  `serve` without dev flags is now the OAuth server: `/.well-known/oauth-protected-resource`
  (RFC 9728) and `/.well-known/oauth-authorization-server` (RFC 8414), `/authorize`
  (authorization code, PKCE S256 required, RFC 8707 `resource` as token audience, RFC 9207
  `iss`), `/token` (code exchange and refresh with rotation and replay detection),
  `/revoke` (RFC 7009) and `/register` (RFC 7591 fallback: public clients, rate limited,
  optional redirect-host allowlist). Clients are identified by Client ID Metadata Documents
  (https URL fetched SSRF-safe: one resolution, every address checked, no redirects, size and
  time limits, cached in the store) or by dynamic registration; redirect URIs are matched
  exactly (loopback ports free per RFC 8252). Access and refresh tokens are opaque and stored
  as hashes (1 h / 30 days sliding / 90 days absolute, configurable); a replayed authorization
  code revokes the tokens issued from it, a replayed refresh token revokes the grant.
  `/mcp` checks the bearer token and its audience and answers 401 with
  `WWW-Authenticate: Bearer resource_metadata=...`.
- Sign-in and consent pages (server-rendered Jinja2, strict CSP without scripts,
  `frame-ancestors 'none'`, CSRF tokens, `__Host-` cookies, rate limits per address and IP).
  Sign-in verifies the mailbox login by an IMAP login against the server `LOGIN_DOMAINS`
  assigns to the address's domain; the password is not stored. The consent page lists the
  client, where the answer goes and per mailbox read / organize / delete / drafts
  (and send over sender identities) as grants. All end-user text goes through a translation
  layer (message catalogs per language, English only for now; default language by operator,
  cookie and browser preparation for a user switch).
- Operator environment for the store and OAuth: `STORE_BACKEND` (`memory`, `firestore`),
  `STORE_KEYS`/`STORE_KEYS_FILE`, `STORE_ACTIVE_KEY`, `PSEUDONYM_KEY`, `FIRESTORE_*`,
  token and session lifetimes, `UEM_DCR*`, `UEM_TRUSTED_PROXY_HOPS`, `UEM_DEFAULT_LANGUAGE`;
  `/ready` checks the store.
- `universal-email-mcp serve` (remote mode, work package 3a - a dev/test preview): a
  Starlette app on uvicorn with `/mcp` (the SDK's Streamable HTTP in stateless mode:
  protocol 2026-07-28 and the legacy sessionless transport), `/health` (liveness) and
  `/ready` (readiness hook for the store). Until OAuth exists `/mcp` requires the static
  bearer token `UEM_DEV_TOKEN` (the server refuses to start without it; `--insecure-local`
  binds loopback only and leaves `/mcp` open) and serves the accounts of a TOML config.
  Operator configuration from the environment (`PORT`, `PUBLIC_URL`, `ALLOWED_HOSTS`,
  `ALLOWED_ORIGINS`, `MAIL_SERVERS`, `LOGIN_DOMAINS`, limits, policy; `docs/operator-env.md`)
  with startup errors naming the variable. Hardening: Host/Origin validation (DNS
  rebinding), request body limit, security headers on non-MCP responses, no CORS,
  generic errors without stack traces, request ids, JSON logs on stdout, graceful
  shutdown. Multi-stage `Dockerfile` (uv, non-root, `PORT`, healthcheck) and `.dockerignore`.
- Store for remote mode (`universal_email_mcp.store`): records for users, mail accounts,
  identities, portal sessions, OAuth clients, authorization codes, grants, access/refresh
  tokens (stored as SHA-256 digests, refresh rotation with replay detection), pending
  approvals and the own-activity feed, with TTLs, optimistic concurrency and GDPR
  `export_user` / `delete_user`. Backends: in-memory and Firestore (extra `gcp`).
  Secrets are sealed with an AES-256-GCM key ring (versioned keys, blobs bound to user,
  record and field, `rotate_keys`). See `docs/stored-data.md`.
- POP3 accounts (`kind = "pop3"`, read-only) in the read tools: `account_info`,
  `list_folders` (INBOX only), `find_messages` (also in one fan-out with IMAP
  accounts), `get_message` (with `thread=true` inside the POP3 inbox),
  `get_attachment`, `find_contacts`, and `save_draft(reply_to_id/forward_id=...)` of a POP3 message (the draft goes to an IMAP account). `mail/pop3.py`: a synchronous POP3 session
  over `mail/net.py` (implicit TLS or mandatory `STLS`, verified, TLS >= 1.2;
  `USER`/`PASS`, or `AUTH PLAIN`), `UIDL` required (message ids are
  `p1.`-prefixed and built from the UIDL, stable across sessions and distinct from
  IMAP ids), headers by pipelined `TOP n 0` under a time budget, newest first and
  cached per account by UIDL (a UIDL diff reads only new mail), search evaluated
  locally on the newest `max_headers_scanned` headers, whole messages by `RETR`
  with a byte cap enforced while reading (oversize messages: `TOP n <lines>`, an
  answer past the cap drops the connection). Never sends `DELE` or `RSET`. No
  read/flagged state (`unread` is `null`), no body search, no download links;
  write tools and `save_draft(draft_id=...)` refuse POP3 ids. Integration tests
  run against the Dovecot container with POP3 enabled (CI now starts the container
  itself instead of as a service, to pass the option).
- Folder map in the server instructions: in `local` mode the folder lists of all
  accounts are read at startup (in parallel, 3 s overall; a slow or unreachable
  account is shown as "not read at startup" and never blocks the server) and the
  instructions show per account the special folders (by role), the top-level
  folders, the number of direct subfolders (`▸ N`) with example names, and the
  archive scheme with its year range. Capped at 30 entries / 1500 characters per
  account, own namespace only, names sanitised and framed as data, not
  instructions. `account_info` returns the current map (text and structured
  `folder_map`), re-reading the folder list.
- `send_message` (identity `send = true`; offered only when the policy is not
  read-only/`off` and an identity can send): sends a saved draft (`draft_id`, re-read
  from the server and re-validated: exactly one From that is a sending identity,
  every To/Cc/Bcc header instance parsed) or a new message (the `save_draft`
  arguments; composed, shown, stored as a draft, then sent). SMTP backend
  (`mail/smtp.py`) over the SSRF-safe connector: implicit TLS or mandatory STARTTLS
  (TLS >= 1.2, verified on the host name, never a plain login), AUTH, SIZE, per-
  recipient refusal aborts before `DATA`, `Bcc` never transmitted, unknown outcome
  after the body is reported and never retried. Recipient check before sending:
  internal / known (sent-to history) / new / look-alike (typos, confusables, `xn--`
  homographs, mixed scripts, other top-level domains - also for addresses that were
  written to before). Policy: `[policy] send` = `off` | `draft` | `confirm` |
  `confirm-external` | `on`, `internal_domains`, `max_sends_per_hour`/`_per_day`,
  `limits.max_send_bytes`; identity keys `save_sent` and `file_replies` (default `both`: the copy of a reply also goes into the user folder the original is filed in).
  The confirmation shows the whole new text (cap 3000 characters / 80 lines, cut parts
  announced with numbers), summarises a quoted original and lists up to 20 attachments.
  `\Answered` needs `organize` or `drafts` on the original's account. The user
  confirms through MCP elicitation (both protocol eras: mid-call request and
  2026-07-28 input-required retry; the question carries a content fingerprint); a
  client that cannot elicit, or a declined confirmation, leaves a draft. After a
  send: copy into Sent and optionally the original's folder, draft removed,
  `\Answered` on the replied-to mail. Audit events (`send.requested`/`confirmed`/
  `declined`/`draft_kept`/`sent`/`failed`) as JSON lines on stderr, counts only.
- Local download links: `universal-email-mcp local` runs a listener on `127.0.0.1`
  (random port, or `[downloads] port`) that streams attachments from IMAP at
  `/a/<token>`. Tokens are HMAC-signed with a per-run key and expire (`link_ttl`,
  default 24 h), so links die with the process. The part is read in ranged chunks
  (own router call each, the account is not locked for the whole download) and
  transfer-decoded incrementally (base64, quoted-printable); `get_message` and
  `get_attachment` now show these links. Served as `attachment` with a sanitised
  file name, passive content types only, `nosniff`, sandbox CSP, `no-store`; `Host`
  checking against DNS rebinding; `GET`/`HEAD` only. Config: `[downloads]`
  (`enabled`, `port`, `link_ttl`, `max_download_bytes`). `get_message` also offers
  a "download .eml" link (`/m/<token>`, the raw message); `account_info` reports
  whether download links are on (and where) or off (and why).
- `save_draft` (permission `drafts`; offered only when an account allows it and the
  policy is not read-only): writes a plain-text draft into the account's Drafts
  folder (`\Draft`, `\Seen`; the new draft's id from `APPENDUID`) and never sends.
  New mail, reply, reply-all (`reply_to_id`, `reply_all`) and forward (`forward_id`;
  attaches the original's files through the verified part lookup, capped by
  `limits.max_attachment_bytes` per file and 10 MiB in total, never local files or
  URLs); `draft_id` replaces a draft: the new version is appended first, then the old
  one removed with `\Deleted` + `UID EXPUNGE` of that one UID, only if it is a
  `\Draft` in the Drafts folder (otherwise, or without UIDPLUS, it is left and the
  result says so). The sender is always a configured identity (explicit `from`, the
  address the original was sent to, an identity of the original's account, the
  default); threading headers come from the original with strict Message-ID syntax
  checks and at most 10 References; recipients are validated, line breaks and control
  characters in headers are refused, the policy's `max_recipients` applies. The result
  previews the draft and warns about a Reply-To to another domain, malformed
  addresses of the original and recipients never written to.
- `move_messages(to="archive")`: files into the account's archive folder (SPECIAL-USE
  `\Archive`, role detection or `folders.archive`). The scheme is detected from the
  archive's subfolders (flat, `YYYY`, `YYYY/MM`, `YYYY-MM`; an empty archive is flat)
  or fixed per account with `archive_scheme`; each message goes to the folder of its
  `Date` header (trusted only if plausible: 1990 or later and not after the arrival date + 1 day; else INTERNALDATE, else now), missing
  year/month folders are created once. No archive folder: `NO_ARCHIVE_FOLDER`.
- `move_messages(with_conversation=true)`: also moves the rest of each message's
  conversation in the same account (INBOX, Sent, the archive and the message's own
  folder; mail filed in other folders is reported as left there, Trash/Junk/Drafts
  never move). Only replies and ancestors of the message are followed - a hostile
  reply cannot pull unrelated mail in. The batch limit counts the whole set.
- `move_messages(dry_run=true)`: lists what would move and where, changes nothing
  (no folders are created either); the result lists the ids to pass to a confirmed
  move, which then searches nothing again.
- `get_attachment`: reads one attachment by the id `get_message` lists. Text-like
  files (text, CSV, JSON, XML, HTML, SVG) come back as fenced, defanged, paged text;
  other files as an embedded resource (base64 blob); files over
  `limits.max_attachment_bytes` (default 2 MiB) are refused with their size. Part
  numbers come from the server's `BODYSTRUCTURE`, so a malformed message (where
  Python's MIME parser and the server disagree) gives the right bytes or a refusal,
  never another part's bytes. Only `BODY.PEEK[n]` is used (no `\Seen`).
- `get_message` lists attachments with their server part id and the real decoded
  size, also when only the beginning of a large message was read (marked `~` as an
  estimate); file names lose path components, control and bidi characters.
- `account_info` returns a cheap overview per account (unread/message counts of INBOX,
  Drafts and Junk, number of folders); `overview=false` skips it.
- `MailService(download_links=...)`: hook for authenticated attachment download
  links (portal in remote mode, loopback listener locally; not built yet). With a
  provider `get_message` lists a link per attachment and `get_attachment` hands out
  a link for files over the cap.
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
- `universal-email-mcp local`: MCP server over stdio (works with Claude Desktop
  and Claude Code via `uvx universal-email-mcp local`) with five read-only tools:
  - `account_info`: accounts, permissions, server features, quota, identities,
    policy and limits.
  - `list_folders`: the top level first, each folder with its role and number of
    direct subfolders; `parent=` drills down (approximate names; ambiguity is
    returned as a choice), `query=` searches all levels, `depth=` (≤ 3) adds
    levels; message/unread counts for the folders shown (at most 50); similar
    names when nothing matches.
  - `find_messages`: time windows (`today`, `this_week`, `last_7_days` …) and
    from/to/subject/body/unread/flagged/attachment criteria as an exact
    server-side search, plus a free-text `query`.
  - `get_message`: fenced, paged body (never marks as read); `thread=true` shows
    the conversation across INBOX, Sent and other folders (archive and folders
    named like the participants first).
  - `find_contacts`: a quick overview of recent correspondents, or with `query`
    a deeper search; `sent_to` (yes / no / unknown) marks addresses you have
    written to in the last two years.
- One `query` parameter for `find_messages`, `list_folders` and `find_contacts`:
  with `*` or `?` a case-insensitive, umlaut-folded wildcard pattern starting at
  a word start (for folders: the folder's own name, or — with `/` — its path,
  where `*` also crosses levels); otherwise fuzzy matching that tolerates typos,
  umlaut spellings and name order.
- Every list result is bounded and its footer says how to narrow it or continue.
- Searches and listings span all accounts in parallel with a per-account
  time-out; failing accounts are reported with the partial result. Cursor
  paging with signed cursors; an account that fails between pages keeps its
  position and is retried.
- Results are Markdown tables (mail text escaped: no links, images, HTML or
  table breakage from crafted subjects) plus structured content with output
  schemas; errors carry a code and a hint.
- Folder names in tools may be approximate and hierarchical
  (`clients/hubr` → `Clients/Huber`); ambiguous names return the choices.
- New limit `max_headers_scanned` (headers read per account for fuzzy search
  and contact lookup).
- Development sandbox: `scripts/dev_mailbox.py` starts a throw-away local
  Dovecot with realistic and hostile mail and a matching config, for trying the
  server without a real mailbox.
- `local` and `probe --account` name the config file they loaded on stderr.
- Organize tools (accounts with the `organize` / `delete` permission):
  - `mark_messages`: read/unread and flagged, by message id.
  - `move_messages`: into another folder (exact name after case/umlaut
    normalisation, unique leaf name, path suffix or role; a typo or an ambiguous
    name changes nothing and returns the candidates). Uses `UID MOVE`; without MOVE it copies,
    flags and `UID EXPUNGE`s exactly the copied UIDs (UIDPLUS); with neither it
    refuses. A plain `EXPUNGE` is never issued. Moved messages get new ids
    (from `COPYUID`), returned in the result.
  - `create_folder`: a folder, nested levels, with correct hierarchy delimiter and
    modified UTF-7 encoding, subscribed after creation; the parent may be
    approximate. An existing folder is reported, not an error. Names are
    validated (no wildcards, quotes, control or invisible characters, `.`/`..`).
  - `delete_messages`: moves to the Trash folder (own tool, `destructiveHint`);
    mail already in Trash is left alone, there is no permanent deletion; an
    account without a recognisable Trash folder refuses.
  - Results are per message (ok / unchanged / failed with a code); stale
    (UIDVALIDITY), forged, unknown or not permitted ids fail individually.
    Tools that no account's permissions allow (or a `read_only` policy) are not
    registered; every call also checks the permission of each message's account.
    Nothing is changed in other users' or shared namespaces.
- New limit `max_batch_messages` (default 50): messages per mark/move/delete call;
  more are refused up front.

### Changed

- Sign-in no longer discards the password: on the first sign-in it is stored (sealed) as the
  credential of the sign-in mailbox account so that the assistant can read that mailbox;
  later sign-ins refresh it when it changed. The sign-in page says so. The consent page no
  longer offers the pseudo account `primary`.

- Defanging of mail text is more complete: bare domains with a well-known top-level domain
  (`evil.com`, also in e-mail addresses) get `[.]` so renderers with fuzzy link detection
  cannot link them, the host after a `word:` scheme prefix is broken up too, and code
  fences in message bodies are neutralised. File names such as `report.pdf` stay readable.
- Fuzzy `find_messages`: a multi-word query also scores sender + subject and
  recipients + subject together (`rechnung huber`), the exact-match boost no longer depends
  on `limit` (scores and paging stay stable), and the flags shown are read fresh.
- Listings flag senders whose name or address mixes alphabets or mimics Latin letters
  (`⚠ look-alike sender`); `probe` prints folder names and server text with control and
  bidi characters escaped; folder names containing a comma are quoted in the folder map.
- A mail server that hangs no longer delays the exit of the process (worker threads are
  daemon threads).
- The conversation search (`get_message(thread=true)`) is limited by a time budget
  (half of `limits.account_timeout`) instead of 25 folders; later rounds look only in
  INBOX, Sent, the archive, the message's folder and folders that had hits.

### Security

- A mail server that trickles bytes (or stalls the TLS handshake) can no longer pin threads
  and starve the instance: sign-in verification, the portal connection tests, SMTP submission,
  client-metadata fetches and connection clean-up no longer use asyncio's shared default
  executor, every connect, test, login check and submission has an absolute deadline
  (`NetPolicy.total_timeout`, 60 s) enforced by a watchdog that shuts the sockets down, and
  idle or forced connection closes abort the socket instead of waiting for a polite LOGOUT.
  Sending no longer holds the sender lock during the SMTP conversation (the rate limit is
  reserved up front and given back when the send certainly did not happen).
- A hostile IMAP server can no longer exhaust memory: a literal above 32 MiB or more than
  64 MiB of untagged data for one command (already in the greeting, before any login) ends the
  connection with a protocol error. Header lists are fetched partially (64 KiB per message).
- After STARTTLS, bytes the server sent before the upgrade are refused (Python 3.14 kept them
  and parsed them as post-TLS responses, which let a man in the middle inject capabilities).
- Hosts that users type in (free entry) are always connected to with public addresses only,
  also when the operator sets `UEM_ALLOW_PRIVATE_NETWORKS`: the accounts carry the rule, so it
  holds for every later connection and send, not only for the portal test. Site-local IPv6
  (`fec0::/10`) is no longer treated as public.
- Re-authentication for sensitive portal actions and for granting `send`; connection tests
  to user-named servers use the SSRF-safe connector (public addresses only, mail ports only,
  verified TLS) and are rate limited; passwords with line breaks or NUL are refused.

- Message bodies are defanged, not only fenced: images become `[image: alt]`,
  links `text (hxxps[:]//…)`, HTML tags and reference-link definitions are
  neutralised; HTML mail no longer yields Markdown links.
- Table cells also defang autolinks without a word boundary (`_https://…`),
  e-mail addresses (`＠`) and scheme prefixes (`mailto:`, `xmpp:` …); error
  results carry details only as structured content.
- Variation selectors U+E0100–E01EF (and a few more invisible format characters)
  are stripped from mail text.

- Hostile mail can no longer take the server or a listing down: header, body and folder-name
  decoders never raise and never return a lone UTF-16 surrogate (UTF-7 such as `+2D0-` killed
  the stdio server's JSON writer); an unusable charset (`undefined`, NUL, bytes-to-bytes
  codecs) falls back to UTF-8 / Windows-1252; one message whose headers cannot be handled is
  shown as a marked placeholder (`[unreadable message: ...]`, id kept, so it can still be moved
  or deleted) instead of dropping its account from the listing; a malformed MIME parameter
  (`name*0*`) leaves the message readable (the bare content type is kept, the stdlib's lenient
  policy is the fallback); MIME bombs (tens of thousands of delimiter lines) are refused before
  the stdlib parser sees them; header values are capped before RFC 2047 decoding and
  `References` is deduplicated in linear time.
- HTML nested deeper than the parser keeps (libxml2 silently drops everything below ~255
  levels) is converted by stripping tags, with a note, instead of hiding the text from the reader.
- The send confirmation and the portal approval page identify the original of a reply or
  forward (sender, date, subject, first lines), say "FORWARDED MESSAGE" for forwards and warn
  when the subject is not `Re:` / `Fwd:` plus the original's subject. The portal only folds a
  quote the server verified against the message in the mailbox (`In-Reply-To`); text the
  model wrote that merely looks like a quote is shown as ordinary text and never described as
  "not written by the application".
- Free text in the confirmation prompt (subject, display names, file names, notes) is escaped
  for Markdown, and `＠` / `﹫` in display names are neutralised like `@`.
- `save_draft`'s structured `quoted` is fenced and defanged like `get_message` bodies.
- Defanging also breaks protocol-relative links (`//host/path`) and compatibility forms
  (fullwidth `ｈｔｔｐｓ://`, `https‥//`).
- File names: Unicode blanks (Braille blank, NBSP, em space ...) collapse to one space and long
  names are shortened in the middle, so a run of blanks cannot hide `.exe` behind `.pdf`.
- The raw-headers page labels authentication / spam headers that are not above the first
  `Received` line as "from the sender, not checked" and renders raw 8-bit header bytes.
- Listing items cap subject, address and reference counts and lengths in structured output.

### Fixed

- A connection that broke while a write (flag change, move, append, folder creation) was in
  flight is no longer retried on a new connection, which could have applied it twice (an
  APPEND duplicated the message); the error says to check the result first. The move fallback
  (COPY + UID EXPUNGE) no longer withdraws a `\\Deleted` mark that another client had set on
  a message before.
- The quoted-printable download decoder is linear on endless whitespace (16 MB took 17 s) and
  both transfer decoders run in a worker thread instead of on the event loop.
- A timed-out account no longer blocks the server until the read time-out, and
  retries against a stalling server share one connection attempt.
- Paging no longer skips messages deleted between pages; cursors stop retrying
  persistently failing accounts after three pages.
- `has_attachment` also finds attachments in signed, related and report mail
  (results marked approximate); listings show current flags; conversations are
  in arrival order; shared folders do not get special roles; deeply nested MIME
  is reported as unparseable.
- `get_message(thread=true)`: a message that copies another's Message-ID no
  longer displaces it from the conversation. Messages that share a Message-ID
  are all kept unless they are identical copies in one account (same size,
  sender, subject, Date, In-Reply-To and References); up to five per id are
  shown (the message asked about, else the earliest arrival, first). The search
  reads a fixed number of headers, shared fairly between the folders it searches
  (both ends of each folder's matches), and each round searches only new ids.
  Only messages linked through the message asked about and each Message-ID's
  first claimant (in any account) stay in the conversation — decided after the
  search, so a forgery cannot keep conversations it pulled in. When the limit
  cuts, later claimants go first, then the oldest messages, but the message
  asked about and what it replies to stay. Shared ids are marked
  (`⚠ same Message-ID`, `shared_message_id`) with short notes, also when a
  claimant is not shown. Conversation tables show the arrival time instead of
  the Date header.
- `get_message` shows every inline text part in order (Apple Mail text–image–text,
  hidden extra parts), each after a `──── part N (…) ────` line that mail text
  cannot imitate at a line start, HTML parts converted, report parts
  (`message/delivery-status` and similar, read from the original bytes with
  base64 / quoted-printable undone) as text; body source
  `mixed` when plain and HTML parts are combined. Text parts beyond the limits
  (100 parts, the HTML size budget) are listed as attachments, the attachment list
  is capped at 100, and notes say what was left out.

## [0.0.1] - 2026-09-30

### Added

- Project skeleton, license (Apache-2.0), CI and release workflow.
- Design plan: `docs/plans/2026-09-30-design.md`.
- Placeholder release to register the package name on PyPI. Not functional yet.

[Unreleased]: https://github.com/arjoma/universal-email-mcp/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/arjoma/universal-email-mcp/releases/tag/v0.0.1
