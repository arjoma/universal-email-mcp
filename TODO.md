# TODO

Open items by area, most important first, then ideas parked for after 0.1.0 (see
`docs/plans/2026-09-30-design.md` for the v1 scope and `docs/plans/2026-10-09-roadmap.md`
for the order). Every item was checked against the code on 2026-10-09. Compact this file
from time to time (AGENTS.md, "Regular cleanup").

## Before 0.1.0 (security or correctness)

- [ ] Dependabot does not read `cloudbuild.yaml` or the CI emulator image (digests are bumped by
      hand).

- [ ] `ImapLoginVerifier` semaphore wait has no timeout (16 tarpits hold sign-ins up to
      `total_timeout`); the first write after a server-side idle drop now fails instead of
      reconnecting (could be softened with a NOOP probe before the first write).
- [ ] `oauth/fetch.py` docstring still says "call it through asyncio.to_thread".
- [ ] `build_html_view` (viewer) still runs on asyncio's default executor. It is CPU only
      and has no network I/O, but a pathological message can occupy a worker; give it a
      bounded executor of its own.
- [ ] `getaddrinfo` in `net.resolve_checked` is not covered by the `Deadline` (the libc
      resolver timeouts apply; a hostile authoritative DNS server can stall one worker thread
      for that long). `run_deadline` abandons the thread after `GRACE`.
- [ ] Run `deploy/gcp` against a real project once (see Deployment) and correct the docs.
- [ ] Try SMTP against a real server and fill `ServerProfile.smtp_saves_sent`; check the
      archive scheme of the united-domains hoster with `probe` (see Send, IMAP).
- [ ] Sign-in brute force is limited per instance only (see Rate limits). Documented for 0.1.0
      (operator-env.md, admin guide: run one or two instances, lower the sign-in limits); the
      shared counter is not built.

## Local mode / read tools

- [ ] Review leftovers of the pre-release hardening: day windows assume the server's INTERNALDATE
      zone and the user's zone differ by under a day (`_trim_to_days` could search two days
      each side) and use a fixed-offset zone (no DST test); `flags_agree` leaves `total`/cursor
      counting dropped hits without a note; activity rows written before the `label` field show
      no account name (not migrated, pre-release); a removed account whose name contains `@`
      gets no label; `form_action_extra` of `Portal.page`/`security_headers` is unused now; the
      Dovecot test of hostile login names only proves "clean AUTH_FAILED" (the wire test proves
      the quoting) and the window test relies on the container counting days in UTC.
- [ ] Time windows use the server's local zone as a fixed offset taken from "now": a window
      that reaches back over a DST change is one hour off at its start; remote mode has no
      per-user zone yet (a portal setting could supply one). `flags_agree` drops a hit whose fresh
      flags contradict `unread`/`flagged` but `total` still counts it.
- [ ] Bare-domain defanging uses the TLD allow-list `render._TLDS`, a rare TLD slips through.
- [ ] Cursor resume after the last returned message was expunged falls back to UID order
      (`_resume_index`), only approximate for SORT (REVERSE ARRIVAL) listings.
- [ ] Look-alike senders: listings flag mixed-script names, but fuzzy search still ranks a
      look-alike domain like the original and does not compare with known contacts; use
      `recipients.skeleton` in the contact ranking.
- [ ] `search_related` reads the first 30 ids only (`MAX_RELATED_IDS`); the same mail in two
      accounts is listed twice (marked as sharing a Message-ID).
- [ ] `list_folders(counts=True)` hit the account time-out once on a slow Dovecot start in CI
      (capped at `MAX_STATUS` = 50 folders); drop this item if CI stays green.
- [ ] `folder_list.build` (`count`, `order`, `walk`) recurses per level; a tree thousands of
      levels deep raises `RecursionError` (startup survives as "not read"). Make it iterative or cap
      the depth.
- [ ] Dev mode (`UEM_DEV_TOKEN`) still serves TOML accounts and logs no tool calls; drop it when
      the portal and the sandbox can stand in.
- [ ] Sandbox corpus: add very long folder names (injection text and bidi names exist:
      `HOSTILE_FOLDER`, `BIDI_FOLDER`).

## IMAP and mail parsing

- [ ] Threads: the earliest INTERNALDATE decides which claimant of a shared Message-ID owns it
      (`_owners`); a forgery that arrived first (or was APPENDed with an old date) wins. Members
      that share a Message-ID with a kept mail but differ are moved with a conversation if they
      reply to it; only the dry-run list protects.
- [ ] Threads: a flood of fake replies with distinct ids fills the newest part of `limit`, and
      floods in all searched folders (`MIN_THREAD_SHARE` headers each) can use up the header budget
      before older ancestors are reached.
- [ ] Conversation search is bounded (header budget, `THREAD_TIME_SHARE` = 0.5 of
      `account_timeout`, not configurable) and same-account only; later rounds search INBOX, Sent,
      the archive, the message's folder and folders with hits. Members of a given message in a
      custom folder move along only from its own folder (+ INBOX/Sent/archive).
- [ ] Report parts (`message/delivery-status` …) are read from the original bytes only when the
      MIME structure is well-formed (`mime._report_text`); otherwise QP soft breaks can be lost.
- [ ] No `UNSELECT`/`CLOSE` after a write: the session stays selected on the last folder.
- [ ] Other users'/shared namespaces are refused for every write; `is_foreign` is tested with
      injected prefixes only (the Dovecot image has none).
- [ ] Archive: `archive_scheme = auto` treats an empty archive as flat and is fooled by a single
      year-named folder; month boundary uses the server host's time zone (an `archive_timezone`
      setting could follow); a non-selectable container is not used.

## Organize (write side)

- [ ] COPY fallback: a copy that worked while removing the original failed leaves the message in
      both folders (reported per message; `\Deleted` rolled back best-effort). A connection lost
      mid-batch leaves the running group's outcome unknown; the batch is retried, so a MOVE that
      went through is then reported "not in folder any more" instead of "may have been applied".
- [ ] A dry run and the real run search separately; pinned only by passing the listed ids to a
      plain move (instructions say so, not enforced).
- [ ] `mark_messages` sets `\Seen`/`\Flagged` only; `$Forwarded` after a forward could follow
      (`\Answered` is set by `send_message`; it needs `organize` or `drafts` on the original's
      account).
- [ ] The sent-to index is not invalidated when mail leaves Sent (intended).
- [ ] Not offered by design: permanent deletion (would need its own tool, permission and
      confirmation), moving between accounts (would need APPEND), folder rename/move/delete
      (only `create_folder` exists).

## Drafts

- [ ] `draft_id` replaces the whole draft: attachments of a forward draft are lost unless
      `forward_id` is passed again, `Bcc` is not carried over, the body cannot be patched
      (`drafts._load_old` reads only to/cc/from/subject/references). Read the old draft's parts via
      the verified part lookup.
- [ ] Plain text only: no HTML alternative (signature, formatting), no `format=flowed`.
- [ ] Reply sender selection looks at the original's To/Cc only (`Delivered-To`,
      `X-Original-To`, list aliases are not read). The original of a plain `draft_id` reply is
      searched in at most 25 folders / 10 s of the store account (`FIND_ORIGINAL_*`).
- [ ] Forwarding: inline images are dropped (warning); inner attachments of a forwarded
      `message/rfc822` are not offered individually; text attachments travel as base64 bytes;
      `message/*` other than rfc822 becomes `octet-stream`.
- [ ] Message-IDs of unusual syntax are dropped from `References` (`compose.valid_msgid`).
- [ ] The quote's attribution line uses UTC (`compose._when`); use the user's zone and language.
- [ ] The "never written to" note (`drafts._recipient_note`) runs one Sent search per save; cache
      or skip it for repeated updates of the same draft.
- [ ] `max_recipients` also caps to+cc+bcc of a draft; a mailing-list draft needs the limit raised.

## Send

- [ ] Try it against a real SMTP server (united-domains hoster: 465/587, STARTTLS, AUTH, SIZE,
      whether it files its own Sent copy; `smtp_saves_sent` is `False` for every preset until
      probe evidence exists). `probe` has no SMTP check yet; add one (EHLO, STARTTLS, AUTH, SIZE).
- [ ] An identity without a store account cannot send (`send.py` skips it); decide the fallback
      "send without copies, noted in the confirmation".
- [ ] Look-alike detection compares with the Sent history of the store account only (up to
      `HISTORY_UPDATE_HEADERS` = 3000 newest, 2 years); contacts seen only in INBOX are not
      "known". The confusables table is small (Cyrillic, Greek, a few Latin), not TR39; local
      parts shorter than 3 are not compared. The sent-to index does not read Bcc, so Bcc recipients
      stay "never written to" (the Sent copy keeps its `Bcc` header).
- [ ] `confirm-external` / `internal_domains` match whole domains exactly (subdomain handling is
      only in `allowed_recipient_domains`).
- [ ] SMTPUTF8 (non-ASCII local parts) is refused; 8-bit bodies need `8BITMIME`; the EHLO name
      is the fixed `localhost`.
- [ ] A hard policy refusal leaves nothing stored (the caller must `save_draft` again); a failure
      after the draft was stored names its id in the hint.
- [ ] Local mode: the in-memory rate limit and sent-Message-ID guard are lost on restart; a send
      whose draft could not be removed (no UIDPLUS) can be sent again after a restart.
- [ ] `SendOut.attachments` reports file names and sizes only (no content types);
      `SendOut.account` shows the generated outgoing account (`smtp:i_...`) instead of the identity
      address.

## POP3

- [ ] No attachment download links in the local loopback listener (the portal viewer reads the
      whole message under `max_message_bytes`); a local link needs the same RETR + parse.
- [ ] The header cache (`Pop3State`) lives in process memory; a persistent one (remote mode)
      would avoid re-reading `TOP` after every restart.
- [ ] A mailbox above `max_headers_scanned` (2000) is searched only in its newest part; no "deep"
      mode or background warm-up.
- [ ] No APOP or SASL other than `PLAIN` (TLS is mandatory). Arrival time is the topmost
      `Received` header (forgeable `Date` as fallback). A mailbox locked by another session
      fails with a clear error but is not retried.

## Remote: OAuth and per-user service

- [ ] Refresh-token reuse is strict: a second use of a rotated token (also two concurrent
      refreshes) revokes the grant; a short reuse interval may be needed once real clients are seen.
- [ ] `/token` refresh grant is limited per network only (not per client or grant); `/mcp` requests
      with a bad or missing token are not limited per network (store lookup per attempt).
- [ ] CIMD fetch (`oauth/fetch.py`): the deadline starts after connect/TLS and every resolved
      address is tried (N x 5 s); fetches and IMAP logins share the default thread pool and
      `login_slots` is released on timeout while the thread runs on. Give both a bounded executor
      and an overall deadline; the portal `LiveTester` (semaphore 8, 45 s) has the same issue.
- [ ] `busy` is detected by message text (`"Too many requests" in str(e)`, `endpoints.py`); HTML
      routes return JSON 500 on store errors (`http.py` registers 404/405 handlers only).
- [ ] The IMAP login assumes the mail server maps logins 1:1 to mailboxes (user id derivation);
      document it in `docs/operator-env.md`. Re-authentication compares the lower-cased
      `User.primary_address`; keep the typed login name on the user record.
- [ ] Consent is per request: a reconnecting client shows up twice in "Connected applications".
      No incremental consent (`WWW-Authenticate` `scope=` on 403) and no "you already allowed this".
- [ ] DCR: no RFC 7592 management, no software statements, only `none` token auth. CIMD documents
      are cached a fixed hour (`cimd_cache_ttl` not an env variable) without conditional requests;
      no allow/deny list for client-id hosts and no trusted-client list (to skip "name not verified").
- [ ] Portal sessions are not bound to IP or user agent; no CAPTCHA or MFA (MFA comes with OIDC SSO).
- [ ] `/mcp` POST reads the user's accounts and identities (two store queries) to compare versions
      (`UserPool.acquire`); with Firestore add a short per-grant cache or a version counter.
- [ ] Connection pool and caps (`UEM_MAX_CONNECTIONS_PER_USER`, `call_slot`) are per grant /
      per process, `BUSY` is never queued; there is no instance-wide cap on parallel calls/threads.
- [ ] A saved account's host is not re-checked against `MAIL_SERVERS` at connect time (the SSRF
      guards of `mail/net.py` always apply).
- [ ] Folder map is read on `initialize`/`server/discover` only (clients that skip discovery never
      see instructions) and re-read after `MAPS_TTL` (10 min); `ensure_instructions` is not
      single-flight and runs outside `call_slot`.
- [ ] `UserPool` leftovers: non-granted identities linked to a drafts-capable account are usable
      for drafts (decide); `records` keeps decrypted passwords for the context lifetime (slim
      projection); concurrent `acquire` can install an older fingerprint; a failure mark/clear bumps
      the account version and rebuilds all contexts (leave failure fields out of the fingerprint).
- [ ] Never set `cache_hints` with public scope (per-user responses); no test fails if someone does.
- [ ] Remote `save_draft` needs an identity linked to a drafts-capable account; a grant without
      one cannot draft (the portal creates the pair for IMAP accounts, the error says so).

## Remote send (approvals)

- [ ] `execute` stores the composed draft before the fallback, so repeated identical asks leave
      duplicate drafts and a rejected/expired approval leaves its draft (by design); consider a
      cleanup hint for drafts older than the TTL. `approved` but unconsumed approvals (crash
      between two store writes) cannot be retried.
- [ ] The replay guard (`Store.claim_send`) holds `user + content hash` for 10 minutes: the same
      text to the same recipients cannot be sent twice on purpose in that time.
- [ ] The approvals list shows application and time only; a short summary (subject, first
      recipient) could be cached in the sealed part of the record. An approval stores the draft as
      `account / folder / UID`; renaming the account or a UIDVALIDITY change makes it "gone".
      The quote is folded only when verified against the original (`split_verified_quote`).

## Portal

- [ ] Show `MailAccount.needs_reauth` as a warning on the accounts page (nothing in `portal/`
      reads it yet).
- [ ] Custom (free-entry) servers take a host name only on ports 993 / 995 / 465. Later:
      autodiscovery (ISPDB, autoconfig, RFC 6186), STARTTLS/other ports behind an operator switch,
      a separate SMTP host, separate SMTP logins (identity credentials are copies of the account's).
- [ ] No account rename; no "allowed only for this client" pre-selection from the scope the
      client asked for. `/authorize` ignores `ui_locales`.
- [ ] A half-filled identity form is lost when the re-authentication redirect happens.
- [ ] Removing an account revokes every client that references it (even ones with other accounts);
      removing credentials or changing the password at the provider does not end portal sessions.
- [ ] Multi-record writes (remove account/identity, first-sign-in migration) are not atomic;
      account/identity limits and unique names are check-then-create; `identity_save` /
      `remove_*` repeat store reads; add-account / password-change tests do not count against the
      sign-in lockout; no test for `identity_test` rate limiting.
- [ ] Viewer: `?images=1` is a plain GET toggle (use a nonce); the HTML is sanitised twice
      (message page and iframe route); sign-in redirect drops the query string; foreign-account 404
      differs in timing; no test for cancellation during a download or for a limited content-origin
      frame; `HEAD` opens IMAP and counts a hit; the HTML frame and its page count as two requests.
- [ ] Viewer account names: the viewer context names accounts in creation order, a grant's
      context in grant order; they differ for names `_account_name` rewrites (invalid characters,
      duplicates), so ids may not resolve. Put the account id in the message id or share one
      naming function.
- [ ] Dead field `Row.checked` (consent rows, always empty): drop it and the template condition.
- [ ] Privacy page: the export needs no fresh password (delete does); `delete_user` failing midway
      logs nothing; sessions row shows "-" (`build_export` counts them); `duration_view` rounds
      odd seconds down; make the `user_id` export drop an explicit constant; tests for a write
      racing the delete and casefold edge cases.

- [ ] German leftovers (4d): file sizes still show a decimal point (`1.5 KB`, `fmt_size` is shared
      with the tool output); service-generated notes that no pattern in `portal/dynamic.py`
      covers stay English (reviewer list: lookalike "you have written to this address and to", compose.py malformed-address and Reply-To warnings, "not attached (<error>)", oversized-message and MIME-mismatch body notes, thread/conversation notes incl. STOPPED_RETRYING, POP3 notes; thread search budget notes, lookalike "you have written to ... and to"
      sentence, `body_notes` variants, folder/quota notes); the plain-text `Not found.` /
      `Too many requests.` answers of the content origin are not translated (no UI).

## Store

- [ ] Expired records can still be `update`d; transactions read one by one (no `get_all`); a
      pseudonym-key change needs a user-id migration. `Store.create_owned` guards the writes of
      requests in flight (activity, approvals, send claims, grants, codes, sessions); the portal's
      own creates (accounts, identities) are not guarded, and `UserPool` contexts of a deleted
      user are only forgotten by the portal (`forget_user`), not retired in other instances.
- [ ] `admin rotate-keys` has no `--check` mode listing the key ids still in use (a dry run only
      counts what would be re-sealed); only records that need rotation are tested for
      readability, a damaged record sealed with the active key is not found by it.
- [ ] Merged feed writes cost create + get + update after the first call of the hour (try
      get-then-update first); a feed write is awaited inside the request (bounded by 3 s) and
      parallel merged writes of one entry contend (emulator: ~25 s for four racing calls).

## Audit and activity feed

- [ ] Not in the user's feed: failed sign-ins (only for existing users), refresh-token reuse and
      code replay (no user in the event), rate-limit hits. A disconnect cannot name the application
      (store the client name with `portal.grant_revoke`).
- [ ] `auth.sign_in ok` and `portal.*` events carry no `ip`; no `session` id in events.
- [ ] `tool.call` is audited in OAuth mode only (local mode logs `send.*`, dev mode nothing).
- [ ] `audit` state (key, feed sink) is module-global: one app per process; multi-instance
      deployments need the same `PSEUDONYM_KEY`. The local `audit.key` has no rotation command.
- [ ] `audit` CLI: no BigQuery sink or gzip input; a pretty-printed multi-line JSON object counts
      as malformed; `--user` cannot find users logged with another key.

## Rate limits

- [ ] All `UEM_*` limiters (sign-in per address and IP, token, registration, CIMD fetch, tool
      calls) are in memory per instance: N instances allow N times the limit (sign-in brute force:
      N x 5 guesses per 15 minutes), a restart resets them; only the send limit is in the store.
      A shared counter, most worth it for sign-in / re-authentication. The per-address limit also
      lets an attacker lock a known address out for 15 minutes; no per-login-domain cap (the mail
      server may ban the egress IP; document whitelisting).
- [ ] Send counting (`remote_send.check_rate`) lists the user's whole activity feed and runs
      twice per send (prepare and deliver); the activity page and `list_activity` also load the
      whole feed (page: latest 200). Use an indexed `event` query or a counter record per
      window; two instances can overshoot by one.
- [ ] Tool-call limits count calls, not cost; every refused call writes a `ratelimit.hit` audit
      line (not coalesced), so a client ignoring `retry_after` can fill the log.
- [ ] Limiter details: eviction is insertion-order; a burst above the sustained limit is not
      flagged at startup; `Limiters.from_config` could be generated from the `RateLimits` fields;
      `PortalEndpoints._hit` could take the limiter instead of a `kind` string; no test of
      `RATE_LIMITED` over the stateless protocol (check `tests/integration/test_rate_limits.py`).

## Deployment

- [ ] Nothing in `deploy/gcp` was run against a real project: the first pilot verifies
      `bootstrap.sh` flags (`--enable-pitr`, `--delete-protection`, TTL commands), the build service
      account's permissions, the `invoker-iam-disabled` annotation, probes and
      `UEM_TRUSTED_PROXY_HOPS` behind a load balancer, then corrects `docs/deploy-gcp.md`
      (its checklist repeats this).
- [ ] Not-ready after SIGTERM (`ready` runs only `ready_checks`) and exit status 143 (uvicorn
      re-raises SIGTERM; harmless on Cloud Run). No Cloud Build trigger from CI.
- [ ] `Host` matching is exact (no `*.run.app`); list each name.
- [ ] Single-VM deployment: a `docker-compose.yml` makes no sense with the memory store; do it
      together with the SQLite store.

## Admin tooling (gaps the docs describe)

- [ ] `universal-email-mcp admin` commands: revoke all grants of a user or of a client, delete a
      user (`Store.delete_user`), list a user's records, print the full user id of an address.
      Today an incident needs manual Firestore edits and a one-off Python job
      (`docs/admin-guide.md`, section 11).
- [ ] Deny list for OAuth clients (a client identified by a metadata URL can be authorised again
      after its grants were deleted) and a per-user block (deny sign-in without changing `LOGIN_DOMAINS`).
- [ ] Pseudonym key rotation: users are keyed by `HMAC(PSEUDONYM_KEY, address)`; a migration
      (re-key users and their records, keep logs matchable) does not exist.
- [ ] Access requests: the portal export does not contain the user's log lines; the operator uses
      `audit --user`. Consider a documented export of those lines.
- [ ] Portal second factor: sign-in reuses the mailbox password only (`docs/dpia-template.md`, R10).
- [ ] Client matrix: the connection steps in `docs/user-guide.md` are generic; verify and add
      client-specific steps (Claude.ai, Claude Desktop, ChatGPT) when the matrix (design section 12)
      has been run against a real deployment.
- [ ] Docs commands that use `uvx universal-email-mcp` only work after the first PyPI release
      (0.0.1 is a placeholder); re-check them at 0.1.0.

## Docs / process

- [ ] Tag ruleset `v*` (restrict create/update/delete, bypass: repository admin) before adding
      collaborators, so only admins can trigger PyPI releases (the `pypi` environment is already
      restricted to `v*` tags); check with `gh api repos/arjoma/universal-email-mcp/rulesets`.
- [ ] Client matrix: measure how Claude Code, Claude Desktop and claude.ai handle embedded blob
      resources and image content; tune `limits.max_attachment_bytes` (2 MiB).

## Later (not v1)

### Attachments
- [ ] IMAP `BINARY.PEEK[n]` for exact downloads of 8bit/binary parts (plain `BODY[n]` may
      normalise NUL and LF).
- [ ] Attachments of a forwarded `message/rfc822` addressable individually (sections `2.1`, `2.2`);
      `get_attachment` by file name; `──── part N` labels follow the parser's numbering, which can
      differ from the server's on malformed messages.
- [ ] Base64 attachment sizes are estimated (76-column wrapping) unless the message was read fully.
- [ ] Recent-mail / top-sender digest in `account_info`'s overview.
- [ ] Read attachments: PDF text (pypdf), office formats, images via the client; bounded
      extraction (page/char limits, timeouts, zip-bomb guards); attachment-aware search and summaries.

### Accounts, platform and targets
- [ ] OIDC SSO for the portal; admin-managed shared mailboxes; OAUTHBEARER / XOAUTH2.
- [ ] SQLite store for single-VM / on-prem (a `Backend`: `get`, atomic `commit`, `find`, `scan`;
      contract tests in `tests/test_store.py`); JMAP backend.
- [ ] More provider presets (only `united-domains` exists: IONOS, Strato, World4You, Hetzner,
      all-inkl, …), each validated with `probe`.
- [ ] Folder management: rename / move / delete / unsubscribe.
- [ ] Message viewer: "all attachments as ZIP" (streaming zip over `iter_part`), `Content-Length`
      for base64/QP downloads (chunked today), text beyond `limits.max_body_chars` (the page points
      to the `.eml`), a decoded (RFC 2047) toggle for the raw header view.

## Mail content (review of fix/mail-content)

- [ ] A reply/forward whose subject does not match the original is only a warning in the
      confirmation; consider making it a reason that forces confirmation.
- [ ] `Sender._verify_quote` scans folders and fetches the original on every approval page load:
      compute it once when the approval is created (or cache by draft ref + In-Reply-To).
- [ ] `defang`: ideographic full stop (`。`) in host names is not treated like `.`.
- [ ] `mail/outgoing.py` (`get_filename`, `get_content_type`) still uses unguarded stdlib calls on
      stored drafts; a malformed MIME parameter makes preparing that draft fail.
- [ ] The placeholder summary subject (`[unreadable message: ...]`) can be imitated by a sender;
      a dedicated flag on `MessageSummary` would be cleaner.
- [ ] Authentication headers added by milters below the first `Received` line are labelled
      "from the sender, not checked" (conservative).

