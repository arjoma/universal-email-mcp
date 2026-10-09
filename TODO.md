# TODO

Open items by milestone / work package, then ideas parked for after 0.1.0 (see
`docs/plans/2026-09-30-design.md` for the v1 scope and `docs/plans/2026-10-09-roadmap.md`
for the order). Compact this file from time to time (AGENTS.md, "Regular cleanup").

## Open work

### 3i Deployment: for the first real pilot
- [ ] Nothing in `deploy/gcp` was run against a real project (no cloud calls in CI): the
      first pilot verifies `bootstrap.sh` flags (`--enable-pitr`, `--delete-protection`,
      TTL commands), the build service account's permissions, the
      `invoker-iam-disabled` annotation, the probes and `UEM_TRUSTED_PROXY_HOPS` behind a load
      balancer, then corrects the docs.
- [ ] Add `universal-email-mcp admin rotate-keys` (the guide uses a small Cloud Run job with
      `python -c`) and a `--check` mode that reports the key ids still in use.
- [ ] Single-VM deployment: a `docker-compose.yml` is pointless with the memory store (all
      accounts lost on restart); do it together with the SQLite store.

### M1 read tools: review leftovers and sandbox findings
- [ ] Time windows: `today`/`this_week` are computed in the local time zone, but IMAP
      `SINCE`/`BEFORE` compare the server's INTERNALDATE day (the zone stored with the
      message), so mail near midnight can fall into the neighbouring day. A fix needs
      the search widened by a day plus a client-side filter on `received` in both
      `list_messages` (which pages by server position) and `query_search`; do it once a
      real mailbox shows the effect (step 2h).
- [ ] Fuzzy results: `unread`/`flagged` filters apply to the cached flags, while the
      flags shown are read fresh, so a shown hit can contradict the filter; the
      bare-domain defanging uses a TLD allow-list (`render._TLDS`), a rare TLD slips through.
- [ ] Cursor resume when the last returned message was expunged falls back to UID
      order, which is only approximate for SORT (REVERSE ARRIVAL) listings.
- [ ] Threads: `search_related` uses the first 30 ids only (most relevant first);
      the same mail in two accounts is listed twice and marked as sharing a
      Message-ID (identical copies are merged within an account only).
- [ ] Watch CI for flakiness of `list_folders(counts=True)` on a slow Dovecot start (it
      hit the account time-out once; counts are capped at 50 folders per call).

- [ ] Threads: arrival order (INTERNALDATE) decides which claimant of a shared
      Message-ID owns it (is followed, kept first); a forgery that arrived before
      the genuine mail (or was APPENDed with an old date) wins, and any fetched
      message competes, also one reached only through another claimant's links.
- [ ] Threads: a flood of fake replies with distinct ids still fills the newest
      part of the shown `limit` (the message and what it replies to stay; the
      note counts the cut), and floods in all searched folders (each gets at least
      `MIN_THREAD_SHARE` headers per round) can use up the header budget before
      later rounds reach older ancestors.
- [ ] Report parts (`message/delivery-status` …) are read from the original bytes
      only when the MIME structure is well-formed; otherwise from Python's
      re-serialised blocks (QP soft breaks across the inserted blank line can be
      lost there).
- [ ] Look-alike senders (listings now flag mixed-script and Latin-mimicking names and
      addresses): a fuzzy search for a real contact still ranks a look-alike domain
      or homoglyph name as high as the original, and listings do not compare against
      known contacts (that is the send-time check in 2d). Rank/flag using the
      confusables skeleton of `service/recipients.py`.

### WP 2a (organize)
- [ ] Permanent deletion (empty Trash, delete from Trash/Junk) is deliberately not
      offered; if ever added it needs its own tool, permission and confirmation.
- [ ] `mark_messages` sets only `\Seen` and `\Flagged` (`\Answered` is set by
      `send_message` only); custom keywords are not planned, `$Forwarded` after a forward could follow.
- [ ] Folder management beyond `create_folder` (rename, move, delete, unsubscribe).
- [ ] Moving between accounts is not supported (an id belongs to one account; the
      destination is resolved per account). Copy-to-other-account would need APPEND.
- [ ] Other users'/shared namespaces are refused for every write; the Dovecot test
      image has none, so `is_foreign` is tested with injected prefixes only.
- [ ] COPY fallback: if the copy worked but removing the original failed, the message
      is in both folders (reported per message, the `\Deleted` flag is rolled back
      on a best-effort basis). A connection lost mid-batch leaves the outcome of the
      running group unknown (hint: search again before retrying).
- [ ] The sent-to index is not invalidated when mail leaves Sent (moving a sent mail
      away does not forget that the user wrote to the recipient - intended, but
      deleting the Sent copy does not make the check stricter either).
- [ ] No `UNSELECT`/`CLOSE` after a write: the session stays selected on the last
      folder until the next EXAMINE/SELECT (harmless, but a pending `\Deleted` set
      by another client is never expunged by us).
- [ ] Sandbox corpus: hostile *folder* names exist (bidi override); add injection text
      and very long names so `create_folder`/`move_messages` can be tried by hand.

### WP 2b (folders as labels)
- [ ] **Check the archive scheme against real `probe` output** of the united-domains
      hoster (and what its webmail's "archive" button does: flat, `Archive/2025`,
      `Archive/2025/10`?). Until then `auto` treats an empty archive as flat and
      `archive_scheme` has to be set by hand; also verify that its webmail files by the `Date` header.
- [ ] The archive month boundary uses the server host's time zone
      (an `archive_timezone` setting could follow). Auto-detection is fooled by a
      single year-named folder (`Archive/2024` for a project): set `archive_scheme`.
      A non-selectable year/month container is not used (the create then fails).
- [ ] Conversation moves are same-account only and bounded by the thread search
      (header budget, time budget): a very long or old conversation can be incomplete
      (the dry-run list shows what was found). Later search rounds look only in
      INBOX, Sent, the archive, the message's folder and folders with hits, so an
      ancestor in an unrelated, hit-less folder is not found.
- [ ] Conversation members of a *given* message in a custom folder move along only
      from that message's own folder (plus INBOX/Sent/archive tree); a configurable
      list of "label" groups that always move could follow.
- [ ] Members that share a Message-ID with a kept mail but differ (forgeries) are
      moved if they reply to the conversation; only the dry-run list protects against
      moving a hostile reply (it is a reply in that conversation by its own claim).
- [ ] After a lost connection the batch is retried; a MOVE that did go through is
      then reported "not in folder any more" instead of "may have been applied".
- [ ] A dry run and the real run search separately: pinned by passing the listed ids
      to a plain move (instructions and dry-run footer say so); not enforced.
- [ ] The time budget of the conversation search is a share of `account_timeout`
      (`THREAD_TIME_SHARE`), not configurable.

### WP 2c (drafts)
- [ ] Plain text only. An HTML alternative (signature with a logo, formatting) and
      `format=flowed` are out of scope for now.
- [ ] `draft_id` replaces the whole draft: attachments of a forward draft are lost
      unless `forward_id` is passed again, `Bcc` is not carried over, and the body
      cannot be patched. Read the old draft's parts (verified part lookup) and keep
      its attachments when the update names none.
- [ ] Sender selection for replies looks at the original's To/Cc only; `Delivered-To`,
      `X-Original-To` and list aliases are not read (the summary does not carry them).
- [ ] Inline images of a forwarded mail are dropped (reported as a warning); the inner
      attachments of a forwarded `message/rfc822` are not offered individually.
- [ ] Forwarded text attachments keep their declared type but travel as base64
      bytes (no charset guessing); `message/*` other than `rfc822` becomes `octet-stream`.
- [ ] Message-IDs of unusual syntax in an original are dropped from `References`
      (the thread link is lost rather than risking odd bytes in a header).
- [ ] The quote's attribution line uses UTC; use the user's time zone and language.
- [ ] The "never written to" note runs one Sent search per save; cache or skip it for
      repeated updates of the same draft.
- [ ] Drafts: `max_recipients` of the policy also caps to+cc+bcc of a draft; a draft
      for a mailing list with more recipients needs the limit raised.

### WP 2d (send)
- [ ] **Try it against a real SMTP server** (the united-domains hoster: 465/587, STARTTLS,
      AUTH mechanisms, SIZE, whether it files its own Sent copy -> `ServerProfile.smtp_saves_sent`
      is `False` for every preset until probe evidence exists) with a throw-away recipient.
      `probe` has no SMTP check yet.
- [ ] An identity without a store account cannot send (the draft is the safety net and the
      Sent copy needs a place); the design allows "send without copies, noted in the
      confirmation". Needs a decision on the fallback when confirmation is impossible.
- [x] Remote mode (3f): sealing, binding and the `SEND_FALLBACK` modes are done (see WP 3f).
- [ ] The in-memory rate limit and sent-Message-ID guard stay in local mode (lost on restart);
      remote mode counts in the store (WP 3f). A send whose draft could not be removed (no
      UIDPLUS) can be sent again after a restart in local mode.
- [ ] Look-alike detection compares with the Sent history of the store account only (up to
      3000 newest Sent headers read per check, 2 years): contacts only seen in INBOX are
      not "known" and not compared. The confusables table is small (Cyrillic, Greek, a few
      Latin letters), no full Unicode TR39 skeleton; short local parts (< 3) are not compared.
- [ ] `confirm-external` / `internal_domains` match whole domains exactly (no wildcard);
      subdomain handling is only in `allowed_recipient_domains`.
- [ ] SMTPUTF8 (non-ASCII local parts, also in drafts) is refused; 8-bit bodies need the server's 8BITMIME.
      The EHLO name is the fixed `localhost`.
- [ ] `\Answered` needs `organize` or `drafts` on the original's account; a forward does not set `$Forwarded`.
      The original of a plain `draft_id` reply is searched in at most 25 folders / 10 s of the
      store account (INBOX first); one in another account is not found.
- [ ] The Sent copy keeps the `Bcc` header (the user's own record); the Sent-to index does not
      read Bcc, so Bcc recipients stay "never written to" for later checks.
- [ ] A hard policy refusal (allowed domains, limits) leaves nothing stored: the caller must
      call `save_draft` again to keep the text. A failure after the draft was stored names its id
      in the error hint.
- [ ] `SendOut.attachments` reports no content types (file names and sizes only).

### WP 3f (send in remote mode)
- [ ] Sends per hour/day are counted from the user's activity entries (`event == "send"`,
      read as a whole list per check): fine for a feed of hundreds, but a counter record per
      user and window (or a Firestore count query) is needed before heavy use; two instances
      can overshoot by one. (3h writes no second `send` entry: the audit pipeline skips `send.sent`.)
- [ ] The replay guard (`Store.claim_send`) keeps `user + content hash` for 10 minutes, so the
      same text to the same recipients cannot be sent twice within that time on purpose.
      A replayed confirmation of a *new* message still leaves one extra copy of the draft in
      Drafts (the draft is stored before the claim fails).
- [ ] `SendOut.account` names the identity's generated outgoing account (`smtp:i_...`), which
      means nothing to a user; show the identity address instead.
- [ ] The approvals list shows application and time only (the mail data needs an IMAP read
      per entry); a short summary (subject, first recipient) could be cached in the sealed
      part of the record if users find the list too bare.
- [ ] `split_quoted` for the portal page is heuristic (a trailing `>` block); the quoted
      original is folded, never hidden, because a hostile draft could imitate a quote.
- [ ] An approval stores the draft as `account name / folder / UID` (opaque id); renaming the
      account or a changed UIDVALIDITY makes it "gone" (the page says so, nothing is sent).
- [ ] No per-user/IP rate limit on the approvals page and its re-authentication beyond the
      password checks of sign-in (M4 rate limits).
- [ ] `send_message` in remote mode always saves the composed text as a draft before the
      question; a rejected, expired or unanswered approval leaves it in Drafts (by design,
      nothing is lost) - consider a cleanup hint in the result for drafts older than the TTL.

- [ ] (review of 3f) `execute` stores the composed draft before the fallback, so repeated
      identical asks leave duplicate drafts; `approved` but unconsumed approvals (crash between
      the two store writes) cannot be retried; the rate limit scans the whole activity feed twice
      per send.

### POP3
- [ ] No download links for POP3 attachments in the *local* loopback listener (it reads
      IMAP sections); the portal viewer handles POP3 by reading the whole message under
      `limits.max_message_bytes`. A local link would need the same RETR + parse.
- [ ] POP3 header cache lives in process memory only; a persistent cache (remote mode,
      store) would avoid re-reading `TOP` for the newest N after every restart.
- [ ] POP3 `APOP` and SASL mechanisms other than `PLAIN` are not implemented (TLS is
      mandatory, so `USER`/`PASS` is as safe as the rest).
- [ ] A POP3 mailbox with more than `max_headers_scanned` messages is searched only in
      its newest part; an optional "deep" mode (more headers per call, background
      warm-up of the cache) is not built.
- [ ] POP3 arrival time is the topmost `Received` header (no INTERNALDATE); a mail
      server that adds none leaves the (forgeable) `Date` header as the only date.
- [ ] POP3 servers that lock the mailbox per session: a reconnect while another client
      holds the lock fails with a clear error but is not retried.

### WP 3e (per-user service)
- [ ] Every `/mcp` POST reads the user's accounts and identities (two store queries) to compare
      record versions with the cached service. Fine for the memory backend; with Firestore add
      a short (seconds) per-grant cache or a version counter on the user record. Revocation of
      the token itself is still checked on every request.
- [ ] Connection pool is per grant: two clients of one user hold separate connections to the same
      mailbox (bounded by `UEM_MAX_CONNECTIONS_PER_USER`). Sharing routers per (user, account
      version) would halve that but needs per-grant permission checks outside the router.
- [ ] Caps are per process, in memory; several instances multiply them. Tool-call rate limits
      per user/token (M4) are not there; `BUSY` is returned, never queued.
- [ ] A saved account's host is not re-checked against `MAIL_SERVERS` at connect time (the
      portal checks on entry; the SSRF guards of `mail/net.py` always apply). Removing a server
      from `MAIL_SERVERS` does not disable existing accounts.
- [ ] The folder map is read on `initialize`/`server/discover` only (clients pinned to 2026-07-28
      that skip discovery never see instructions) and re-read after 10 minutes; a first
      `initialize` after idle eviction waits up to 3 s for slow mail servers.
- [ ] `REAUTH_REQUIRED` marks the account for any `AuthFailed` (also "LOGINDISABLED" and servers
      that answer a throttled login with NO); the portal (3d) should show the flag
      (`MailAccount.needs_reauth`) and clear it when the password is re-entered (it clears
      itself because the flag is tied to the failed login).
- [ ] Remote `save_draft` needs an identity linked to a drafts-capable account; a grant without
      any such identity cannot draft (the error says so). 3d should create the identity/account
      pair in one step (design section 5).
- [ ] Review leftovers of 3e: (a) identities not granted but linked to a drafts-capable account
      are usable for drafts (From can be a non-granted identity; never sent) - decide whether drafts
      should need the identity grant; (b) `records` keeps decrypted passwords for the context
      lifetime (slim projection possible); (c) concurrent `acquire` can install an older
      fingerprint over a newer one (one extra rebuild); (d) a failure mark/clear bumps the account
      version and rebuilds all of the user's contexts (leave failure fields out of the
      fingerprint); (e) `ensure_instructions` is not single-flight and runs outside `call_slot`;
      (f) no instance-wide cap on parallel calls/worker threads; (g) cursor key falls back to a
      random per-process key without `PSEUDONYM_KEY` (cursors break across instances); (h) the SDK
      seams (`__class__` swap of the lowlevel server, `list_tools`/`call_tool` overrides) need a
      canary on SDK upgrades; never set `cache_hints` with public scope (per-user responses).

### Folder map
- [ ] `folder_list.build` recurses per level (fine for real mailboxes; a folder tree
      thousands of levels deep would raise `RecursionError`, which the startup path
      survives as "not read").

### Portal (3d follow-ups)
- [ ] Custom (free-entry) servers take a host name only, on the standard TLS ports 993 / 995 /
      465. Later: autodiscovery (Thunderbird ISPDB, autoconfig, RFC 6186) to prefill, STARTTLS
      and other ports behind an operator switch, a separate SMTP host.
- [ ] Not yet in the portal (M4 list): activity page, privacy page (export / delete
      everything), pending approvals (3f), a rename for accounts, an "allowed only for this
      client" pre-selection from the scope the client asked for on the account page.
- [ ] Re-authentication re-checks `User.primary_address` (lower-cased) against the login
      server; a server that treats the login name case-sensitively would refuse a user who
      signed in with different capitalisation. Keep the typed login name on the user record.
- [ ] A half-filled identity form is lost when the re-authentication redirect happens (the
      add-account form asks for the password first, so nothing is lost there). Carrying the
      non-secret fields through the redirect would fix it.
- [ ] Removing an account revokes every client that references it, even ones that also use
      other accounts; reducing those grants instead may be friendlier (the spec of 3d said
      revoke).
- [ ] Removing the stored credentials does not end portal sessions, and a password change at
      the provider is only noticed at the next sign-in or connection test (3e reports
      `reauth_required` per call).
- [ ] The `LiveTester` runs blocking connections in the default thread pool (bounded by a
      semaphore of 8 and a 45 s deadline; the socket threads continue after a timeout until
      their own socket timeout). Same executor issue as the CIMD fetch and IMAP login item
      of 3c (a).
- [ ] German comes with M4 (the switch appears once a second catalog exists);
      `/authorize` ignores `ui_locales`.
- [ ] Identity SMTP credentials are copies of the account's login (kept current on password
      change). Separate SMTP logins (different user name or password) are not offered yet.

- [ ] Review leftovers of 3d: add-account / password-change tests do not count against the
      sign-in lockout of the guessed mailbox (they have their own limits: per user, per IP, per
      user and target); multi-record writes (remove account/identity, first-sign-in migration)
      are not atomic - a crash can leave a half state (migration is retried only while
      `primary_done` is unset); account/identity limits and unique names are check-then-create
      (concurrent POSTs can exceed them); `identity_save`/`remove_*` repeat store reads that a
      small helper could share; no test for `identity_test` rate limiting.

### Remote HTTP and store (3a-3c follow-ups)
- [ ] Refresh-token reuse is strict: any second use of a rotated token (also two truly
      concurrent refreshes, e.g. a client retrying after a lost response) revokes the whole
      grant. A short configurable reuse interval (return the same successor for a few
      seconds) may be needed once real clients are observed.
- [ ] Rate limiters (sign-in per address and IP, token, registration, client-document
      fetch) are in memory per instance: N instances allow N times the limit, a restart
      resets them. A shared counter in the store would fix it. The per-address limit also
      lets an attacker lock a known address out of sign-in for 15 minutes.
- [ ] Consent is per request: every authorization creates a new grant, so a client that
      reconnects shows up twice in "Connected applications" (the user disconnects the old
      one). Replacing the older grant of the same client and user was left out on purpose:
      two devices of one user that use the same client would then disconnect each other in
      turn. Needs a per-device notion or a "you already allowed this" shortcut.
- [ ] Re-consent / scope step-up: a refresh cannot widen the scope; a client needing more
      must run `/authorize` again. Incremental consent (`WWW-Authenticate` `scope=` on 403)
      is not implemented.
- [ ] DCR: no `/register` management (RFC 7592), no software statements; a client asking for
      `client_secret_*` or non-`none` auth is refused. CIMD documents are cached for a fixed
      hour (HTTP cache headers are ignored) and fetched without a conditional request.
- [ ] CIMD: only `https` documents on any port; there is no operator allow/deny list of client
      hosts, and no display of a verified publisher. A trusted-client list (e.g. for the
      Claude and ChatGPT connector identities) could skip the "name not verified" hint.
- [ ] Portal sessions are not bound to IP or user agent; sign-in has no CAPTCHA or MFA
      (MFA comes with OIDC SSO). A password change at the mail server does not end existing
      portal sessions or grants until their lifetime ends.
- [ ] Review leftovers of 3c: (a) CIMD fetch: the deadline starts after connect/TLS and every
      resolved address is tried (N x 5 s); fetches and IMAP logins share the default thread
      pool and the login semaphore is released on timeout while the thread runs on - give
      them their own bounded executor and an overall deadline; (b) rate limits key IPv6 by
      full address (use /64) and failed sign-ins have no global cap per login domain (the
      mail server may ban the egress IP; document whitelisting); (c) and (d) are done in 3d (CORS for the cookie-less
      endpoints; `send` needs a fresh password); (e) the
      consent redirect after Allow crosses CSP `form-action` per hop (a callback that
      redirects on to another origin is blocked in Chromium); answer with a 200 page that
      continues via meta refresh; (f) reject repeated request parameters; `busy` error
      detected by message text; HTML routes return JSON 500 on store errors; (g) login
      hardening: quote the IMAP user name (CR/LF/NUL in passwords are refused since 3d); the user id assumes
      the mail server maps logins 1:1 to mailboxes (document); (h) a refresh with a narrower
      `scope` still returns the full scope; (i) dead code: `login_profile`,
      `RateLimiter.retry_after`, `Row.checked`; huge `UEM_*_TTL` values overflow at startup;
      `--config` is silently ignored in OAuth mode.

- [ ] Dev mode still serves the TOML accounts (a development aid next to the per-user
      service; drop it once the portal and the sandbox can stand in).
      `OperatorConfig.mail_servers` is parsed but unused until 3d.
- [ ] Consider reporting not-ready after SIGTERM.
- [ ] No per-IP/per-token rate limiting on `/mcp` (M4 rate limits); 3e caps parallel calls and
      connections per user, not calls per minute.
- [ ] uvicorn re-raises SIGTERM after the graceful stop, so the process exits with status 143
      instead of 0 (harmless on Cloud Run). No CI image build yet (3i `cloudbuild.yaml`).
- [ ] `Host` matching is exact on names (no wildcards such as `*.run.app`); list each name.

- [ ] Store review leftovers: `rotate_keys`/`export_user` abort on one corrupt record
      (skip and report); expired records can still be `update`d; `delete_user` is not
      atomic against concurrent writes (tombstone); transactions read one by one
      (`get_all`); portal session touch/reauth methods. A pseudonym-key change needs a
      user-id migration.

## Later (not v1)

### Attachments
- [ ] Measure how Claude Code, Claude Desktop and claude.ai handle embedded blob
      resources and image content (part of the client matrix) and tune the default
      `limits.max_attachment_bytes` (now 2 MiB).
- [ ] Downloads of 8bit/binary parts with NUL bytes or bare LF: plain `BODY[n]`
      fetches may normalise them (Dovecot turns NUL into 0x80, LF into CRLF); the IMAP
      `BINARY` extension (`BINARY.PEEK[n]`) would deliver them exactly.
- [ ] Attachments of a forwarded `message/rfc822` are not addressable individually
      (the whole .eml is one attachment); inner parts would be sections `2.1`, `2.2` …
- [ ] `get_attachment` for ids is by section only; no lookup by file name. The
      `──── part N` labels in bodies still use the parser's numbering, which can
      differ from the server's on malformed messages (attachment ids never do).
- [ ] Attachment sizes of base64 parts are exact only when the message was read
      completely; otherwise estimated from the encoded size (76-column wrapping assumed).
- [ ] Overview: no recent-mail or top-sender digest per account (the old
      `mailbox_overview` idea); `find_contacts` and `find_messages` cover it.
- [ ] Read and make sense of attachments: PDF text extraction (pypdf), then
      office formats (docx, xlsx, odt), images via the AI client (embedded resource).
- [ ] Bounded extraction (page/char limits, timeouts, zip-bomb/resource guards).
- [ ] Attachment-aware search ("the PDF invoice from Huber") and summaries.

### Accounts, platform and targets from real use
- [ ] OIDC SSO for the portal (Entra ID, Keycloak, Authentik, Google, …).
- [ ] Admin-managed shared mailboxes granted to several users.
- [ ] OAUTHBEARER / XOAUTH2 to mail servers that offer it (Microsoft 365 only on demand).
- [ ] SQLite store for single-VM / on-prem deployments (a `Backend` implementation:
      `get`, atomic `commit`, `find`, `scan`; the contract tests in `tests/test_store.py` apply).
- [ ] Store wiring after WP 3a: `STORE_KEYS` / `STORE_ACTIVE_KEY` / backend choice in the
      operator config, `universal-email-mcp admin rotate-keys` (calls `store.rotate_keys`).
- [ ] Store: activity feed is listed by a per-user query sorted in Python (no composite
      index); fine for 30 days of events, add `order_by` + index or a per-user cap if feeds grow.
- [ ] More provider presets (IONOS, Strato, World4You, Hetzner, all-inkl, …),
      each validated with `probe`.
- [ ] JMAP backend.
- [ ] Fuzzy matching of hierarchical folders used as labels (`Clients/<name>`, any group).
- [ ] Label management: rename / move / delete folders later (list and create exist).
- [ ] Message viewer follow-ups (3g shipped the core): "all attachments as ZIP" (needs a
      streaming zip writer over `iter_part`); `Content-Length` for base64/QP downloads
      (responses are chunked); message text beyond `limits.max_body_chars` (the page says to
      take the `.eml`); a per-user rate limit for viewer requests (only the parallel-call cap
      applies); a decoded (RFC 2047) toggle for the raw header view.
- [ ] Viewer review leftovers (minor): `?images=1` is a plain GET toggle (a mail link to
      it would pre-click for a user who knows the id: use a nonce); the message page
      sanitises the HTML once for the counts and the iframe route again (cache briefly);
      sign-in redirect drops the query string (`?view=html`); `/c/<token>` addresses appear
      in access logs (two minute lifetime; keep them out of logs); the oracle-free 404 still
      differs in timing for foreign accounts; no test for cancellation during a download.
- [ ] Viewer account names: the viewer context names accounts in creation order while a
      grant's context uses the grant's order; they only differ for names the pool rewrites
      (invalid characters -> "Account N", duplicate names -> "(2)"). Message ids of such
      accounts may not resolve in the viewer; store the account id in the id (or enforce the
      same naming in the portal) when it matters.

### Repository
- [ ] Before adding collaborators: tag ruleset `v*` (restrict create/update/delete,
      bypass: repository admin) so only admins can trigger PyPI releases. The `pypi`
      environment is already restricted to `v*` tags.

### WP 3h (audit log and activity feed)
- [ ] `universal-email-mcp audit` CLI (M4): summarise Cloud Logging per pseudonymous user
      (`--user alice@...` recomputes the pseudonym from `PSEUDONYM_KEY`), counts per tool, failed
      sign-ins; optional BigQuery sink.
- [ ] Not in the user's feed yet: failed sign-ins (a record per arbitrary address would be a
      write-amplification hole; needs "only for existing users"), refresh-token reuse and
      authorization-code replay (the event has no user; look the grant up), rate-limit hits.
      They are in the log and in the suggested alerts.
- [ ] A disconnect ("You disconnected ...") cannot name the application afterwards because the
      grant is gone; store the client name label with `portal.grant_revoke`.
- [ ] Activity page: latest 200 entries only (no paging, filter or export); `list_activity`
      still loads and decrypts the whole feed of the user (and `check_rate` the same for the
      send limit). Reads are merged per hour, but a counter record per window / an indexed
      `event` field would remove the scan.
- [ ] A feed write is awaited inside the request (bounded by 3 s); on Firestore that is one
      round trip per tool call. Batch or hand it to a background task if latency shows up.
      Parallel merged writes of one entry contend (Firestore emulator: ~25 s for four racing
      calls through retries); real Firestore is expected to be faster, measure it.
- [ ] `tool.call` is audited in OAuth mode only: local mode logs `send.*` (no user), dev mode
      (`UEM_DEV_TOKEN`) logs no tool calls at all.
- [ ] `auth.sign_in ok` and `portal.*` events carry no `ip` (only failures and rate-limit hits
      do, with `AUDIT_LOG_CLIENT_IP`); there is no `session` id in events.
- [ ] Local per-install key (`audit.key` in the state directory): no rotation; deleting it
      changes all pseudonyms (documented behaviour, but there is no command for it).

