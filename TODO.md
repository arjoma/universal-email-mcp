# TODO — later (not v1)

Ideas parked for after 0.1.0. See `docs/plans/2026-09-30-design.md` for the v1 scope.

## Attachments
- [ ] Measure how Claude Code, Claude Desktop and claude.ai handle embedded blob
      resources and image content (part of the client matrix) and tune the default
      `limits.max_attachment_bytes` (now 2 MiB).
- [ ] Portal download endpoint (3g): the same streaming (`service/downloads.py`:
      `open_part` / `iter_part`) behind a portal session instead of a per-run token.
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

## Accounts and auth
- [ ] OIDC SSO for the portal (Entra ID, Keycloak, Authentik, Google, …).
- [ ] Admin-managed shared mailboxes granted to several users.
- [ ] OAUTHBEARER / XOAUTH2 to mail servers that offer it (Microsoft 365 only on demand).

## Platform
- [ ] SQLite store for single-VM / on-prem deployments.
- [ ] More provider presets (IONOS, Strato, World4You, Hetzner, all-inkl, …),
      each validated with `probe`.
- [ ] JMAP backend.

## Repository
- [ ] Before adding collaborators: tag ruleset `v*` (restrict create/update/delete,
      bypass: repository admin) so only admins can trigger PyPI releases. The `pypi`
      environment is already restricted to `v*` tags.

## Targets from real use (planned for M2, see design §7.2)
- [ ] Fuzzy matching of hierarchical folders used as labels (`Clients/<name>`, any group).
- [ ] File replies: the Sent copy of a reply goes into the conversation's folder too (2d).
- [ ] Label management: rename / move / delete folders later (list and create exist).
- [ ] Message viewer (M3, design §6.2): links from the chat to the full mail, thread,
      raw headers, `.eml` and attachment downloads in the authenticated portal.

## WP 2b (folders as labels) leftovers
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

## Tool surface review leftovers (PR #7)
- [ ] Fuzzy message score keys can shift between pages: the exact-match boost
      covers only the first `limit*4` UIDs, and `limit` is not in the argument hash.
- [ ] `list_messages` could reuse `paging.keyset_page` for its retry logic.
- [ ] A fuzzy `query` is scored per header text (sender, recipients, subject
      separately), so words spread over several fields ("rechnung huber") do not
      add up — consider scoring the combined text too.
- [ ] WP 2d look-alike check must handle "the user really wrote to a typo
      address" (`sent_to=true` for `oliver.grnat@`).

## WP 2a (organize) leftovers
- [ ] Permanent deletion (empty Trash, delete from Trash/Junk) is deliberately not
      offered; if ever added it needs its own tool, permission and confirmation.
- [ ] `mark_messages` sets only `\Seen` and `\Flagged`; `\Answered` is for the
      reply/send work (2c/2d), custom keywords are not planned.
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
- [ ] Sandbox corpus: add hostile *folder* names (injection text, bidi, very long)
      so `create_folder`/`move_messages` can be tried by hand against them.

## M1 review leftovers
- [ ] Time windows: `today`/`this_week` are computed in the local time zone, but IMAP
      `SINCE`/`BEFORE` compare the server's INTERNALDATE day (server time zone) —
      mail near midnight can fall into the neighbouring day.
- [ ] Fuzzy search results show flags from the header cache (up to the index TTL);
      listings and threads refresh them.
- [ ] Bare domains (`evil.com`, no scheme/`www.`/path) stay as they are: GFM does not
      autolink them, but renderers with fuzzy linkify (markdown-it) do.
- [ ] Cursor resume when the last returned message was expunged falls back to UID
      order, which is only approximate for SORT (REVERSE ARRIVAL) listings.
- [ ] Threads: `search_related` uses the first 30 ids only (most relevant first);
      the same mail in two accounts is listed twice and marked as sharing a
      Message-ID (identical copies are merged within an account only).
- [ ] Observed once: an integration `list_folders(counts=True)` call (then: STATUS of
      every folder) hit the account time-out on a slow container start — counts are
      now capped at 50 folders per call; watch for flakiness in CI.

## Known issues from the sandbox corpus
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
- [ ] Look-alike senders are hard to spot: tables show only the display name, and a
      fuzzy search for a real contact ranks a look-alike domain or a homoglyph
      name (Cyrillic letters) as high as the original. Flag mixed scripts and
      look-alike domains (also needed for the send-time recipient check).
- [ ] `probe` prints folder names to the terminal unsanitised (bidi overrides;
      other servers may allow terminal escape sequences).
- [ ] Defanging of folder names is uneven (`http\[:\]attacker.test` keeps the
      dots); a fake code fence in a body is left as is.

## WP 2c (drafts) leftovers
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
- [ ] Non-ASCII local parts (SMTPUTF8) are refused; domains are IDNA-encoded.
- [ ] Message-IDs of unusual syntax in an original are dropped from `References`
      (the thread link is lost rather than risking odd bytes in a header).
- [ ] The quote's attribution line uses UTC; use the user's time zone and language.
- [ ] `\Answered` on the original is set only when the reply is sent (WP 2d).
- [ ] The "never written to" note runs one Sent search per save; cache or skip it for
      repeated updates of the same draft.
- [ ] Drafts: `max_recipients` of the policy also caps to+cc+bcc of a draft; a draft
      for a mailing list with more recipients needs the limit raised.
