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
- [ ] Archive action like the webmailer's (probably `Archive/<year>` — verify with `probe`).
- [ ] Move mail between folders, incl. "move the mail from X and my answer to client X".
- [ ] File replies: the Sent copy of a reply goes into the conversation's folder too.
- [ ] Label management: list (tree) and create first; rename / move / delete folders later.
- [ ] Message viewer (M3, design §6.2): links from the chat to the full mail, thread,
      raw headers, `.eml` and attachment downloads in the authenticated portal.

## WP 2b (folders as labels) — conversation search
- [ ] `get_message(thread=true)` searches at most 25 folders (special folders,
      archive and folders named like the participants first; the rest are listed
      as skipped). Restructure: a time budget instead of a folder count, and later
      rounds only in folders that had hits.

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
