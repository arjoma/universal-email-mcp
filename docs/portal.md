# The user portal (remote mode)

The portal is where people manage what AI clients may do with their mail: `PUBLIC_URL/portal`.
It is part of OAuth mode (see [oauth.md](oauth.md) for the OAuth flow, [operator-env.md](operator-env.md)
for the variables, [stored-data.md](stored-data.md) for what is stored). Pages are plain
server-rendered HTML: no scripts, no third-party assets, every form works without JavaScript.

## Signing in

`/portal/signin` takes the user's mailbox address and password and checks them with an IMAP
login against the server the operator assigned to the address's domain (`LOGIN_DOMAINS`) -
never a server the user names. The same sign-in serves the OAuth consent step: whoever is
signed in at `/authorize` is signed in at the portal and vice versa. Sessions are
`__Host-` cookies, 30 minutes idle / 12 hours absolute by default.

Signing in **only verifies the password**. The sign-in form (portal and OAuth) has an opt-in
checkbox, pre-ticked: "Use this mailbox with AI clients (stores the password encrypted)".
Only when it is ticked is the sign-in mailbox turned into a real account named "Main" (IMAP,
the login server, the typed password sealed in the store) plus a sender identity with the
same address when the server has a submission endpoint. Unticked, nothing is stored (no
account, no identity, no sealed password) and the user can add the mailbox later under
Accounts, or tick the box at a later sign-in. The form cannot know the user before the address
is typed, so the box is always shown and pre-ticked; it only has an effect while the user has
no "Main". If "Main" exists, every sign-in keeps its stored password current if it changed at
the provider, ticked or not. A user who removes "Main" does not get it back by signing in
(ticked or not); they can add the mailbox again like any other account. With nothing stored,
the OAuth consent page says no mail account is connected yet and links to the portal; a grant
can only name existing accounts, so the user denies or adds an account first. (Before the portal, the consent page offered
a pseudo account `primary`; grants that still reference it are rewritten to "Main" at the
owner's next sign-in that creates "Main", i.e. when the box is ticked; until then they are inert.)

## Mail accounts

| Action | What happens |
|---|---|
| **Add** | name, protocol (IMAP or POP3), user name, password, and the permissions applications may get at most. The server comes from `MAIL_SERVERS`: one entry = fixed (nothing to choose), several = a list, none = the user types a host name. The login is **tested before anything is stored**; a failing test shows a short reason and stores nothing. |
| **Test** | logs in again (IMAP/POP3) and, if the server has a submission endpoint, checks the SMTP login too (nothing is sent). Shows the server's capabilities (`MOVE`, `UIDPLUS`, ...). |
| **Permissions** | `read`, `organize` (mark, move, create folders), `delete` (move to Trash), `drafts`. They are the **upper bound** for every connected client: a client gets at most what the account allows *and* what the user ticks at consent *and* what the operator's policy offers. POP3 accounts are read-only; a read-only deployment (`UEM_READ_ONLY`) offers reading only. Lowering is free, raising asks for the password. |
| **Password** | for when it changed at the provider: checked, then stored; sender identities that copied the login follow. |
| **Remove** | deletes the credentials, removes the identities that send through the account, and disconnects every client that could use it. Mail is untouched. |

Free entry (only when `MAIL_SERVERS` is empty) is guarded like every outbound connection to a
user-named host: the name is resolved once, **every** address must be public (no private,
loopback, link-local, CGNAT or metadata ranges, also not embedded in IPv6), the socket
connects to the checked address, TLS is verified for the host name, only the ports 993 / 995 /
465 / 587 are allowed, and IP literals and bare names are refused. Free-entry accounts are
**always public-only**, also when the operator sets `UEM_ALLOW_PRIVATE_NETWORKS` (the accounts
remember this, so the check applies to every later connection, not only to the portal test).
Servers listed by the operator are trusted (any port; private addresses only with
`UEM_ALLOW_PRIVATE_NETWORKS`).

Connection tests open outbound connections and try logins, so they are rate limited (by default 10 per
user and 10 minutes, 30 per IP, 5 per target mailbox and 15 minutes). Every portal POST is
also limited per user and per network, message pages per user, and raw/attachment downloads
per user; a refused request gets a translated 429 page with `Retry-After`. Re-authentication
is a password check: wrong entries count against the same per-address and per-IP limits as
sign-in. All values: [operator-env.md](operator-env.md#rate-limits). Nothing the server says
is shown - only a fixed reason: rejected login, not reachable, certificate/TLS problem,
address not allowed, features missing, timeout, unexpected answer.

## Sender identities

An identity is an address that drafts and sent mail come from: address, display name,
signature, the account whose server and login send the mail ("sending account": SMTP host,
user name and password are copied from it and kept current), the IMAP account that keeps
drafts and sent copies, a default flag, and **sending allowed**. Allowing sending needs the
password, a sending account, an IMAP account with the `drafts` permission, and a deployment
whose send policy is not `off`. Addresses and display names are validated like the TOML
config does (no line breaks or control characters, no `=?`, quotes or angle brackets in
names); the signature is plain text. Exactly one identity is the default. The identity page
has a "test the sending login" button.

## Connected applications

Lists every AI client the user authorized: its name (escaped, cleaned of control and bidi
characters), where it is identified (host of the metadata document, or "self-registered, name
not verified"), when it connected, when it was last used, when its access ends unless used
again, and what it may use. A client can be **disconnected** (tokens stop working at once)
or **reduced**: permissions and identities can be taken away, never added (to give more,
disconnect and connect again). A client that reconnects creates a second entry; the older one
can be disconnected.

## Pending approvals

`/portal/approvals` lists the sends that an application wanted to make but could not ask the
user about (the client has no elicitation, or the operator's `SEND_FALLBACK` always asks in the
portal; see [oauth.md](oauth.md)). Each entry stays for `UEM_APPROVAL_TTL` (10 minutes by
default) and then shows as **expired**. The page of one entry re-reads the draft from the
mailbox, through the same per-user service the application uses, and shows what would be sent:

* the sender (and which identity), **every recipient with its class** (internal, written to
  before, **NEW**, **LOOK-ALIKE**) and the recipient check's warnings, Bcc marked as hidden;
* the subject, the attachments (names and sizes; a count of the ones not listed),
* the whole **new text** under the same truncation rules as the elicitation prompt (3000
  characters / 80 lines, the rest announced with numbers, never silently); links are defanged,
  control and bidi characters removed, everything is HTML-escaped. The original of a
  reply or forward is named (sender, date, subject; "forwarded message" for forwards), with a
  warning when the subject is not `Re:` / `Fwd:` plus the original's subject. The quote of a
  reply is folded into a `<details>` block (collapsed, never dropped) only when the server
  verified it against the message in the mailbox; anything else is shown as ordinary text.

If the draft has an HTML version that differs from the plain text (or there is no plain
text), its text is shown under its own heading too, with the same cut notices; remote images in
it (tracking pixels) are warned about, and a plain text cut at 300000 characters is announced.
The elicitation prompt of local mode shows the same.

If the draft has an HTML version that differs from the plain text (or there is no plain
text), its text is shown under its own heading too, with the same cut notices; remote images in
it (tracking pixels) are warned about, and a plain text cut at 300000 characters is announced.
The elicitation prompt of local mode shows the same.

**Send this message** needs the CSRF token and a password entry within `UEM_REAUTH_WINDOW`
(otherwise the user is taken to `/portal/reauth` and back to the page). It sends **exactly the
stored draft**: the page compares the draft's content hash with the one stored in the
approval, and a draft that was replaced or edited in the meantime (or removed) is refused
("ask the application to create it again"). The approval is decided once and consumed
(`take`), so a double click or a second tab cannot send twice; afterwards the Sent copy, the
thread-folder copy (`file_replies`), the draft removal and `\Answered` happen as in local mode.
**Reject** leaves the draft in Drafts and needs no password. An approval of another user is a
404 for everyone else; approvals whose application was disconnected are void.

## Re-authentication

Typing the password again (checked live against the login server) opens a window of
`UEM_REAUTH_WINDOW` seconds (default 300). Signing in counts. Needed for: opening or
submitting the add-account form, removing an account, changing an account's password, raising
an account's permissions, allowing an identity to send, **approving a pending send**, and **granting `send` to a client
at the consent page**. When the window is over the user is sent to `/portal/reauth` and back;
nothing secret is carried along (a half-filled form is lost, never a password).
Wrong passwords count against the same limits as sign-in (5 failures per address and 15
minutes).

## Message viewer

Every message in a tool result of remote mode carries a link into the portal,
`PUBLIC_URL/m/<message id>`, and every attachment and the `.eml` have one too
(`/m/<id>/a/<part>`, `/m/<id>/eml`). The user clicks it in the chat and sees the mail in the
browser without opening a mail client. The links contain **no token**: opening one needs a
portal session (a signed-out visitor is sent to sign-in and comes back to the message), and
the message must belong to one of the **signed-in user's own accounts** that grants `read`.

| Page | Content |
|---|---|
| `/m/<id>` | from / to / cc / reply-to / date / account, the text body, the attachment list with a download link each. `?view=html` shows the formatted (HTML) version in a sandbox (below). |
| `/m/<id>/thread` | the conversation, oldest first, each message expandable (text of up to 25 messages; more are linked). |
| `/m/<id>/headers` | every header line as the server delivers it, with the authentication results (`Authentication-Results`, `Received-SPF`, ...) first. |
| `/m/<id>/eml` | the raw RFC 822 message as a download. |
| `/m/<id>/a/<part>` | one attachment, streamed from the mail server. |

**Ownership.** The id names an account by the name its owner gave it. It is resolved inside a
per-user context that holds only that user's accounts (from the store, by user id) with the
`read` permission, so another user's id, a removed account, a forged id with a guessed account
name and an unreadable account all end in the same "cannot be shown" page (404) as a message
that was deleted - ids cannot be probed. A forged id that happens to name an account the user
also has can only ever reach the user's own mail.

**Nothing is marked as read.** The folder is opened read-only and bodies are fetched with
`BODY.PEEK`.

**HTML mail in a sandbox.** Mail HTML is attacker-controlled. It is shown only in an `iframe`
with `sandbox="allow-popups allow-popups-to-escape-sandbox"` (no scripts, no same-origin) whose
document comes from a separate route with its own CSP:

* `default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none';
  form-action 'none'; frame-ancestors <the portal>; sandbox ...` - no script, frame, font,
  media, connection or form source at all.
* The HTML is cleaned with an allow-list sanitizer (`nh3`, the Python binding of the Rust
  `ammonia` library): only formatting, table and image tags; no `script`, `style`, `link`,
  `meta`, `base`, `form`, `iframe`, `object`, `svg`; no event handlers, `class` or `id`;
  relative URLs and every scheme except `http`, `https`, `mailto` and `tel` on links are
  dropped. `<style>` blocks are not kept; `style` attributes pass an own filter (about 70
  presentation properties, values without `url()`, escapes, comments or any function except
  colours and `calc`), so there is no CSS exfiltration even without the CSP. Input with
  more than 20,000 tags or nested deeper than 400 levels is refused (the sanitizer is quadratic
  in the depth); the page then shows the text version. At most 8 MiB of inlined images are
  written per document.
* **Images**: `cid:` references become `data:` URIs of the message's own raster images (PNG,
  JPEG, GIF, WebP; never SVG; 2 MiB each, 8 MiB in all). Remote (`https:`) images are **not
  loaded**: the page says how many there are and offers "Load remote images", an explicit click
  that reloads this one view with `img-src data: https:`. The next view blocks them again.
  `http:` images are never loaded.
* **Links** open in a new tab with `rel="noopener noreferrer"`; below the frame the page lists
  the link targets, defanged (`hxxps[:]//...`) so they cannot be clicked there.

With **`CONTENT_ORIGIN`** (recommended) the document is served from another host name instead:
the iframe points to `CONTENT_ORIGIN/c/<token>`, where the token is a signed, two minute address
(user, message, image choice) because that origin never sees the portal cookie. Even a sandbox
escape then lacks the portal's origin. Without it the document is served from the portal's own
origin at `/m/<id>/html` (still sandboxed by the frame attribute and by the response's own
`sandbox` CSP). See [operator-env.md](operator-env.md).

**Downloads.** Attachments and the `.eml` are served with `Content-Disposition: attachment`
(the file name is cleaned to ASCII plus an RFC 5987 form; no line break or quote can get
into a header), `X-Content-Type-Options: nosniff`, `Content-Security-Policy: sandbox;
default-src 'none'; frame-ancestors 'none'`, `Cache-Control: no-store`, and a content type
from the passive allow-list (`application/pdf`, archives, office documents, audio/video);
everything else - HTML, SVG, XML, scripts, any text type - is sent as
`application/octet-stream`. They use the same building blocks as the local download listener:
the part is looked up in the **server's** `BODYSTRUCTURE`, then read chunk by chunk (256 KiB per
request, transfer encoding undone incrementally), never buffered whole; the size limit is
`UEM_MAX_DOWNLOAD_BYTES` (default 100 MiB). Base64 and quoted-printable parts have no known
decoded length in advance, so those responses are chunked. POP3 has no server-side parts: there
the message is read as a whole (up to `UEM_MAX_MESSAGE_BYTES`).

Audit events and activity entries: `viewer.open` (kind message or thread, whether HTML was shown, attachment count,
size bucket), `viewer.raw` (headers; `.eml` with size bucket) and `attachment.download`
(size bucket, content-type family, whether the stream completed) - pseudonymous user, no names,
subjects or content.

## Activity

`/portal/activity` lists the signed-in user's own recent events, newest first, in plain words
("You connected My Assistant.", "My Assistant searched your mail 14 times.", "My Assistant moved 3
messages.", "You declined a message that My Assistant wanted to send."): sign-in, connecting and
disconnecting applications, changes to accounts and identities, what the applications did (tool
calls with counts, merged per hour for reads), sends and approvals, viewer use. The store keeps
only ids, labels and counts (30 days, see [stored-data.md](stored-data.md)); application and
account names are looked up in the user's own records when the page is shown, and what no longer
exists reads as "an application that is no longer connected". The page only ever reads the
signed-in user's entries. The text is translatable like every other page. Details: [audit.md](audit.md).

## Privacy: what is stored, export, delete everything

`/portal/privacy` (menu "Privacy") has three parts.

* **What is stored.** A table of the record kinds (user record, mail accounts, sender
  identities, connected applications, activity, pending approvals, sign-in sessions) with live
  counts of the signed-in user's own records and the retention. The durations are read from the
  running configuration (portal session limits, the store's `SessionPolicy`: access key
  lifetime, refresh lifetime and absolute maximum, activity 30 days, `UEM_APPROVAL_TTL`), not
  written into the template.
* **Download my data.** A `POST` (CSRF token required, no re-authentication: it shows the user
  what they can already see) answers with one JSON file, `Content-Disposition: attachment`,
  `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`. Contents and exclusions:
  [stored-data.md](stored-data.md#privacy-export-and-delete). Audit event `portal.export` (also
  a line in the user's Activity page).
* **Delete all my data.** `GET /portal/privacy/delete` shows what will go and asks to type the
  sign-in address; it needs a recent password entry like every sensitive action (stale: redirect
  to `/portal/reauth` and back). `POST` checks the CSRF token, the password freshness and the typed
  address (case-insensitive), calls `Store.delete_user`, retires the user's pooled mail
  contexts (`UserPool.forget_user`; calls in flight finish, then the connections close), clears the session cookie and shows
  "Your data was deleted". Signing in again afterwards starts from scratch like a new user.
  Audit event `portal.delete_all` (log only, with counts per record kind; no feed entry because
  the feed is deleted too).

## Language

Templates contain no literal text; everything goes through the translation layer
(`portal/i18n.py`). **English and German ship.** A language is a JSON catalog in
`portal/locales/<code>.json` mapping the English text (the message id) to its translation;
with more than one language a switch appears in the footer (it sets the `uem_lang` cookie).
Order: cookie, `Accept-Language` (`de-AT` finds `de`), `UEM_DEFAULT_LANGUAGE`, English.
The operator sets the default for visitors without a preference, for example
`UEM_DEFAULT_LANGUAGE=de`; the user's own choice always wins.

* **German** addresses the user formally ("Sie"). Terms: mail account = *E-Mail-Konto*
  (the provider-side mailbox = *Postfach*), connected application = *verbundene Anwendung*,
  approval = *Freigabe*, sender identity = *Absenderidentität*, permissions = *Berechtigungen*,
  draft = *Entwurf*, sign in = *anmelden*.
* **Times** are written `2026-10-09 14:30 UTC` in English and `09.10.2026 14:30 UTC` in German:
  the format string is itself a message id (`%Y-%m-%d %H:%M UTC`).
* **Sentences built by the service layer** (the recipient notes and warnings on the approval
  page, the notes under a message) are shared with the English tool output for the AI client,
  so they are translated by pattern in `portal/dynamic.py` (`DYNAMIC_MESSAGES`, with
  `%(name)s` holes) via the `|tr` filter. A text no pattern fits stays English. Tool results,
  server instructions, logs and error codes are never translated.
* **Add a language** `xx`: create `portal/locales/xx.json` (copy the ids from
  `extract_messages()`; keep the `%(name)s` placeholders and HTML tags exactly), add its
  name to `LANGUAGE_NAMES` if missing, and write a test like `tests/test_portal_i18n_de.py`.
  English plural pairs are two ids (`%(n)s day` / `%(n)s days`); the catalog picks the
  first for exactly 1, the second otherwise.
* **Keep it complete:** `tests/test_portal_i18n_de.py::test_german_catalog_is_complete` fails with
  the list of missing (or stale) ids whenever a template or `DYNAMIC_MESSAGES` changes without
  `de.json`; further tests check placeholders, formality and that every page renders in German.

## Security notes

* CSP `default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self';
  frame-ancestors 'none'` - no scripts at all; `no-store`; `__Host-` `Secure` `HttpOnly`
  `SameSite=Lax` cookies (dropped only for a plain-http loopback `PUBLIC_URL`). The viewer's
  pages additionally allow one frame (`frame-src 'self'` or the content origin); everything
  else stays script-free.
* Every `POST` carries a CSRF token (double submit) and is refused when the browser says
  `Sec-Fetch-Site: cross-site`. Reads never change anything. `Host` and `Origin` are checked
  for the whole app; the portal and `/authorize` answer no preflight and send no CORS headers.
* **CORS** is on for the cookie-less endpoints only (`/.well-known/*`, `/register`, `/token`,
  `/revoke`, `/mcp`) so browser-based MCP clients such as the MCP Inspector can connect:
  `Access-Control-Allow-Origin: *`, never credentials; `Authorization`, `Content-Type`,
  `Mcp-Protocol-Version` and the other MCP headers are allowed. These endpoints authenticate
  by bearer token or not at all, so a foreign page gains nothing it could not do with an HTTP
  client. The dev mode (`UEM_DEV_TOKEN`) has no CORS.
* Passwords are never rendered, logged or put in a URL; forms never repeat them, even after
  an error. Pages show account names, hosts and user names to their owner only (every id is
  checked against the signed-in user; foreign ids answer 404).
* Audit events (JSON, see [audit.md](audit.md)): `portal.account_add`,
  `portal.account_test`, `portal.account_permissions`, `portal.account_password`,
  `portal.account_remove`, `portal.identity_add`, `portal.identity_edit`,
  `portal.identity_test`, `portal.identity_remove`, `portal.grant_edit`,
  `portal.grant_revoke`, `portal.reauth`, and for approvals `approval.approved`,
  `approval.rejected`, `approval.refused`, `approval.send_failed` (next to the `send.*` events of
  the send itself). They carry pseudonyms (`u_...`) and random ids
  only - no addresses, host names, account names or passwords.
