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
owner's next sign-in, keeping the permissions that had been granted.)

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
465 / 587 are allowed, and IP literals and bare names are refused. Servers listed by the
operator are trusted (any port; private addresses only with `UEM_ALLOW_PRIVATE_NETWORKS`).

Connection tests open outbound connections and try logins, so they are rate limited (10 per
user and 10 minutes, 30 per IP, 5 per target mailbox and 15 minutes). Nothing the server says
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

## Re-authentication

Typing the password again (checked live against the login server) opens a window of
`UEM_REAUTH_WINDOW` seconds (default 300). Signing in counts. Needed for: opening or
submitting the add-account form, removing an account, changing an account's password, raising
an account's permissions, allowing an identity to send, and **granting `send` to a client at
the consent page**. When the window is over the user is sent to `/portal/reauth` and back;
nothing secret is carried along (a half-filled form is lost, never a password).
Wrong passwords count against the same limits as sign-in (5 failures per address and 15
minutes).

## Language

Templates contain no literal text; everything goes through the translation layer
(`portal/i18n.py`). English ships. A language is a JSON catalog in `portal/locales/<code>.json`
mapping English text to translation; as soon as there is more than one language a switch
appears in the footer (it sets the `uem_lang` cookie). Order: cookie, `Accept-Language`,
`UEM_DEFAULT_LANGUAGE`, English.

## Security notes

* CSP `default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self';
  frame-ancestors 'none'` - no scripts at all; `no-store`; `__Host-` `Secure` `HttpOnly`
  `SameSite=Lax` cookies (dropped only for a plain-http loopback `PUBLIC_URL`).
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
* Audit events (stderr JSON, see [oauth.md](oauth.md)): `portal.account_add`,
  `portal.account_test`, `portal.account_permissions`, `portal.account_password`,
  `portal.account_remove`, `portal.identity_add`, `portal.identity_edit`,
  `portal.identity_test`, `portal.identity_remove`, `portal.grant_edit`,
  `portal.grant_revoke`, `portal.reauth`. They carry pseudonyms (`u_...`) and random ids
  only - no addresses, host names, account names or passwords.
