# OAuth and sign-in (remote mode)

In remote mode the server is its own OAuth 2.1 authorization server and resource server
(design section 6.1). An AI client (Claude, ChatGPT, Claude Code, MCP Inspector ...)
connects to `PUBLIC_URL/mcp`, is sent through the browser to **sign in** and **consent**, and
gets tokens. This page is for operators and client authors; variables are in
[operator-env.md](operator-env.md), stored records in [stored-data.md](stored-data.md).

> **Status:** sign-in, consent, tokens and the per-user mail tools (work package 3e) work;
> sending from remote mode follows with 3f (see "What `/mcp` serves" below).

## What `/mcp` serves

Every request is authenticated by its access token (live token, existing grant, audience
`PUBLIC_URL/mcp`) and then served from a **per-user service** built from the store
(`service/userpool.py`, `server/peruser.py`): the accounts the grant names, with their
credentials decrypted in memory only, the user's identities, the operator's limits and policy.
Revoking the grant or the token stops the very next request (the token is checked on every
call); a changed or removed account takes effect on the next request too.

* **Tools offered = what the grant allows.** The tool list is computed per request from the
  grant, as in local mode from the configuration: a read-only grant sees the six read tools
  (`account_info`, `list_folders`, `find_messages`, `get_message`, `get_attachment`,
  `find_contacts`); `mail.organize` / `mail.delete` / `mail.drafts` on at least one account add
  `mark_messages`, `move_messages`, `create_folder` / `delete_messages` / `save_draft`.
* **Effective permission per account** = the account's own permissions (portal) ∩ the grant's
  scope for that account ∩ the scope of the token ∩ the operator policy (`UEM_READ_ONLY` leaves
  only `read`; POP3 accounts stay read-only). An account without `read` is not part of the grant's
  view. The check runs again on every call, per account: an organize grant on one mailbox and a
  read grant on another lets writes through to the first and refuses them (`NOT_PERMITTED`)
  on the second, and a client that calls a tool it was never shown gets "unknown tool".
* **Isolation.** A request only ever sees records of its own user (queried by `user_id` and
  checked again when the configuration is built); message ids and paging cursors name accounts
  and are resolved inside the caller's own view, cursors are signed with a per-user key derived
  from `PSEUDONYM_KEY`. Another user's ids resolve to "unknown account" or to the caller's own
  mailbox of the same name, never to the other user's.
* **Instructions per user.** The server instructions (handshake and `server/discover`) describe
  the tools of the grant and carry the folder map of the user's accounts, read with the same
  3 second timeout as in local mode (an account that does not answer is shown as "not read";
  `account_info` refreshes the map). A client pinned to 2026-07-28 that never asks for
  discovery does not see instructions.
* **`reauth_required`.** When a mail server rejects a stored password, the tool result names the
  account with code `REAUTH_REQUIRED` and says that the user has to enter the password again in the
  portal (`PUBLIC_URL/portal/accounts`); the other accounts keep working. The account record is
  marked (`auth_failed_at`, plus a sealed digest of the failed login) and no login is tried again
  for `UEM_REAUTH_RETRY_AFTER` seconds unless the password or user name changed (the flag lifts
  itself then; a working login clears it). No retry storm against the hoster.
* **Resource caps** (`UEM_MAX_CONNECTIONS*`, `UEM_MAX_CONCURRENT_CALLS_PER_USER`, ...,
  see [operator-env.md](operator-env.md)): mail connections are pooled per grant, closed after
  `UEM_CONNECTION_IDLE_TTL`, capped per user and per instance (the longest idle connection is
  closed to make room, otherwise the call fails with `BUSY`), and a user can run only so many
  tool calls at once (`BUSY` beyond that - the client may retry).
* **Sending.** `mail.send` and sender identities are stored with the grant, but `send_message` is
  **not offered** in remote mode until work package 3f (request-state sealing for the
  confirmation, pending approvals in the portal). Drafts work: `save_draft` writes into the
  Drafts folder of the account an identity is linked to (identities that copy to a drafts-capable
  account of the grant are usable for drafts without the right to send).

## Endpoints

| Path | Spec | Purpose |
|---|---|---|
| `/.well-known/oauth-protected-resource` (and `.../mcp`) | RFC 9728 | the resource `PUBLIC_URL/mcp` and its authorization server |
| `/.well-known/oauth-authorization-server` | RFC 8414 | endpoints, `code_challenge_methods_supported: [S256]`, `client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported` |
| `/authorize` | OAuth 2.1, RFC 8707, RFC 9207 | sign-in, consent, redirect with code and `iss` |
| `/token` | OAuth 2.1 | `authorization_code` (PKCE verifier required) and `refresh_token` (rotation) |
| `/revoke` | RFC 7009 | revoke an access token, or a refresh token (= the whole session) |
| `/register` | RFC 7591 | Dynamic Client Registration, public clients only (switch off with `UEM_DCR=false`) |

An unauthenticated `/mcp` request answers `401` with
`WWW-Authenticate: Bearer realm=..., resource_metadata="<PUBLIC_URL>/.well-known/oauth-protected-resource/mcp"`,
from which MCP clients discover everything else.

Send-only grants include `mail.read`. Granting `send` asks for the password again unless it
was typed within `UEM_REAUTH_WINDOW` (the consent page then shows a password step).

The MCP Python SDK's server-side OAuth provider was not used: it assumes registered
clients (no Client ID Metadata Documents) and ties the authorization UI to its provider
interface. The SDK's *client* is what the end-to-end tests drive.

## Clients

* **Client ID Metadata Documents (CIMD, preferred).** `client_id` is an `https` URL
  (with a path, no query, no fragment, no credentials, no IP literal). The server fetches it
  and requires: status 200, JSON content type, at most 16 KiB, a `client_id` member equal to
  the URL, `redirect_uris` (non-empty), no client secret or JWKS, `token_endpoint_auth_method`
  `none` if present. The fetch resolves the host once, checks **every** address (public
  unicast only, unless the operator allows private networks), connects to the checked IP and
  verifies TLS for the host name; redirects are **not** followed; a 10 s deadline covers slow
  senders; no cookies, no compression. The document is cached in the store for one hour, so
  a changed document takes effect after that. Only the (cleaned, length-limited, escaped)
  name is shown; logos and other URLs in the document are never fetched.
* **Dynamic Client Registration (fallback).** Open but rate limited (10 per IP and hour,
  200 per hour overall per instance), request body at most 8 KiB, public clients only (no
  secret is ever issued), `redirect_uris` required. `UEM_DCR_REDIRECT_HOSTS` restricts the
  hosts of `https` redirect URIs. Registrations expire after 30 days without use. The name is
  not verified and the consent page says so.
* **Redirect URIs** must be `https`, `http` on a loopback host (`127.0.0.1`, `[::1]`,
  `localhost`; the **port is free**, RFC 8252), or a private-use scheme in reverse-domain
  style (`com.example.app:/cb`). Matching is an exact string comparison. A request with an
  unregistered `redirect_uri`, or an unknown client, is shown as an error page and never
  redirected.

## Flow and checks

1. `/authorize`: `response_type=code`, `code_challenge` + `code_challenge_method=S256`
   (mandatory), optional `resource` (must be `PUBLIC_URL/mcp`; it is the default),
   `scope` (unknown scopes are dropped; only unknown ones is `invalid_scope`), `state`.
   Protocol errors (bad PKCE, resource, scope, response type) are shown on an error page and
   not redirected - anyone can register a client, so redirecting would make `/authorize` an
   open redirect (RFC 9700 4.11.2). Only the user's own Deny goes back (`access_denied`,
   with `state` and `iss`). `redirect_uri` at `/token` is optional but must match if sent.
2. No browser session: the **sign-in page**. Address and password are verified by an IMAP
   login against the server `LOGIN_DOMAINS` assigns to the address's domain (never a server
   the user names). The password is checked against that server; it is stored, sealed, as the credential of the sign-in mailbox account (the portal's "Main"; see [portal.md](portal.md)) only if the user ticks the opt-in checkbox "Use this mailbox with AI clients". The user record is keyed by the
   pseudonym `HMAC(PSEUDONYM_KEY, normalised address)`. A browser session (cookie) lives for
   `UEM_PORTAL_IDLE_TIMEOUT` idle / `UEM_PORTAL_SESSION_MAX` absolute.
3. The **consent page** shows the client name, its metadata URL (CIMD) or "self-registered,
   name not verified" (DCR), the host the answer goes to, and the grants:
   per mailbox `read` / `organize` / `delete` / `drafts`, and `send` over sender identities.
   Only reading is pre-ticked; reading is added whenever anything else is allowed; only what
   the client asked for (and the operator's policy offers) can be ticked; at least one
   permission is required. The accounts and identities are the user's own, managed in the
   [portal](portal.md): an account offers only the permissions the user gave it, and only
   identities with "sending allowed" are offered for `send`.
4. Allow: a grant and a **single-use code** (60 s) bound to client, redirect URI, PKCE
   challenge, resource and user; redirect `?code&state&iss`. Deny: `error=access_denied`.
5. `/token` redeems the code. Client, `redirect_uri` and PKCE verifier must match; any
   mismatch burns the code and the pending grant. A code used a second time revokes the
   grant and the tokens issued from it. The answer carries `access_token` (opaque, 1 h),
   `refresh_token` (opaque), `scope`, `expires_in`.
6. `refresh_token` exchanges for a new pair; the old refresh token is marked consumed.
   Presenting a consumed token revokes the grant (replay detection, strict: two truly
   concurrent refreshes of the same token also end the session - see `TODO.md`). A refresh
   cannot widen the scope.
7. `/mcp` accepts only a live access token **issued for `PUBLIC_URL/mcp`** (RFC 8707); other
   audiences, expired, revoked or unknown tokens get 401.

Lifetimes: access 1 h; refresh 30 days sliding; a connected client ends after 90 days at the
latest (`UEM_ACCESS_TOKEN_TTL`, `UEM_REFRESH_TOKEN_TTL`, `UEM_SESSION_MAX_AGE`; `0` =
unlimited for the last two, which is weaker because a leaked refresh token then never
expires on its own).

## Security properties

* PKCE S256 is required for every client (there is no confidential-client path); the
  `plain` method and implicit flow do not exist. Only public clients: a request with a
  `client_secret` or an `Authorization` header at `/token` is refused.
* Tokens, codes and browser-session cookies are 256-bit random values; the store keeps only
  SHA-256 digests (compared in constant time by lookup). Tokens never appear in logs or URLs
  (the access log records the first path segment only).
* Pages: `Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'
  [+ the redirect target on the consent page]; frame-ancestors 'none'`, no scripts, no
  inline styles, `X-Frame-Options: DENY`, `Cache-Control: no-store`,
  `Referrer-Policy: same-origin` (not `no-referrer`: browsers then send `Origin: null` on
  form posts). Cookies are `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`, session
  cookies (on a plain-`http` loopback `PUBLIC_URL` - development - the prefix and `Secure`
  are dropped). CSRF: double-submit token plus refusal of `Sec-Fetch-Site: cross-site`;
  Host and Origin are checked for the whole app. **CORS** is on for the cookie-less endpoints only
  (`/.well-known/*`, `/register`, `/token`, `/revoke`, `/mcp`; `Access-Control-Allow-Origin: *`, never
  credentials, `Authorization` and `Mcp-Protocol-Version` allowed) so browser-based clients such as
  the MCP Inspector work; `/authorize` and the portal send none and refuse foreign origins.
* Rate limits (in memory, per instance): portal connection tests 10 per user and 30 per IP per
  10 minutes and 5 per target mailbox per 15 minutes; sign-in 5 failures per address and 20 attempts per
  IP per 15 minutes; client-document fetches 30 per IP per minute; registrations as above;
  token and revoke requests 300 per IP per minute. Behind a proxy set
  `UEM_TRUSTED_PROXY_HOPS`.
* Audit events on stderr (`auth.sign_in`, `auth.consent`, `auth.token`, `auth.revoke`,
  `auth.code_replay`, `auth.client_refused`, `auth.csrf_failed`, `ratelimit.hit`) carry
  pseudonyms (`u_...`), grant ids and client ids, never addresses, passwords, tokens, codes
  or IP addresses.
* All text the client controls (name, redirect host, state) is escaped by the template
  engine; the name is additionally stripped of control, bidi and zero-width characters.

## Translation

Templates contain no visible text of their own: everything goes through `_("English text")`
(the English text is the message id), so English needs no catalog. A language is a JSON file
`src/universal_email_mcp/portal/locales/<code>.json` mapping English text to translation;
`portal.i18n.extract_messages()` lists all message ids. The language of a request is the
cookie `uem_lang` (the user's switch, prepared), then the browser's `Accept-Language`, then
`UEM_DEFAULT_LANGUAGE`, then English. German is planned as the second language (M4).

## Trying it

```bash
export PUBLIC_URL=http://127.0.0.1:8080 STORE_BACKEND=memory
export LOGIN_DOMAINS=company.example=mail.company.example
uv run universal-email-mcp serve --host 127.0.0.1
npx @modelcontextprotocol/inspector   # connect to http://127.0.0.1:8080/mcp, Authentication: OAuth
```

`tests/integration/test_oauth_e2e.py` runs the MCP SDK's own OAuth client (dynamic
registration and a metadata-document client) against a real server and a Dovecot login.
