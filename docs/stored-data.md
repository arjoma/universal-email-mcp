# Stored data and keys (remote mode)

Remote mode keeps its state in a `Store` (`universal_email_mcp.store`). Local mode stores
nothing. **No mail content is ever persisted**: no subjects, bodies, addresses of
correspondents, folder names, attachment names or search terms.

## Backends

| Backend | Use | Notes |
|---|---|---|
| `MemoryBackend` | tests, single-process development | lost on restart |
| `FirestoreBackend` | production (Google Cloud) | `pip install universal-email-mcp[gcp]`, Firestore native mode |
| SQLite | single VM / on-prem | planned, see `TODO.md` |

Firestore layout: one top-level collection per record kind (optional name prefix so several
instances can share a project), document id = SHA-256 of kind and record id (record ids can be attacker-chosen URLs; the real id is in `_id`). Fields:
the plain record fields, `_v` (version), `expires_at` (timestamp), `_sealed` (encrypted
blob) and `_mac` (authentication tag of the whole record, see below). Enable TTL deletion once per collection:

```bash
for c in portal_sessions oauth_clients auth_codes grants tokens approvals activity; do
  gcloud firestore fields ttls update expires_at --collection-group=$c --enable-ttl
done
```

Firestore deletes expired documents some hours after `expires_at`; the store treats expired
records as absent on every read, so the delay has no effect on behaviour. Queries are
single-field equality (`user_id`, `grant_id`), no composite index is needed.

## Records

| Record (collection) | Plain fields | Sealed (AES-256-GCM) | Lifetime |
|---|---|---|---|
| user (`users`) | pseudonym id, default identity, created | primary address, settings (ids of the sign-in mailbox account) | until deleted |
| account (`accounts`) | name, protocol, permissions, preset, `auth_failed_at` (set by the MCP side when the server rejected the login) | host, port, TLS, login name, **password**, `auth_failed_mark` (digest of the failed login; the flag only holds while it matches) | until removed |
| identity (`identities`) | copies account (drafts, sent), SMTP source account, send allowed, default flag | SMTP host/port/TLS, addresses, display name, signature, SMTP login and **password** | until removed |
| portal session (`portal_sessions`) | user, times, id = keyed digest of the cookie | - | 12 h (configurable) |
| OAuth client (`oauth_clients`) | CIMD URL / DCR id, name, redirect URIs | - | 30 days unused (extended on use) |
| authorization code (`auth_codes`) | client, grant, PKCE challenge, id = keyed digest of the code | - | 1 minute, single use |
| grant (`grants`) | user, client, granted account and identity ids, times | - | sliding refresh lifetime (30 days), absolute max 90 days; both configurable, 0 = unlimited |
| token (`tokens`) | id = keyed digest of the token, type, grant, resource, expiry | - | access 1 h, refresh as grant |
| pending approval (`approvals`) | user, grant, identity, content hash (SHA-256 of the message without Message-ID/Date), status | draft reference | `UEM_APPROVAL_TTL`, 10 minutes by default |
| send marker (`approvals`, status `sent`, id `s_...`) | user, content hash | - | 10 minutes (replay guard of a send in flight) |
| activity (`activity`) | user, time | event, grant id, tool, account id, label (name of a removed account), outcome, counts | 30 days |

A *grant* is a connected AI client in the portal's "Connected AI clients" list. Refresh
tokens rotate on every use; the old one stays (marked consumed) until it expires, and
presenting it again revokes the whole grant (replay detection).

Activity entries accept only short labels (no `@`, max 64 characters) and integer counts, a
tripwire against accidents; callers must still pass names and counts only. `client` holds the
**grant id** and `account` an account id (for a removed account the entry also keeps its `label`, the name as it was, never an address); the portal's
Activity page resolves both to the user's current names when it renders, so nothing but ids
and counts is duplicated. Entries are written by the audit pipeline (`audit.record`, see
[audit.md](audit.md)); `Store.record_activity(..., coalesce=True)` merges repeated events of one
kind within an hour into one entry with a `calls` counter. The send rate limit counts the
entries with event `send` (one per completed send, written with the send itself).

### Privacy: export and delete

The portal's Privacy page (`/portal/privacy`, see [portal.md](portal.md)) uses two store
methods.

**Export.** `Store.export_user(user_id)` returns the user's records as plain data, and the portal
builds the download from it (format `universal-email-mcp-export`, field `version`, currently 1):
the user (primary address, created, default identity, the 14-character pseudonym that appears
in the operator's logs, so the user can point the operator to their log lines), mail accounts (name, protocol, host, port, TLS, login name, preset,
permissions, created, `auth_failed_at`), sender identities (addresses, display name, signature,
SMTP host/port/login, flags), connected applications (grants: client name and id, accounts,
scopes, created, last used, expiry), the activity feed and pending approvals (identity, grant,
status, times). Left out by design: passwords (incoming and SMTP), the `auth_failed_mark`
digest, token, session and authorization-code records (only counts appear under
`not_exported`), digests and record ids that are derived from a secret, draft references, the
content hash of an approval, send markers, the full user pseudonym (`user_id` of every
record), unknown fields written by a newer version, key material and CSRF values. Mail content
is not stored, so it is not exported. What a record excludes is declared on its class
(`EXPORT_EXCLUDE`); a record whose id is a digest of a bearer secret must list `id`.

**Delete.** `Store.delete_user(user_id)` removes every record keyed to the user, also expired
ones, in the order of `records.DELETE_ORDER`: grants first (an access or refresh token is only
valid while its grant exists, so every token of the user is dead after the first step), then
tokens, authorization codes, approvals and send markers, sign-in sessions, mail accounts,
identities, activity, and the user record last; a final sweep removes what a request in flight
wrote meanwhile. Writes of a request in flight cannot create orphans after that: the per-user
writes of the store (activity entries, approvals and send markers, grants, authorization codes,
sign-in sessions) go through `Store.create_owned`, which checks that the user record exists
before and after the create and takes the record back if the user vanished in between
(`UserGone`; an activity entry is dropped silently, a send claim answers "no"). It returns
counts per kind. Every step is a delete by id, so a crash midway
leaves a user who can sign in again and repeat the deletion; the second run finishes the job.
OAuth clients are shared across users and not personal data (they expire when unused). The
tests fail when a record type is added without deciding whether it is per-user and where it
goes in `DELETE_ORDER`.

## Encryption

Sealed fields of a record are serialised together and encrypted as **one blob** with
AES-256-GCM (random 96-bit nonce per blob):

```
e1.k2.<base64url(nonce || ciphertext || tag)>
  |  |
  |  key id in the ring
  format version
```

The associated data is `[format, key id, user id, record kind, record id, "_sealed"]`: a blob
copied to another record, user or field (or relabelled with another key id or format) fails
authentication.

### Bearer secrets: keyed record ids

Tokens, authorization codes and portal-session cookies are 256-bit random strings and are never
stored. The record id is `HMAC-SHA256(derive("<purpose>-id-v1"), secret)` (hex), with the
purposes `token`, `authcode` and `session` and `derive(purpose)` = `HMAC-SHA256(ring key,
"uem-derive\0" + purpose)` (one derived key per ring key, never the ring key itself). An unkeyed
digest would let anybody who can *write* to the database (without any key) mint a token by
creating a record under the SHA-256 of a value of their choice; with the keyed id they cannot
compute an id at all. New records use the active key, a lookup tries the ids of every ring key,
so rotation keeps sessions valid. The ids cannot be re-keyed (the secret is not stored): removing
an old ring key ends the sessions and tokens issued under it.

### Record MAC: plain fields are authenticated

Every record carries `_mac = m1.<key id>.<base64url(HMAC-SHA256(derive("record-mac-v1"), input))>`.
The input is one JSON array `["uem-record-v3", namespace, kind, record id, owner user id, {all
stored fields except _v and _mac, with the sealed blob}]` (`namespace` is the Firestore
collection prefix, `FIRESTORE_PREFIX`, empty for the memory backend); sorted keys,
ASCII-escaped, datetimes as UTC microseconds in a tagged object, tuples as lists. It covers the fields that decide what a
caller may do and that are *not* sealed: scopes, per-account permissions, `send` flags,
redirect URIs, owners, expiries, session `reauth_at` and so on. On every read the tag is
verified (constant time) **before** anything else; a record without a valid tag is treated like
a damaged one (`CryptoError`, the same path as a wrong key): it is never trusted, the bearer
verifier answers 401, and `rotate-keys` and the GDPR export report it as unreadable. A record is
bound to its id, owner and namespace, so a genuine record copied to another id, user or
deployment (collection prefix) fails too; **changing `FIRESTORE_PREFIX` of a deployment that
holds data therefore invalidates every record** (move data with an export/import, not by
renaming collections). Unknown
fields written by a newer instance are included in the input (a rolling deploy keeps working).

`_v` is deliberately **not** covered: it is only the optimistic-concurrency counter that makes
a write fail when the record changed meanwhile, not an authorization field. Changing it can
at most cause a spurious conflict or let a stale writer overwrite a newer genuine version,
which an attacker with database write access can do by replacing the document anyway
(see rollback below); binding it would not stop that.

The store format is "3" (`uem-record-v3`): records written by an earlier build have no `_mac`
and are rejected. This is acceptable before 0.1.0 because nothing is deployed yet; from 0.1.0 on a
format change needs a migration.

**Residual risk: rollback.** A MAC cannot tell a record from an older, genuine copy of itself.
Someone who can write to the database and has an old backup or export can restore a whole
document (an account with its former permissions, a grant that was narrowed or revoked, a
deleted token). Deleting a document is likewise not detectable by the service. Mitigations are
operational: restrict who may write to Firestore (IAM, see [deploy-gcp.md](deploy-gcp.md)), audit
the Firestore data-access logs, and keep access and refresh tokens short-lived.

### Key ring

Keys are 32 random bytes, base64-encoded, named `k1`, `k2` ... Configure through the
environment or a mounted secret (never in the repository, never logged):

| Variable | Meaning |
|---|---|
| `STORE_KEYS` | `k1=<base64>[,k2=<base64>...]` |
| `STORE_KEYS_FILE` | path of a file with the same content (one key per line, `#` comments); use instead of `STORE_KEYS` |
| `STORE_ACTIVE_KEY` | key used for new blobs (default: the highest number) |

Generate a key: `python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`
(or `KeyRing.generate_key()`).

**Rotation** (no logouts, no downtime):

1. Add `k2` to the ring and make it active; deploy. New and updated records use `k2`, old
   blobs still open with `k1`.
2. Run `universal-email-mcp admin rotate-keys` (same environment as `serve`; `--dry-run`
   counts without writing; it calls `rotate_keys(store)` of `universal_email_mcp.store.rotation`)
   to re-seal the records nobody has written since. It prints counts per record kind and is
   safe to repeat. A record that cannot be read (damaged, or sealed with a key that is not in
   the ring) does not stop the run: it is skipped, counted as `UNREADABLE` per kind, a warning
   without ids or content is logged and the exit status is 3. Keep the old key until that is
   resolved. The GDPR export (`Store.export_user`) treats such records the same way: it lists
   them as `{"unreadable": true}` instead of failing.
   Re-sealing includes re-issuing the record MAC under the active key, also for records that
   have no sealed part (grants, tokens, sessions ...).
3. Remove `k1` from the ring. Losing a key makes the blobs sealed with it unreadable: keep
   the ring in Secret Manager with versions. Sessions, access and refresh tokens issued under
   `k1` stop working (their ids are keyed by `k1`); wait for their lifetimes (12 h sessions,
   30-day refresh tokens) to pass if you do not want to sign anyone out.

Server settings are sealed so that someone with write access to the database cannot repoint
an account at another host; the record MAC (above) protects the plain fields. Rollback of a
record to an older, genuine copy of itself is not prevented.
With a name `prefix`, the TTL loop above needs the prefixed collection names. `touch_client`
must be called by the caller to extend an OAuth client.

Not covered: a compromised running instance (it holds the keys), and rotation of the
pseudonym key (users are keyed by it; a change needs a migration).

## Testing

`tests/test_store.py` runs the same contract tests against the memory backend and the
Firestore emulator (marker `integration`). Locally the emulator is started with rootless
podman/docker from `gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators` (skipped with a
reason if neither is available); set `UEM_TEST_FIRESTORE_HOST=host:port` to use a running one.
