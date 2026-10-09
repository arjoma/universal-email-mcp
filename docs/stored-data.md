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
the plain record fields, `_v` (version), `expires_at` (timestamp) and `_sealed` (encrypted
blob). Enable TTL deletion once per collection:

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
| user (`users`) | pseudonym id, default identity, created | primary address, settings | until deleted |
| account (`accounts`) | name, protocol, permissions, preset | host, port, TLS, login name, **password** | until removed |
| identity (`identities`) | copies account, default flag | SMTP host/port/TLS, addresses, display name, signature, SMTP login and **password** | until removed |
| portal session (`portal_sessions`) | user, times, id = SHA-256 of the cookie | - | 12 h (configurable) |
| OAuth client (`oauth_clients`) | CIMD URL / DCR id, name, redirect URIs | - | 30 days unused (extended on use) |
| authorization code (`auth_codes`) | client, grant, PKCE challenge, id = SHA-256 of the code | - | 1 minute, single use |
| grant (`grants`) | user, client, granted account and identity ids, times | - | sliding refresh lifetime (30 days), absolute max 90 days; both configurable, 0 = unlimited |
| token (`tokens`) | id = SHA-256 of the token, type, grant, resource, expiry | - | access 1 h, refresh as grant |
| pending approval (`approvals`) | user, grant, identity, content hash, status | draft reference | 10 minutes |
| activity (`activity`) | user, time | event, client, tool, account name, outcome, counts | 30 days |

A *grant* is a connected AI client in the portal's "Connected AI clients" list. Refresh
tokens rotate on every use; the old one stays (marked consumed) until it expires, and
presenting it again revokes the whole grant (replay detection).

Activity entries accept only short labels (no `@`, max 64 characters) and integer counts, a
tripwire against accidents; callers must still pass names and counts only. Account fields hold the account *name* the user chose.

### Privacy: export and delete

`Store.export_user(user_id)` returns everything stored about a user as plain data (passwords,
token digests, draft references and keys left out). `Store.delete_user(user_id)` removes every record of the
user (accounts, identities, sessions, grants, tokens, codes, approvals, activity, the user
itself) and returns counts; run it again if it was interrupted. OAuth clients are shared
across users and not personal data.

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
authentication. Tokens are 256-bit random strings; only their SHA-256 digest is stored
(sufficient for high-entropy input, no salt needed) and compared in constant time.

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
2. Run `rotate_keys(store)` (`universal_email_mcp.store.rotation`; it will be exposed as
   `universal-email-mcp admin rotate-keys` with the HTTP server) to re-seal the records
   nobody has written since. It reports counts per record kind and is safe to repeat.
3. Remove `k1` from the ring. Losing a key makes the blobs sealed with it unreadable: keep
   the ring in Secret Manager with versions.

Server settings are sealed so that someone with write access to the database cannot repoint
an account at another host. Rollback of a record to an older blob of itself is not prevented.
With a name `prefix`, the TTL loop above needs the prefixed collection names. `touch_client`
must be called by the caller to extend an OAuth client.

Not covered: a compromised running instance (it holds the keys), and rotation of the
pseudonym key (users are keyed by it; a change needs a migration).

## Testing

`tests/test_store.py` runs the same contract tests against the memory backend and the
Firestore emulator (marker `integration`). Locally the emulator is started with rootless
podman/docker from `gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators` (skipped with a
reason if neither is available); set `UEM_TEST_FIRESTORE_HOST=host:port` to use a running one.
