# Audit events and the activity feed

One pipeline (`universal_email_mcp.audit`) serves both modes. Every call site passes *raw ids,
counts, buckets and outcome codes*; the pipeline checks them against a per-event allow-list,
pseudonymises the ids and writes one JSON line. In OAuth mode the same call also writes the
user's own-activity entry (`audit.record`).

## Where the lines go

| Mode | Stream | Why |
|---|---|---|
| `serve` (remote) | **stdout** | Cloud Run ships it to Cloud Logging, which reads `severity` |
| `local` (stdio) | **stderr** | stdout is the MCP protocol there; one stray line breaks the framing |

The audit logger is independent of `-v` / `UEM_LOG_LEVEL`. Audit lines are separate from the
access/diagnostic log lines (`logger`, `message`); both are JSON on stdout in `serve` mode and
tell apart by the `event` field and the `logger` name `universal_email_mcp.audit`.

## Line format

```json
{"event":"tool.call","message":"tool.call","severity":"INFO","ts":1760000000.123,
 "instance":"mail-00012-abc","request_id":"9c0f...","user":"u_3f9a1c2e7b4d",
 "grant":"g_5a1e0c77b2d4","tool":"find_messages","outcome":"ok","dur":"<1s","accounts":2}
```

* Always: `event`, `message` (= `event`), `severity` (`INFO`, `WARNING`, `ERROR`), `ts`
  (epoch seconds). When known: `instance` (Cloud Run revision, `K_REVISION`), `request_id`
  (same as the `X-Request-Id` header and the access log), `user`, `client`, `account`,
  `outcome`, `code`.
* `severity` is `WARNING` for refusals (`auth.csrf_failed`, `ratelimit.hit`, a sign-in with an
  outcome other than `ok`, a tool call with the outcome `error` or `partial`, ...) and `ERROR` for `send.failed` / `approval.send_failed`.
* Every event names an account by its **id** (`a_...`), also the `send.*` events (the account the
  sent copy goes to, plus the `identity`); local mode has no ids and uses the configured name
  throughout. The one place a name is kept is the feed `label` of `portal.account_remove` (it is
  never part of the log line), so the Activity page can still say which account was removed.
* Other fields are event specific (counts such as `accounts`, `attachments`, `succeeded`;
  buckets `size` (`<10k` ... `>=10M`) and `dur` (`<100ms`, `<1s`, `<5s`, `<30s`, `>=30s`);
  `recipients` as counts per class).

## Pseudonyms and what is never logged

* `user` is the first 14 characters of the user id, which already is
  `HMAC-SHA256(PSEUDONYM_KEY, normalised primary address)`.
* `client`, `account`, `grant`, `identity`, `approval` are `<letter>_<12 hex>` of an
  HMAC-SHA256 under the same key, one namespace per kind (the same id never gives the same
  pseudonym in two kinds). In local mode the key is a **per-install key** in the state directory
  (`audit.key`, mode 0600, created on first use; a throw-away key if that fails). Without the key a
  pseudonym cannot be reversed or checked.
* **Never logged**: addresses, subjects, bodies, folder names, search terms, file names, message
  ids, tool *arguments*, tokens, passwords, client names, account names, IP addresses.
* **IP addresses** are not logged. With `AUDIT_LOG_CLIENT_IP=true` the sign-in and rate-limit
  events carry `ip` = a keyed pseudonym (`n_...`) of the *network* (IPv4 /24, IPv6 /48): enough
  to see "many failures from one place", useless for identifying a person.
* A schema allow-list per event (`EVENTS`) names the fields it may carry, and every field has a
  kind that validates the value: ids are hashed, `tok` values are up to three dot-separated words
  of `[A-Za-z0-9_<>=+-]` (no `@`, space, `/`, `:`, so no address or URL), counts must be integers.
  A value that does not fit is logged as `invalid`, a field that is not allowed is dropped, an
  unknown event becomes `audit.invalid`. The test suite runs in **strict** mode (it raises
  instead) and checks every event with hostile values.

## Events

| Area | Events |
|---|---|
| authentication | `auth.sign_in` (outcome), `auth.consent`, `auth.token` (grant type, outcome), `auth.revoke`, `auth.register`, `auth.code_replay`, `auth.client_refused`, `auth.redirect_refused`, `auth.csrf_failed`, `portal.reauth`, `ratelimit.hit` (`scope`: `signin_address`, `signin_ip`, `authorize_ip`, `token_ip`, `register`, `portal_action`, `portal_test`, `viewer`, `download`, `tool_user`, `tool_grant`, `tool_write`; plus `user`, `grant`, `ip` where known; a refused tool call is logged as this event only, not as `tool.call`, so it writes nothing to the activity feed) |
| portal | `portal.account_add/test/permissions/password/remove`, `portal.identity_add/edit/test/remove`, `portal.grant_edit/revoke`, `portal.export` (record counts; in the feed), `portal.delete_all` (`deleted`: count per record kind; log only, the user's feed is deleted with them) |
| tool calls (OAuth mode) | `tool.call`: tool name (`unknown` for names the client invented), outcome `ok`/`error`/`partial` (`partial`: a batch with `succeeded` and `failed` both above 0), `code`, duration bucket, number of accounts, and for writes `succeeded`/`unchanged`/`failed`/`planned` message counts |
| sends | `send.requested`, `send.confirmed`, `send.declined`, `send.draft_kept`, `send.fallback_send`, `send.approval_requested`, `send.replay_refused`, `send.sent`, `send.failed`; `approval.approved/rejected/refused/send_failed/expired_use` |
| viewer | `viewer.open`, `viewer.raw`, `attachment.download` |

In local mode only the `send.*` events occur (counts, buckets, outcome; no user).

## The activity feed (OAuth mode)

`audit.record(...)` stores, for events that have a user, an `ActivityEntry` in the store
(`docs/stored-data.md`): event name, grant id (as `client`), tool, account id (and, for a removed
account, a `label` with its name),
outcome and counts - sealed, 30 days (TTL). The portal page **Activity** (`/portal/activity`)
shows the signed-in user's own entries in plain words and resolves the application and
account names from the user's own records when the page is rendered.

* Not in the feed: failed sign-ins (they would create records for arbitrary addresses),
  token refreshes, rate-limit hits, `send.requested/confirmed/sent` (the completed send is
  the single `send` entry that also feeds the send rate limit), the `send_message` tool call.
* Read tool calls (`find_messages`, `get_message`, ...) are **merged per grant, tool and hour**
  into one entry with a `calls` counter, so a busy client cannot flood the feed (or the
  rate-limit scan over it); write tools get one entry per call with their counts.
* A feed write that fails or takes longer than 3 seconds never breaks the request; the log line
  has already been written.

Pseudonyms are stable across instances only with the same `PSEUDONYM_KEY` (required in
production anyway). The audit state is process-global: one app per process.

## Operations

Log-based metrics and alert examples: [deploy-gcp.md](deploy-gcp.md), section 10.
Summaries and per-user questions: the `audit` command below.

## The `audit` command

`universal-email-mcp audit` summarises audit lines from files or stdin. It needs no server, no
store and no network; it reads what the log already holds. Input can be raw audit lines
(`{"event":...}`, one per line) or Cloud Logging exports: the JSON array of
`gcloud logging read --format=json` (entries with `jsonPayload`; the entry `timestamp` is used
when a line has no `ts`) or newline-delimited entries. Lines that are not audit events (access
log, diagnostics) and lines that are not JSON are skipped and counted, never fatal.

```bash
# summary of the last day (per event and outcome, per tool with error rate and duration
# buckets, sends, failed sign-ins per network pseudonym, rate-limit hits, time range)
gcloud logging read 'resource.type="cloud_run_revision" AND jsonPayload.event:*' \
  --freshness=1d --format=json | universal-email-mcp audit --since 24h

# what did one user do? the pseudonym is recomputed from PSEUDONYM_KEY
export PSEUDONYM_KEY_FILE=/secure/pseudonym-key        # or: audit --key-file FILE
universal-email-mcp audit --user alice@example.org --since 7d export.json
universal-email-mcp audit --client "https://client.example/meta.json" --event 'send.*' export.json
universal-email-mcp audit --account ACCOUNT_ID --grant GRANT_ID --json export.json

# local mode (per-install key audit.key; there are no users): --local
universal-email-mcp local 2> audit.log    # or whatever captures stderr
universal-email-mcp audit --local --account Work audit.log

# the pseudonym of a value, to build Logs Explorer or log-based metric filters
universal-email-mcp audit pseudonym user alice@example.org      # u_3f9a1c2e7b4d
universal-email-mcp audit pseudonym ip 203.0.113.7               # n_... (the /24 network)
```

Example filter from a pseudonym:
`resource.type="cloud_run_revision" AND jsonPayload.user="u_3f9a1c2e7b4d" AND jsonPayload.event="tool.call"`.

* Options: `--since` / `--until` (ISO time, a date, or relative `90m` `24h` `7d`; `--until` is
  exclusive), `--event` (name or pattern such as `send.*`, repeatable), `--user ADDRESS`,
  `--client`, `--account`, `--grant` (raw ids; hashed with the matching prefix), `--json`.
  Kinds for `pseudonym`: `user client account grant identity approval ip`. Options go after
  `audit` (and after `summary`, which is the optional default action).
* **The key** is read from `PSEUDONYM_KEY` / `PSEUDONYM_KEY_FILE` (the operator variables, base64,
  at least 32 bytes), from `--key-file FILE`, or with `--local` from the per-install
  `audit.key`. It is never accepted as an argument value (it would show in the process list),
  never printed, and only needed for the filters and `pseudonym`. Without a key the summary still
  works on the pseudonyms as they are.
* **Safe to paste.** The log is untrusted too: anyone who can write to it can forge lines. Every
  value taken from it is cut to 48 characters, ANSI/OSC escape sequences are removed and control
  or format characters (including bidi overrides) are replaced by `?` before anything is
  printed, in text and in `--json`. Lines over 64 KiB are skipped (a JSON array is read as one document of up to 48 MiB), a counter keeps at most 500
  distinct keys (the rest is `(other)`), and wrong types in any field are ignored.
* Events without a `ts` (and entry `timestamp`) are left out when `--since`/`--until` is used.
  A file literally named `summary` or `pseudonym` must be written `./summary`. Pseudonyms can only
  be recomputed with the real `PSEUDONYM_KEY` (a memory-backend dev server uses a random one). The
  `pseudonym` command also covers `identity`, `approval` and `ip`, which have no filter option:
  paste the result into a Logs Explorer filter.
* An audit line is a JSON object with `event` like `area.name` and `message` equal to `event`.
* **BigQuery** is out of scope for the command. For long-term analysis create a log sink to
  BigQuery (`gcloud logging sinks create audit-bq bigquery.googleapis.com/projects/P/datasets/D
  --log-filter='jsonPayload.event:*'`), query it with SQL, and export rows as JSON lines
  (select the `json_payload` column, one object per line, `bq query --format=json`) and feed
  them to this command if you want the same summary.
