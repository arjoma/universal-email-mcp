# universal-email-mcp

> **Status: under development — not usable yet.** Version 0.0.1 only reserves the
> package name. Follow the [design plan](https://github.com/arjoma/universal-email-mcp/blob/main/docs/plans/2026-09-30-design.md).

A vendor-neutral [Model Context Protocol](https://modelcontextprotocol.io) server that
connects AI assistants (Claude, ChatGPT, any MCP client) to ordinary mailboxes over
**IMAP, POP3 and SMTP** — for everyone whose mail is not on Gmail: web hosters,
self-hosted servers, Exchange on-prem, and the like.

Planned highlights:

- **Several accounts per user** — search across all IMAP/POP3 mailboxes at once, send
  from the right identity automatically, per-account permissions (e.g. read-only).
- **Smart retrieval** — time windows, fuzzy matching of people, subjects and folders,
  contact lookup from your mail history.
- **Two modes** — a local single-user server (stdio) and a multi-user remote server
  with built-in OAuth 2.1 and a self-service portal.
- **Safe by design** — mail is treated as untrusted input; the server checks
  recipients (new or look-alike addresses) before anything is sent; no permanent
  deletion.
- **Operable** — encrypted credentials, pseudonymous audit logging, admin policy;
  reference deployment on Google Cloud Run ([`docs/deploy-gcp.md`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/deploy-gcp.md)).

## Try the probe

The first working piece is a read-only diagnostic that logs in to an IMAP server
and shows what it supports (no message content is displayed). From a checkout:

```bash
UEM_PASSWORD=... uv run universal-email-mcp probe --server mail.example.com --user alice@example.com
```

`--server` takes a preset name (e.g. `united-domains`) or a host name; `--starttls`
and `--port` select other connection modes, `--account NAME` uses an account from
the local config file (see [`docs/config.example.toml`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/config.example.toml)).

## Local mode (stdio)

`universal-email-mcp local` runs the MCP server over stdio for one user, with the
accounts from the config file ([`docs/config.example.toml`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/config.example.toml);
default `~/.config/universal-email-mcp/config.toml`, or `--config PATH` / `UEM_CONFIG`).
Passwords come from environment variables (`password_env`) or the OS keyring —
never from the file. Six read tools are always there:

| Tool | What it does |
|---|---|
| `account_info` | accounts, permissions, server features, quota, identities, limits, plus a cheap overview (unread in INBOX, Drafts/Junk counts, number of folders) and the folder map |
| `list_folders` | top level first with subfolder counts (`Clients ▸ 87`); `parent=` drills down, `query=` searches all levels, `depth=` (≤ 3) |
| `find_messages` | time window (`today`, `this_week` …), from/to/subject/body, unread/flagged/attachments — exact, server-side; plus `query` (wildcard or fuzzy) |
| `get_message` | headers, text body (paged, fenced as untrusted), attachments; `thread=true` for the conversation |
| `get_attachment` | one attachment by the id `get_message` lists: text-like files inline (fenced, paged), other files as an embedded resource up to `limits.max_attachment_bytes` (default 2 MiB); never marks mail as read |
| `find_contacts` | recent correspondents; `query=` finds a person (deeper search); `sent_to` (yes/no/unknown) marks people you wrote to |

Accounts with the `organize` and/or `delete` permission (default: `read` only)
add tools that change mail. A tool no account allows — or any tool under
`[policy] read_only = true` — is not offered at all, and each call is checked
again against the permissions of the account each message belongs to:

| Tool | Permission | What it does |
|---|---|---|
| `mark_messages` | organize | read/unread and flagged, by message id (batch, capped) |
| `move_messages` | organize | into another folder (exact folder name, unique leaf name or role; a typo or ambiguous name changes nothing and returns the candidates); moved messages get new ids. `to="archive"` files into the account's archive folder, in a year or month sub-folder when the archive is organised that way (created when missing). `with_conversation=true` moves the rest of each message's conversation too (INBOX, Sent, archive and the message's own folder; mail filed elsewhere stays, Trash/Junk/Drafts are never touched), `dry_run=true` only lists what would move |
| `create_folder` | organize | a folder (nested levels, `parent=` named exactly), subscribed; never renames or deletes folders |
| `delete_messages` | delete | moves to Trash (recoverable); mail already in Trash stays; there is no permanent deletion |

| `save_draft` | drafts | writes a draft into the account's Drafts folder: new, reply (`reply_to_id`, `reply_all`), forward (`forward_id`, attaches the original's files only), or replaces an earlier one (`draft_id`); **never sends** |
| `send_message` | an identity with `send = true` | sends a saved draft (`draft_id`) or a new message (the `save_draft` arguments; it is saved as a draft first). Irreversible, so: every recipient is classified (internal / written to before / new / **look-alike** of an address you know), the policy decides, and normally **you are asked to confirm** in your client; see below |

`save_draft` picks the sender among your configured identities (`from` names one;
else the identity the original was addressed to, else the default; a made-up
address is refused), adds the signature and the quoted original, validates every
address and refuses line breaks in headers. A reply goes to the original's
Reply-To (else From), like in a mail client, and warns when that points to another
domain. The result previews the draft and warns about recipients you never wrote
to. An identity needs `store_account` (or `account`) for its drafts; no SMTP server
is needed for drafts. Plain text only.

**Sending** is the riskiest tool and therefore the most guarded (design plan
section 8):

- The message always exists as a **draft** first; a declined, impossible or failed
  send leaves it in Drafts (the result and error hints give its id).
- SMTP goes through the same SSRF-safe connector as IMAP: the host is resolved
  once, every address checked, TLS >= 1.2 verified against the host name.
  Implicit TLS (465) or STARTTLS (587) - a server without STARTTLS is refused
  before any login; there is no plain-text mode. The envelope sender is the
  identity address, a `Bcc` header is never transmitted, and if the server
  refuses any recipient nothing is sent. A broken connection after the body went
  out is reported as `SEND_OUTCOME_UNKNOWN` (never retried).
- **Confirmation** (`[policy] send`): `confirm` (default) asks the user through
  MCP elicitation, showing sender, To/Cc/Bcc with their class and warnings,
  subject, attachments and the start of the text; `confirm-external` asks unless
  every recipient is internal; `on` asks only for look-alikes; `draft` never
  sends; `off` removes the tool. A look-alike recipient is **always** put to the
  user. A client that cannot elicit (or a user who declines) means: nothing is
  sent, the mail stays a draft and must be sent from the mail client. (Remote mode
  can instead park it for approval in the portal, see below.)
- Recipient classes: `internal` = your own identity addresses and
  `[policy] internal_domains`; `known` = you wrote to it (Sent, To/Cc, 2 years);
  `new`; `lookalike` = a typo or confusable (digits for letters, Cyrillic or
  Greek letters, `xn--` homographs, mixed scripts, another top-level domain) of an
  address or domain you know - including a *known* address that has a near-twin
  (you once mistyped `oliver.grnat@` and it went out).
- Hard limits: `allowed_recipient_domains`, `max_recipients`,
  `max_sends_per_hour` / `max_sends_per_day` per SMTP account, `limits.max_send_bytes`
  and the server's SIZE.
- Afterwards: a copy in Sent (identity `save_sent`), the draft removed (UID-scoped),
  `\Answered` on exactly the replied-to message (its account needs `organize` or
  `drafts`), and - `file_replies = "both"` is the default - the copy of a reply also
  goes into the user folder the original is filed in (`sent` / `thread_folder` are options).
- The confirmation shows the whole new text (up to 3000 characters / 80 lines; what is cut
  is announced with its size), a one-line summary of a quoted original, and up to 20
  attachments with sizes.
- One audit line per attempt on stderr (JSON; counts per class, size bucket,
  outcome - never addresses, subjects or text; see `docs/audit.md`).

The archive scheme of an account (`archive_scheme` = `auto` | `flat` | `yearly` |
`monthly`, see `docs/config.example.toml`) is detected from the archive folder's
subfolders; an empty archive is flat. Each message goes to the folder of its
`Date` header when plausible (not before 1990, not later than the arrival date + 1 day), else its arrival date (INTERNALDATE).

Changes are reported per message. They use UIDs checked against the folder's
UIDVALIDITY, `UID MOVE` (or `UID COPY` + `UID EXPUNGE` with UIDPLUS, otherwise
refused), and never a plain `EXPUNGE`. Try them on the sandbox mailbox
(`scripts/dev_mailbox.py`, see below) before pointing them at a real one.

`query` works the same everywhere: with `*` or `?` it is a case-insensitive,
umlaut-folded wildcard pattern that starts at a word start (`hub*` finds "Anna
Huber", `*gmbh`; inside a word: `*ub*`). For folders a pattern without `/`
matches the folder's own name at any level, one with `/` its path, where `*`
also crosses levels (`clients/m*`, `*/2025`). Anything else is matched fuzzily
(typos, `Müller`/`Mueller`, name order). Lists are bounded; each result's footer says how
to narrow it or fetch the next page (`cursor`).

**Attachment downloads.** Files too big for a tool result (and every attachment
`get_message` lists) come with a download link, `http://127.0.0.1:<port>/a/<token>`,
served by a small listener on the loopback interface for as long as the server runs.
The token is signed with a key that is random per run and expires after
`[downloads] link_ttl` (default 24 h), so a link stops working when the server
stops — ask for a fresh one. The file is streamed from the mailbox in chunks and
decoded on the fly (never held in memory whole, never marks mail as read); it is
served as a download with `nosniff` and a sandboxing CSP, and requests with any
other `Host` header are refused. Set `[downloads] enabled = false` to switch it off
or `port = …` for a fixed port.

**POP3 accounts** (`kind = "pop3"`, read-only) work in the read tools, in one search
together with IMAP accounts, but POP3 is a much smaller protocol:

- One folder, `INBOX`. There is no read/unread or flagged state: messages show
  "unknown", never "unread", and the `unread`/`flagged` criteria are ignored (the
  result says so).
- Ids are built from the server's `UIDL`, so they stay valid across sessions (a
  server without `UIDL` or `TOP` is refused). Headers come from `TOP n 0`, newest
  first, and are cached per account by UIDL; a later call only reads what is new.
  `find_messages` with header criteria, time windows or `query` looks at the newest
  `limits.max_headers_scanned` messages (the notes say so; a call has a time
  budget for loading headers and continues on the next call). Without criteria all
  messages are listed. POP3 has no search: `body` and the fuzzy "also in the body"
  match only see the headers. Dates come from the first `Received` header (POP3 has
  no arrival date), else `Date`.
- Whole messages are read with `RETR`, capped by `limits.max_message_bytes`: a larger
  message is read partially (`TOP`) and marked truncated. Attachments are numbered by
  this server's own MIME parse and `get_attachment` reads the message again; there
  are no download links for POP3 mail.
- Nothing is ever changed or deleted on the server: no `DELE`, no `RSET`, the session
  ends with `QUIT`, and write tools refuse POP3 ids ("POP3 accounts are read-only").
  Fresh mail appears after a new connection (a listing older than 20 s reconnects).
- TLS is mandatory: implicit TLS (995) or `STLS` (110), verified, TLS 1.2 or newer.

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "email": {
      "command": "uvx",
      "args": ["universal-email-mcp", "local"],
      "env": { "UEM_WORK_PASSWORD": "…" }
    }
  }
}
```

Claude Code:

```bash
claude mcp add email -e UEM_WORK_PASSWORD=… -- uvx universal-email-mcp local
```

Add `"--config", "/path/to/config.toml"` to the arguments for a non-default config
file. Until the first functional release is on PyPI, run it from a checkout
instead: `"command": "uv", "args": ["run", "--directory", "/path/to/universal-email-mcp", "universal-email-mcp", "local"]`.

**What the assistant knows at the start:** the server instructions include a
folder map per account, read when the server starts (all accounts in parallel,
3 seconds at most; an account that is slow or down shows "not read at startup" and
the server starts anyway):

```text
Work: INBOX, Drafts, Sent, Archive ▸ 8 (yearly: 2019 … 2026), Trash,
      Clients ▸ 87 (e.g. Huber, Müller, Schmidt …), Projects ▸ 12, Personal
```

Special folders come first (labelled with their role where the name differs, e.g.
`Gesendet (sent)`), then the other top-level folders alphabetically; `▸ N` is the
number of direct subfolders, with a few example names or, for the archive, its
scheme. The map is capped (30 folders, about 1500 characters per account), shows
only your own folders (never other users' or shared ones) and treats every name as
untrusted data. `account_info` returns the current map, so a long-running session
can refresh it.

Results come as Markdown tables (mail text escaped, links defanged) plus
structured JSON; message bodies are fenced as untrusted content, so the assistant
can tell mail from instructions.

## Remote mode (preview)

`universal-email-mcp serve` runs the server over HTTP (Streamable HTTP, stateless:
protocol 2026-07-28 and the legacy transport) with `/health` and `/ready`.

**OAuth mode** (the default): the server is its own OAuth 2.1 authorization server
(authorization code + PKCE S256, refresh-token rotation, revocation, Client ID Metadata
Documents with Dynamic Client Registration as fallback). Users sign in with their mailbox
login, see a consent page and grant the connecting AI client what it may do; `/mcp` needs
the resulting access token. A **self-service portal** at `/portal` lets each user add
their mail accounts (IMAP or POP3, connection tested before it is saved), set permissions,
manage sender identities, see the connected AI clients and disconnect or reduce them, and read
their own **Activity** feed (what the clients did, in plain words)
([`docs/portal.md`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/portal.md)).
`/mcp` serves each user's own accounts from the store with exactly the tools the client's
grant allows (read, organize, delete, drafts, and `send_message` when the grant, the
sender identity and the operator's policy all allow it). A send asks the user through MCP
elicitation (the continuation state is sealed, bound to user and grant, and cannot be forged
or replayed); a client that cannot ask gets the operator's `SEND_FALLBACK`: keep a draft, or
park the message under **Pending approvals** in the portal, where the user reads exactly what
would go out and approves it with a password check. Messages in tool results link to a **message viewer** in the portal
(`PUBLIC_URL/m/<id>`: text, HTML in a sandbox with no remote content unless clicked, conversation,
raw headers, `.eml`, attachment downloads streamed from the mail server; the portal session
authorises, no tokens in the links). How it works and how to run it: [`docs/oauth.md`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/oauth.md);
all variables: [`docs/operator-env.md`](https://github.com/arjoma/universal-email-mcp/blob/main/docs/operator-env.md).

```bash
export PUBLIC_URL=http://127.0.0.1:8080 STORE_BACKEND=memory   # development store
export LOGIN_DOMAINS=company.example=mail.company.example      # who may sign in, and where
uv run universal-email-mcp serve --host 127.0.0.1
claude mcp add --transport http email http://127.0.0.1:8080/mcp
```

**Dev mode** (temporary, with the mail tools): with `UEM_DEV_TOKEN` (or `--insecure-local`,
loopback only, no token) `/mcp` takes one static bearer token and serves the accounts of a
local config file:

```bash
export UEM_DEV_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ALLOWED_HOSTS=localhost,127.0.0.1
uv run universal-email-mcp serve --config config.local.toml --host 127.0.0.1 --port 8080
claude mcp add --transport http email http://localhost:8080/mcp --header "Authorization: Bearer $UEM_DEV_TOKEN"
```

## Remote mode: stored data

Remote mode keeps users, accounts, sessions and tokens in a store (memory or Firestore,
secrets encrypted with a rotatable key ring, no mail content): see
[docs/stored-data.md](https://github.com/arjoma/universal-email-mcp/blob/main/docs/stored-data.md).

## Development

To try the server without a real mailbox, start the sandbox: a throw-away local
Dovecot (podman or docker) with a few weeks of realistic German/English mail and
hostile samples (prompt injection, crafted headers, broken encodings):

```bash
uv run scripts/dev_mailbox.py up      # prints the probe and `claude mcp add` commands
uv run scripts/dev_mailbox.py down
```

Contributor guidelines and checks: [AGENTS.md](https://github.com/arjoma/universal-email-mcp/blob/main/AGENTS.md).

## License

Apache License 2.0 — see [LICENSE](https://github.com/arjoma/universal-email-mcp/blob/main/LICENSE) and [NOTICE](https://github.com/arjoma/universal-email-mcp/blob/main/NOTICE).
Copyright 2026 ARJOMA FlexCo.
