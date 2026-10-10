# GDPR notes for operators

These notes help an organisation that runs universal-email-mcp in remote mode (or provides it to
staff in local mode) to prepare its data protection documentation. **They are not legal advice.**
Whether and how the GDPR applies, who is controller, and which legal basis fits depends on your
situation; involve your data protection officer or counsel. Statements about the software refer
to what the code does today and are checked against [stored-data.md](stored-data.md),
[audit.md](audit.md), [portal.md](portal.md) and [operator-env.md](operator-env.md). Where a
statement depends on your deployment it says so. A fill-in assessment is in
[dpia-template.md](dpia-template.md).

## 1. Roles

| Party | Role in the usual setup |
|---|---|
| **The project** (maintainers of the open-source software) | Processes nothing. It publishes software; it has no access to any deployment, log or store. |
| **You, the operator** | Run the service. Usually the **controller** when you offer it to your own staff or members and decide purposes and means; a **processor** when you run it on behalf of another organisation under its instructions. Decide this explicitly and write it down. |
| **Users** | Data subjects (and, in a company, employees acting for the controller). Their correspondents are data subjects too. |
| **Mail provider** | Operates the mailboxes. Independent of this software; normally already your (or the user's) processor or a controller of its own. |
| **Cloud / hosting provider** | Your processor for the service, the store and the logs (in the reference deployment: Google Cloud Run, Firestore, Secret Manager, Cloud Logging). |
| **AI client vendor** | The vendor of the assistant the user connects (a chat product or agent). Receives whatever mail content the user asks the assistant to read. See section 6. |

Local mode with a single user processing their own mail has no operator in this sense; if an
organisation instructs staff to use it, the organisation is the controller and the points about
the AI client vendor still apply.

## 2. Personal data involved

### Stored by the service (remote mode)

All records keep **no mail content**: no subjects, bodies, correspondents' addresses, folder
names, attachment names or search terms. Details and lifetimes per record: [stored-data.md](stored-data.md).

| Category | Where | Notes |
|---|---|---|
| Mailbox credentials: host, port, login name, **password** (incoming and SMTP) | store, sealed (AES-256-GCM) | needed to read and send on the user's behalf; decrypted only in the memory of the instance that serves a request |
| User's primary mail address and settings | store, sealed; the record id is a keyed pseudonym | the address is the sign-in identity |
| Sender identities: addresses, display name, signature | store, sealed | signature text can contain names, phone numbers |
| Account and permission settings, preset, timestamps | store, plain | account names are chosen by the user |
| Connected applications (grants): client name and id, granted accounts and scopes, times | store | the client name comes from the client, not verified for self-registered clients |
| Tokens, sign-in sessions, authorisation codes | store, only keyed digests (HMAC) as ids | not readable as secrets |
| Pending send approvals: identity, grant, status, content hash, draft reference | store | the draft itself stays in the user's own Drafts folder |
| **Activity feed**: event, tool, account, outcome, counts, time | store, sealed, per user | no content; shown to the user as "Activity" |
| OAuth client records (URL/registration, name, redirect URIs) | store | not personal data in general |

### In logs (remote mode: stdout; local mode: stderr)

Audit lines use **pseudonyms** (a keyed hash of the address, ids of clients, accounts, grants),
event names, outcome codes, counts, size and duration buckets. They never contain addresses,
subjects, bodies, folder or file names, search terms, tool arguments, tokens, passwords, client
names, account names or IP addresses. Optionally (`AUDIT_LOG_CLIENT_IP=true`, off by default)
sign-in and rate-limit events carry a keyed pseudonym of the client's *network* (IPv4 /24, IPv6
/48). Ordinary request lines carry a route pattern, status, duration and request id. A pseudonym
is still **personal data for whoever holds the pseudonym key** (and can map known addresses to
pseudonyms); treat the log as personal data. The platform (load balancer, Cloud Run) may log client
IP addresses on its own; that is outside this software.

### Transient: mail content in memory and in transit

When a user's assistant reads mail, the server fetches it from the mail provider and returns it to
the AI client in the tool result (and to the user's browser in the message viewer). Header caches
(subjects, addresses, dates) and decrypted accounts live in the memory of the serving instance only
and are dropped after being idle (`UEM_USER_IDLE_TTL`, 15 minutes by default; connections
`UEM_CONNECTION_IDLE_TTL`, 2 minutes). Nothing is written to disk by the server except, in local
mode, the key file for audit pseudonyms. Drafts and Sent copies that the user's assistant creates
are written to the **user's own mailbox** at the mail provider, as with any mail program.

### Data of third parties

Correspondents appear only transiently (above), never in the store or the log. The recipient
check derives its "written to before" sets from the user's Sent history in the mailbox and keeps
them in memory only.

## 3. Purposes and possible legal bases

Purposes: providing the service the user asked for (assistant access to their mail with their
chosen permissions); security (authentication, abuse prevention, rate limits, audit trail);
transparency to the user (activity feed); operating and capacity planning (aggregated
metrics from the log).

Possible bases, to be decided and documented by you:

* Staff or members using the service as part of their duties: legitimate interests of the
  organisation (Art. 6(1)(f)) or performance of a contract (employment, membership, Art. 6(1)(b));
  consent is rarely suitable in an employment relationship. In some countries the works council
  or staff representation must be involved (in Austria, for instance, ArbVG sections 96 and 96a may
  apply to systems that monitor staff). Check this before turning on logging.
* Customers or the public who choose to connect their own mailbox: contract (Art. 6(1)(b)) for the
  service they requested, possibly consent for optional parts.
* Security logging: legitimate interests (Art. 6(1)(f)) or a legal obligation, with a documented
  balancing test.

The processing of the content of the mailbox by the AI client is a separate processing with its
own purpose and basis (section 6).

## 4. Retention

Values are the defaults in the code; the ones marked * are configurable (see
[operator-env.md](operator-env.md)). Firestore deletes expired documents some hours after
`expires_at`, but the store ignores expired records immediately.

| Record | Retention |
|---|---|
| User, mail accounts, identities | until the user removes them or deletes everything |
| Portal sign-in session | 30 minutes idle*, 12 hours absolute* |
| Authorisation code | 1 minute (single use; kept 10 minutes marked as used, to detect replay) |
| Pending consent result | 10 minutes |
| Grant (connected application) | refresh lifetime 30 days sliding*, absolute 90 days* (`0` = unlimited, not recommended) |
| Access token | 1 hour* |
| Refresh token | as its grant |
| OAuth client | 30 days after last use |
| Pending approval, send marker | 10 minutes* (`UEM_APPROVAL_TTL`; the marker is fixed) |
| Activity feed | 30 days |
| Audit and request logs | **your choice**: the log storage's retention. The deployment guide suggests a dedicated log bucket with about 90 days; Cloud Logging's default bucket keeps 30 days |
| Backups of the store | **your choice**: point-in-time recovery 7 days; scheduled backups as long as you configure (the guide's example: 14 days) |
| In-memory caches | minutes (see section 2) |

Backups and logs are where deleted data lingers. State this in your retention concept: a user who
deletes their data in the portal is removed from the live store at once, from backups when they
expire.

## 5. Data subject rights and the features that serve them

| Right | How it is served today |
|---|---|
| Information (Art. 13/14) | You provide the privacy notice (section 8). The portal's *Privacy* page shows what is stored about the signed-in user, with counts and retention read from the running configuration. |
| Access (Art. 15) and data portability (Art. 20) | *Privacy* > *Download my data*: one JSON file with the user's accounts (without passwords), identities, applications, activity and approvals, and the pseudonym that appears in your logs. Passwords, token and session records, digests and key material are left out on purpose. Mail content is not stored by the service, so it is not in the export; it is in the user's mailbox. **Log lines** about the user are not in the export: you must be able to look them up (`universal-email-mcp audit --user ADDRESS`, [audit.md](audit.md)) and answer that part of an access request yourself. |
| Rectification (Art. 16) | Users change account data, password, identities and permissions in the portal. Mail content is the mail provider's. |
| Erasure (Art. 17) | *Privacy* > *Delete all my data* removes every record of the user (grants first, so every client stops), after a password check and typing the address. It runs through the store, also for expired records; a second run finishes an interrupted one. Logs and backups age out by their retention (section 4); the pseudonymous log lines cannot be deleted individually by the software, so if you must erase them earlier, that is a task for your log platform. Operator-side deletion without the user is not packaged as a command yet (`Store.delete_user`, see the [administrator guide](admin-guide.md#11-incident-response-checklist)). |
| Restriction (Art. 18) and objection (Art. 21) | A user can remove an account, reduce or disconnect an application, or delete everything. The operator can set the deployment read-only. There is no per-user "restrict" switch for the operator. |
| Not subject to automated decisions (Art. 22) | The software makes no decisions about people. What the AI client does with mail is outside it. |
| Notification of recipients (Art. 19) | The service does not pass personal data to recipients other than the AI client the user connected, the mail provider and your processors. |

## 6. Sub-processors and recipients to consider

* **Cloud hosting** (compute, database, secrets, logs, load balancer): your processor. Sign a data
  processing agreement; check the region (Firestore location is fixed at creation; a single region
  keeps data in one place), the provider's sub-processors and its audit access to your data.
* **Mail provider(s)**: the mailboxes. The service logs in with the user's own credentials and
  reads or writes exactly as a mail program would. Check the provider's terms for automated or
  third-party access, and allow-listing of the service's IP address (a static egress address is
  optional, see [deploy-gcp.md](deploy-gcp.md#7-static-egress-ip-for-mail-servers-optional)).
* **AI client vendor** - *the most important point.* The assistant reads mail **because the user
  asks it to**, and the content of that mail (including personal data of correspondents, and
  attachments if requested) is sent to the AI vendor to be processed by its model, under that
  vendor's terms, not yours. The operator of this server does not control it, cannot see it and
  is not the vendor's processor. Consequences: tell users plainly; decide which AI clients are
  acceptable for your organisation (business terms with a data processing agreement and no
  training on inputs, versus consumer terms); restrict permissions (read-only by default);
  consider whether certain mailboxes (HR, health, legal privilege) must not be connected; and
  include the AI vendor as a recipient in your records of processing and privacy notice.
* **Message viewer**: mail is shown in the user's own browser; no additional party.
* **Support or monitoring tools** you attach to the logs.

## 7. International transfers

Transfers can occur with: the cloud provider (its region and support access), the AI client
vendor (often outside the EU/EEA, depending on the vendor's service and region), and mail providers
if outside the EU/EEA. Considerations: adequacy decision or standard contractual clauses with a
transfer impact assessment where needed; the region of the store and logs; whether the vendor
offers an EU data location. The software itself sends nothing anywhere else: it makes outbound
connections only to the mail servers, to fetch OAuth client metadata documents (HTTPS URLs named by
the client; the document is fetched, nothing else) and to its cloud store.

## 8. Technical and organisational measures in the software

What the code implements today, as input to your Art. 32 documentation (it does not replace your
own organisational measures):

* **Encryption at rest**: mail passwords, SMTP passwords, server settings, primary address,
  identity data and activity are sealed with AES-256-GCM under a versioned key ring; the
  associated data binds a blob to its user, record kind and id, so it cannot be moved to another
  record. Key rotation without downtime is supported. The store holds no mail content.
* **Tokens and sessions**: random 256-bit values, only keyed digests (HMAC) stored; refresh-token
  rotation with replay detection (a reused token revokes the whole grant); short access-token
  lifetime (1 hour); audience binding to the resource (RFC 8707); PKCE S256 for every client.
* **Pseudonymisation**: user ids and all identifiers in logs are keyed HMACs; the activity feed
  keeps ids and counts only.
* **Access control**: sign-in verifies the password against the mail server *you* assign to the
  domain; effective rights are the intersection of account permissions, grant, token and policy,
  checked on every call and per account; each request sees only its own user's records; message ids
  and cursors are resolved inside the caller's own view; sensitive portal actions require
  re-entering the password; sends need confirmation or portal approval, with sealed, user- and
  grant-bound confirmation state and a replay guard.
* **Web hardening**: strict CSP (no scripts at all on portal and consent pages), `__Host-` cookies
  (`Secure`, `HttpOnly`, `SameSite=Lax`), CSRF tokens plus `Sec-Fetch-Site` checks, `Host` and
  `Origin` checks, HSTS, `no-store`. Mail HTML is sanitised with an allow-list and shown in a
  sandboxed frame, optionally from a separate content origin, with remote images off by default.
* **Network safety**: all outbound connections resolve once, check every address against private,
  loopback and metadata ranges, connect to the checked address and verify TLS (1.2 or newer) for
  the host name (SSRF protection); no plain-text mail protocols.
* **Abuse protection**: rate limits on sign-in, authorisation, tokens, registration, portal,
  viewer, downloads and tool calls; caps on connections, parallel calls and sizes.
* **Prompt-injection hardening**: mail text is fenced as untrusted content and escaped; links
  defanged; outbound actions are decided by the user and the server's policy, never by mail
  content; no permanent deletion.
* **Logging and audit**: allow-listed audit events with pseudonyms and no content; users see their
  own activity; operators have the `audit` command; alerts on sign-in failures, token replay,
  send failures and rate-limit hits (examples in [deploy-gcp.md](deploy-gcp.md)).
* **Data subject tooling**: export and complete deletion in the portal; a retention view driven by
  the running configuration.
* **Supply chain**: locked dependencies, `pip-audit` and image scanning in CI, pinned base image,
  unprivileged container user.

Not provided by the software and left to you: network and platform security of the deployment,
administrator access control and logging on the cloud project, secret handling, backups,
incident handling and staff training. Known gaps are in `TODO.md` (for example per-instance rate
limit counters, no operator-side per-user revocation or deletion command, no automatic rotation of
the pseudonym key).

## 9. What the operator still has to do

1. Decide and document the **role** (controller or processor) and the **legal bases** (section 3).
2. Add the service to your **records of processing** (Art. 30): purposes, categories of data and
   data subjects (users, their correspondents), recipients (cloud provider, mail provider, AI
   vendor), transfers, retention (section 4), measures (section 8).
3. Conclude **data processing agreements** with the cloud provider and any other processor; check
   the AI vendor's terms and decide which clients are allowed.
4. Carry out a **DPIA** where required (this kind of processing - systematic access to
   private mail by an AI system - will usually call for one): use [dpia-template.md](dpia-template.md).
5. Publish a **privacy notice** (template below) and give staff or users usage rules (what may be
   connected, which permissions, review before sending).
6. Set the **log retention** and restrict log access; where works-council or staff-representation
   rules apply, involve them before launch.
7. Define how you answer **access and erasure requests** (including logs and backups) and who is
   the contact; check the data subject can reach it.
8. Define the **incident procedure** and the 72 hour notification path (Art. 33); the checklist is
   in the [administrator guide](admin-guide.md#11-incident-response-checklist).
9. Keep the keys and the cloud project's administrator access under review.

### Template paragraph for a privacy notice

Adapt and complete; check with your counsel.

> **AI assistant access to your mailbox ([OPERATOR: service name]).** If you connect an AI
> assistant to your mailbox through [OPERATOR: service name], operated by [OPERATOR: organisation,
> contact, data protection contact], we store the settings you give us (your mailbox address, the
> login data for your mail account in encrypted form, sender identities, the applications you
> connected and the permissions you gave them) and a record of what your connected applications did
> (for example "searched mail 14 times"; no mail content) for 30 days, which you can see under
> *Activity*. We do not store the content of your mail. When your assistant reads mail on your
> request, the content is passed through our service to the assistant you connected, which is
> operated by [OPERATOR: AI vendor], and is processed there under [OPERATOR: its terms / our
> agreement]. We keep technical log entries that use a pseudonym instead of your address for
> [OPERATOR: retention, e.g. 90 days] to secure and operate the service. The legal basis is
> [OPERATOR: e.g. Art. 6(1)(b) / (f) GDPR]. Our service providers are [OPERATOR: cloud provider,
> region]. You can download or delete all stored data yourself under *Privacy* in the portal, and
> disconnect applications at any time under *Connected applications*. You also have the rights to
> access, rectification, restriction, objection and to complain to a supervisory authority; contact
> [OPERATOR: contact].
