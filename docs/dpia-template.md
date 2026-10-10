# Data protection impact assessment (DPIA) template

A fill-in template for an assessment under Art. 35 GDPR of an organisation running
universal-email-mcp in remote mode. It is pre-filled with what the software does and which
measures it implements (verified against the code, see [gdpr.md](gdpr.md) and the pages it links);
everything the operator has to decide or confirm is marked **`[OPERATOR: ...]`**. **This is not legal advice**; have your data protection officer
review the result and record their advice (Art. 35(2)).

Document control: version `[OPERATOR: ]`, date `[OPERATOR: ]`, author `[OPERATOR: ]`, DPO consulted
`[OPERATOR: name, date, advice]`, next review `[OPERATOR: e.g. yearly or on a major change]`.

## 1. Description of the processing

### 1.1 Nature

| Item | Content |
|---|---|
| Controller | `[OPERATOR: organisation]` (or processor acting for `[OPERATOR: controller]`) |
| Service name and URL | `[OPERATOR: e.g. https://mail.example.org]` |
| What the service does | Lets AI assistants chosen by the user read and, if allowed, organise, delete, draft and send mail in the user's IMAP/POP3/SMTP mailboxes through the MCP protocol. Users sign in with their mailbox login, give each assistant explicit permissions on a consent page, and manage everything in a self-service portal. |
| Processing operations | Authentication and authorisation (OAuth 2.1); storing encrypted mailbox credentials and settings; fetching mail from the mail server on request and passing it to the user's AI client or browser; writing drafts, sent copies and flag/folder changes to the user's mailbox; sending mail through the user's SMTP server after confirmation; audit logging; own-activity feed; export and deletion. |
| Technology | Container on `[OPERATOR: e.g. Google Cloud Run, region]`, store `[OPERATOR: e.g. Firestore, location]`, secrets in `[OPERATOR: secret manager]`, logs in `[OPERATOR: log bucket, retention]`. Open-source software, version `[OPERATOR: ]`. |
| Mode and policy | `UEM_READ_ONLY=[OPERATOR: ]`, `UEM_SEND_POLICY=[OPERATOR: ]`, `SEND_FALLBACK=[OPERATOR: ]`, `MAIL_SERVERS=[OPERATOR: fixed list or free entry]`, `LOGIN_DOMAINS=[OPERATOR: ]`. |
| AI clients permitted | `[OPERATOR: which clients/vendors, under which contract]` |

### 1.2 Scope

* Data subjects: users `[OPERATOR: staff / members / customers, number]`; **correspondents** of
  the users (senders and recipients of mail, unbounded and unaware).
* Categories of personal data: see [gdpr.md section 2](gdpr.md#2-personal-data-involved). In short:
  credentials and settings (stored encrypted); pseudonymous activity and log data; and, transiently,
  **the full content of whatever mail the user's assistant is asked to read**, which can contain any
  category of data, including special categories (Art. 9) and data about third parties
  `[OPERATOR: assess which mailboxes may contain such data]`.
* Volume and frequency: `[OPERATOR: users, calls per day]`. Retention: [gdpr.md section 4](gdpr.md#4-retention)
  `[OPERATOR: deviations]`.
* Geographic scope: `[OPERATOR: regions of hosting, mail providers, AI vendor processing]`.

### 1.3 Context

Relationship to data subjects (employment, membership, customer) `[OPERATOR: ]`; their reasonable
expectations `[OPERATOR: ]`; vulnerable groups `[OPERATOR: none / employees: power imbalance]`;
prior concerns or works council position `[OPERATOR: ]`; state of the art of the technology
(AI assistants acting on private mail is a novel use with an evolving risk picture, notably prompt
injection).

### 1.4 Purposes and legal basis

Purposes: [gdpr.md section 3](gdpr.md#3-purposes-and-possible-legal-bases). Legal basis chosen:
`[OPERATOR: Art. 6(1)(b) / (f) / (a); for special categories Art. 9 condition if applicable]`.
Legitimate interest assessment, where used: `[OPERATOR: ]`.

## 2. Necessity and proportionality

| Question | Answer |
|---|---|
| Is the purpose achievable with less data? | The service stores **no mail content** and only the data needed to act for the user. Assistants only receive mail the user asks for, in bounded amounts (result, body and attachment size caps; `[OPERATOR: adjust limits]`). |
| Data minimisation by default | Only `read` is pre-ticked at consent; accounts default to the permissions the user sets; sending needs an extra password check and explicit identity setting; activity feed holds no content; logs hold no addresses or content. |
| Storage limitation | Short lifetimes for sessions, tokens, approvals; activity 30 days; log and backup retention `[OPERATOR: ]`. |
| Transparency | Privacy page (what is stored, with live counts and retention), activity feed, consent page naming the application and permissions; privacy notice `[OPERATOR: link]`. |
| Data subject rights | Export and delete-all in the portal; log and backup handling per [gdpr.md section 5](gdpr.md#5-data-subject-rights-and-the-features-that-serve-them) `[OPERATOR: process, contact]`. |
| Processors | `[OPERATOR: list with DPA status]`; transfers `[OPERATOR: mechanism]`. |
| Alternatives considered | `[OPERATOR: e.g. no AI access; local mode per user; read-only]` |
| Is use of the AI vendor necessary and proportionate? | `[OPERATOR: justify; note that mail content flows to the vendor on user request]` |

## 3. Risk assessment

Scale. Likelihood: low / medium / high. Severity (for the persons concerned): low / medium / high /
very high. "Residual" is the assessment after the measures; the pre-filled values are a starting
proposal for a deployment that follows the [administrator guide](admin-guide.md) - **review and
change them for your situation** `[OPERATOR: confirm every row]`.

| # | Risk | Likelihood (inherent) | Severity | Measures in the software | Measures the operator must add `[OPERATOR: ]` | Residual |
|---|---|---|---|---|---|---|
| R1 | **Credential theft**: mailbox passwords taken from the store, memory, backups or secrets | medium | very high (access to the whole mailbox and possibly other services using the same password) | Passwords sealed with AES-256-GCM, bound to user/record; key ring versioned and rotatable; secrets only from the environment/secret manager, never logged; decrypted only in instance memory and dropped when idle; sign-in verifies against an operator-assigned server; users can opt out of storing the password at sign-in; `REAUTH_REQUIRED` handling avoids retry storms; per-user isolation | Restrict who can read the two secrets and the database; Secret Manager audit logs and alerts; separate runtime identity with least privilege; protect backups; key rotation schedule; incident process; ask users to use app-specific mail passwords where the provider offers them | `[OPERATOR: e.g. medium]` |
| R2 | **Token theft**: an access or refresh token of an AI client is stolen | medium | high | Opaque 256-bit tokens, only keyed digests stored (a database writer cannot mint a token); every record is MAC-protected against changes in the database; access token 1 h; refresh rotation with replay detection (reuse revokes the grant); absolute grant lifetime 90 days; tokens bound to the resource; PKCE; HTTPS and HSTS; tokens never in URLs or logs; users can disconnect at once; per-grant rate limits; permissions limited by grant ∩ account ∩ policy | Keep `UEM_REFRESH_TOKEN_TTL` and `UEM_SESSION_MAX_AGE` finite; alert on token replay; user guidance; TLS configuration of the front end | `[OPERATOR: ]` |
| R3 | **Prompt injection** in incoming mail makes the assistant send unwanted mail, change mail, or **exfiltrate** other mail to an attacker through the AI client or a link | high (cannot be excluded for any model) | high | Mail text fenced as untrusted and escaped; links/images defanged; outbound sends only after user confirmation or portal approval **when `UEM_SEND_POLICY` is `confirm`/`confirm-external` and `SEND_FALLBACK=portal`** (policy `on` and `send-unless-flagged` skip the question for known recipients; a client that auto-accepts elicitation defeats it); look-alike recipients always put to a human; new addresses flagged; recipient domain allow-list, recipient and rate limits; draft first; send needs an identity with sending enabled and a separate grant; no permanent deletion; bounded outputs; viewer shows HTML without scripts and without remote images; actions are limited by the permissions the user gave; user activity feed and audit | Choose `UEM_SEND_POLICY=confirm` (or stricter) and `SEND_FALLBACK=portal`; set `UEM_ALLOWED_RECIPIENT_DOMAINS`/`UEM_INTERNAL_DOMAINS`; start read-only; train users to read confirmations; **residual exfiltration path**: the assistant may place read mail into its own output or into requests the AI client makes (e.g. web access, other connectors) - the server cannot prevent this; restrict which AI clients/connectors are allowed and keep sensitive mailboxes disconnected | `[OPERATOR: ]` |
| R4 | **Over-broad grants**: users tick more than needed, or accounts are left with broad permissions; forgotten connections | high | medium to high | Only `read` pre-ticked; permissions are the intersection of account, grant, token and policy; per account; send needs password re-entry and a separate identity flag; grants expire (30 days idle, 90 days absolute); list of connected applications with last-use dates; users may reduce or disconnect; client names escaped, unverified names flagged | Policy that caps rights (`UEM_READ_ONLY`, `UEM_SEND_POLICY`); user guidance; periodic reminders; consider shorter lifetimes | `[OPERATOR: ]` |
| R5 | **Log leakage**: pseudonymous logs reveal who uses the service and when, or are misused; logs forged | medium | medium | Allow-listed events; no addresses, subjects, bodies, folder or file names, search terms, tool arguments, tokens, passwords, client or account names, or IP addresses (network pseudonym only if enabled); keyed pseudonyms; `audit` CLI treats the log as untrusted input | Dedicated log bucket with retention and restricted access `[OPERATOR: retention, who]`; keep `AUDIT_LOG_CLIENT_IP` off unless needed; protect the pseudonym key separately from the logs; purpose limitation; staff representation where required; platform/load-balancer logs reviewed (they may contain IPs) | `[OPERATOR: ]` |
| R6 | **Operator and administrator access**: staff with cloud access read the store, secrets or logs; an insider cuts users off or impersonates | medium | high | The store holds no mail; sensitive fields are sealed; the audit log and activity feed record sends and approvals; the service offers no operator view of mail content | Least-privilege IAM, separation of duties between those who can read the secrets and the database, admin audit logging and alerts, background checks and confidentiality duties, documented admin procedures `[OPERATOR: ]`. **Note** the operator can in principle obtain the keys and decrypted passwords (a compromised or malicious instance holds them) - this must be accepted or mitigated organisationally | `[OPERATOR: ]` |
| R7 | **Provider outage or loss**: the cloud platform, store or mail provider is unavailable, data or keys are lost | medium | low to medium | Stateless instances; `/ready` and `/health` probes; point-in-time recovery and backup guidance; delete protection; mail itself stays at the provider; errors are explicit (`SERVER_UNREACHABLE`, `TIMEOUT`); caps avoid overloading mail servers | Monitoring and alerts; tested restore; key and secret version retention; multi-region or recovery objectives `[OPERATOR: RTO/RPO]`; communication plan | `[OPERATOR: ]` |
| R8 | **Third-party content flow to the AI vendor** (correspondents' data, special categories) without their knowledge or an adequate basis | high | high | None technically beyond permissions: the user decides what the assistant reads; read-only default | Contract and terms with the AI vendor, transfer mechanism, restrict allowed clients and mailboxes, usage rules, user training, inform in the privacy notice, consider exclusion of sensitive folders by organisational rule | `[OPERATOR: ]` |
| R9 | **SSRF or abuse of the server as a proxy**: a user-supplied host or client metadata URL is used to reach internal systems or to attack third parties | low | high | Resolve once, check every address, connect to the checked address, TLS verified; private/loopback/metadata ranges refused; ports restricted for free entry; metadata documents size/time limited, no redirects; rate limits | Prefer a fixed `MAIL_SERVERS` list; keep `UEM_ALLOW_PRIVATE_NETWORKS` off; egress filtering at network level | `[OPERATOR: ]` |
| R10 | **Account takeover of the portal** (phishing, password reuse) and malicious HTML in the viewer | medium | high | Sign-in verified against the mail server; rate limits per address and network; re-authentication for sensitive actions; CSRF, CSP without scripts, `__Host-` cookies; sandboxed, sanitised mail HTML from a separate origin; downloads served as attachments with `nosniff` | Set `CONTENT_ORIGIN`; user awareness; monitor sign-in failures; MFA at the mail provider (the sign-in reuses the mailbox password; there is no second factor in the portal itself) | `[OPERATOR: ]` |
| R11 | **Incomplete erasure or access**: logs and backups keep data after a request | medium | low to medium | Delete-all removes live records at once; export covers stored records; `audit --user` finds log lines | Retention concept for logs and backups; process for requests `[OPERATOR: ]` | `[OPERATOR: ]` |

Add rows for risks specific to your organisation `[OPERATOR: ]`.

## 4. Measures summary

Implemented in software: [gdpr.md section 8](gdpr.md#8-technical-and-organisational-measures-in-the-software).
Operator measures decided in this assessment: `[OPERATOR: list, owner, due date]`.

## 5. Result and consultation

| Item | Content |
|---|---|
| Overall residual risk | `[OPERATOR: low / medium / high]` |
| Any high residual risk not mitigated? | `[OPERATOR: if yes, consult the supervisory authority before processing (Art. 36)]` |
| Views of data subjects or their representatives (Art. 35(9)) | `[OPERATOR: works council / user survey / reason for not seeking]` |
| DPO advice | `[OPERATOR: ]` |
| Decision to proceed, by whom, date | `[OPERATOR: ]` |
| Review triggers | new version with changed stored data or tools; new AI client or vendor; new mail provider; incident; yearly `[OPERATOR: ]` |
