# Deploying on Google Cloud (Cloud Run + Firestore)

A generic walk from an empty Google Cloud project to a running multi-user instance
(remote mode, design section 11). It uses the files in [`deploy/gcp/`](../deploy/gcp):

| File | Purpose |
|---|---|
| `bootstrap.sh` | One-time, repeatable setup: APIs, service accounts, Artifact Registry, Firestore with TTL policies, secrets with generated keys. |
| `cloudbuild.yaml` | Build the image (with the `gcp` extra), push it, deploy by digest. |
| `service.yaml` | Cloud Run service template (Knative); `render.sh` fills the `__PLACEHOLDERS__`. |

All names below are placeholders: `PROJECT_ID`, `REGION`, `mail.example.org` (the public
host), `mail-content.example.org` (the viewer's content host), `imap.example.org` (a mail
server). **Nothing instance-specific belongs in this repository**; see
[Private deploy repository](#private-deploy-repository).

The container itself is not Google-specific (any container platform with a Firestore
project, or later the SQLite store, can run it); this document describes the reference
setup. Every setting is explained in [operator-env.md](operator-env.md), the stored data
and keys in [stored-data.md](stored-data.md), the sign-in flow in [oauth.md](oauth.md).

## 0. Prerequisites and decisions

- A Google Cloud project with billing, `gcloud` installed and logged in (`gcloud auth login`),
  `openssl`. You need Owner (or equivalent) on the project for the bootstrap.
- A domain you control, with a host name for the service (`mail.example.org`) and, strongly
  recommended, a **second** host name for the message viewer's HTML (`CONTENT_ORIGIN`,
  `mail-content.example.org`) so that mail HTML never shares an origin with the portal.
- The e-mail domains whose users may sign in and the IMAP server used for the login check
  (`LOGIN_DOMAINS=example.org=imap.example.org`), and the servers users may add
  (`MAIL_SERVERS`; **empty means free entry** of any public host, list at least one to forbid it).
- Region: pick one close to users and to the mail server. Firestore's location is fixed
  once created (a multi-region such as `eur3` survives a region outage; a single region is
  cheaper and keeps the data in one place).

## 1. Bootstrap the project

```bash
export PROJECT_ID=my-project REGION=europe-west1
gcloud config set project "$PROJECT_ID"
DRY_RUN=1 deploy/gcp/bootstrap.sh   # prints every gcloud command, changes nothing
deploy/gcp/bootstrap.sh
```

What it does (each step first checks whether the thing exists, so it can be re-run):

1. Enables the Cloud Run, Cloud Build, Artifact Registry, Firestore, Secret Manager,
   Logging, Monitoring and IAM APIs.
2. Creates two service accounts and grants least privilege:

   | Account | Roles | Why |
   |---|---|---|
   | runtime `uem-runtime` | `roles/datastore.user` (project; the project should hold only this database) and `roles/secretmanager.secretAccessor` **on the two secrets only** | The service reads and writes Firestore and reads its two keys. It cannot create secrets, read other secrets, delete the database or touch anything else. Logging needs no role (Cloud Run writes the container's output). |
   | build `uem-build` | `roles/run.admin`, `roles/logging.logWriter` (project), `roles/iam.serviceAccountUser` on the runtime account, `roles/artifactregistry.writer` on the one repository, `roles/storage.objectViewer` on the source bucket | Builds, pushes and deploys; it cannot read secrets or Firestore. |

3. Creates the Artifact Registry repository, a private source bucket for Cloud Build
   (public access prevention on) and the Firestore database in **native mode** with delete
   protection and point-in-time recovery.
4. Enables **TTL policies** on `expires_at` for `portal_sessions`, `oauth_clients`,
   `auth_codes`, `grants`, `tokens`, `approvals`, `activity` (the same list as in
   [stored-data.md](stored-data.md); with `FIRESTORE_PREFIX` the script uses the prefixed
   names). The policies finish creating in the background (minutes to an hour); the server
   treats expired records as absent anyway, so deletion delay has no effect on behaviour.
   No composite indexes are needed (single-field equality queries only), so there is no
   `firestore.indexes.json`.
5. Creates the secrets **with generated keys, never printed**: `uem-store-keys`
   (`k1=<base64 32 bytes>`, the AES-256-GCM key ring) and `uem-pseudonym-key`
   (the HMAC secret behind the pseudonymous user ids). A secret that already has a version
   is left alone, so a re-run cannot replace a key by accident.

Environment variables adjust names and locations (`FIRESTORE_LOCATION`, `REPO`,
`RUNTIME_SA`, `BUILD_SA`, `FIRESTORE_PREFIX`, secret names); see the header of the script.
Only if a mail server must allow-list the instance's address, also do step 7 now.

> The pseudonym key and the key ring are the crown jewels: the pseudonym key can **never**
> change (users are keyed by it), the key ring only through the rotation procedure below.
> Restrict who may read or administer these two secrets (`roles/secretmanager.admin` is
> enough to read every version), and keep Secret Manager audit logs on.

## 2. Build and deploy

```bash
gcloud builds submit --config deploy/gcp/cloudbuild.yaml --region "$REGION" \
  --gcs-source-staging-dir "gs://${PROJECT_ID}-uem-build-src/source" \
  --substitutions '^;^_REGION=europe-west1;_PUBLIC_URL=https://mail.example.org;_CONTENT_ORIGIN=https://mail-content.example.org;_LOGIN_DOMAINS=example.org=imap.example.org;_MAIL_SERVERS=imap.example.org' .
```

The build runs as `uem-build`, builds the `Dockerfile` with `EXTRAS=gcp`, pushes
`REGION-docker.pkg.dev/PROJECT_ID/REPO/universal-email-mcp:<build id>`, resolves the
image **digest** and applies the rendered `service.yaml` with
`gcloud run services replace`. Substitutions: `_REGION`, `_SERVICE`, `_REPO`, `_IMAGE`,
`_RUNTIME_SA`, `_BUILD_SA`, `_PUBLIC_URL`, `_CONTENT_ORIGIN`, `_LOGIN_DOMAINS`,
`_MAIL_SERVERS`, `_FIRESTORE_PREFIX`, `_INGRESS`, `_MIN_INSTANCES`, `_MAX_INSTANCES`,
`_TRUSTED_PROXY_HOPS` (defaults in the file). Settings that are not substitutions
(limits, policy, token lifetimes; [operator-env.md](operator-env.md)) are added as `env`
entries to your copy of `service.yaml`, or `gcloud run services update --update-env-vars`.

### Choices in `service.yaml`

| Setting | Value | Reason |
|---|---|---|
| Authentication | Cloud Run IAM **off** (`run.googleapis.com/invoker-iam-disabled`) | This is a public OAuth 2.1 server: AI clients and browsers have no Google identity. Authentication is the server's own (OAuth tokens on `/mcp`, sign-in sessions on the portal). `--no-allow-unauthenticated` would break every client. The annotation replaces an `allUsers` invoker binding, which "domain restricted sharing" org policies forbid. |
| Ingress | `all`; `internal-and-cloud-load-balancing` with a load balancer | See section 4. Behind a load balancer, close the direct `*.run.app` path (or set `default-url-disabled`). |
| Execution environment | gen2 | Full Linux compatibility, better network performance for many outbound TLS connections. |
| Instances | min 0 (pilot with users: 1), max 3 | State is in Firestore, nothing is shared in memory. `max x UEM_MAX_CONNECTIONS` (default 200) bounds the connections to mail servers, which often cap them per mailbox. Rate-limit counters and header caches are per instance. |
| Concurrency | 40 | Requests are I/O bound; the per-user caps (`UEM_MAX_CONCURRENT_CALLS_PER_USER`) apply on top. |
| CPU / memory | 1 vCPU, 512 MiB, startup CPU boost, request-based billing | Per-user services and header caches are bounded (`UEM_MAX_CACHED_USERS`). Raise memory if `/ready` or the Cloud Run metrics show pressure; large attachments are streamed, not buffered. |
| Request timeout | 300 s | Streaming attachment downloads and SSE responses; the 60 s default cuts them off. Max 3600 s. |
| Probes | startup `/ready`, liveness `/health` | `/ready` checks the loaded config and one Firestore round trip, so a revision with a wrong key or missing permission never receives traffic. `/health` has no dependencies. Both ignore the `Host` header. |
| Secrets | `secretKeyRef` to `latest` | Mounted as environment variables at start; the value never appears in the service definition, build logs or revision. A new secret version needs a new revision (deploy again) to take effect. |
| `UEM_TRUSTED_PROXY_HOPS` | `1` | Cloud Run adds one proxy; decides which `X-Forwarded-For` entry rate limits use. With an external load balancer verify the value (it adds a hop) by checking the client address in the logs; a wrong value either counts the proxy or lets a forged header dodge limits. |

After the first successful deploy, check:

```bash
URL=$(gcloud run services describe universal-email-mcp --region "$REGION" --format 'value(status.url)')
curl -s "$URL/health"                              # {"status":"ok"}
curl -s -H "Host: mail.example.org" "$URL/ready"   # exempt from Host checks; 200 when the store works
```

The run.app URL itself answers 421 on other paths until you add its host to
`ALLOWED_HOSTS`; production traffic uses the custom domain.

## 3. Domain, `PUBLIC_URL` and DNS

`PUBLIC_URL` (`https://mail.example.org`) is the OAuth issuer, the base of the metadata
URLs and the resource identifier (`PUBLIC_URL/mcp`). Clients and tokens are bound to it:
**choose it once**; changing it later logs everybody out and breaks connected clients.
The server sends HSTS when `PUBLIC_URL` is https.

## 4. Custom domain: Cloud Run domain mapping or a load balancer

| | Domain mapping | External Application Load Balancer (recommended) |
|---|---|---|
| Setup | `gcloud beta run domain-mappings create`, add the DNS records it prints | Reserve a static IP, serverless NEG, backend service, URL map, managed certificate, forwarding rule |
| Availability | Preview feature, only some regions, higher latency | Generally available, global anycast |
| Certificates | Managed | Google-managed (multi-host) or your own |
| Cloud Armor (rate limiting, geo/IP rules, WAF) | No | Yes |
| Ingress lock-down | No (ingress must be `all`) | Yes (`internal-and-cloud-load-balancing`) |
| Several host names (`mail` + `mail-content`) | One mapping each | One URL map, one certificate |
| Cost | none extra | forwarding rule, roughly 18 USD/month plus traffic |
| Headers / HSTS | untouched | untouched (the server sets HSTS itself); you can add more in the backend service |

For a pilot, domain mapping is fine; for a production instance take the load balancer.
Sketch (details and current flags: Google Cloud documentation "Set up a global external
Application Load Balancer with Cloud Run"):

```bash
gcloud compute addresses create uem-ip --global
gcloud compute network-endpoint-groups create uem-neg --region "$REGION" \
  --network-endpoint-type serverless --cloud-run-service universal-email-mcp
gcloud compute backend-services create uem-backend --global --load-balancing-scheme EXTERNAL_MANAGED
gcloud compute backend-services add-backend uem-backend --global \
  --network-endpoint-group uem-neg --network-endpoint-group-region "$REGION"
gcloud compute url-maps create uem-map --default-service uem-backend
gcloud compute ssl-certificates create uem-cert --global \
  --domains mail.example.org,mail-content.example.org
gcloud compute target-https-proxies create uem-proxy --url-map uem-map --ssl-certificates uem-cert
gcloud compute forwarding-rules create uem-https --global --load-balancing-scheme EXTERNAL_MANAGED \
  --address uem-ip --target-https-proxy uem-proxy --ports 443
```

Point both DNS names at the reserved address (A/AAAA); the certificate becomes active
once DNS resolves. Add a port-80 URL map that redirects to https (HSTS is only honoured
over https). Both host names go to the **same** backend: the server tells them apart by
`Host` (`PUBLIC_URL` vs `CONTENT_ORIGIN`); only `/c/*` is used on the content host. Then
redeploy with `_INGRESS=internal-and-cloud-load-balancing` and consider
`_TRUSTED_PROXY_HOPS=2`. Verify the hop count from a request log (the client address that
rate limits use must be yours, not the load balancer's or Google's).

Optional Cloud Armor policy: a per-IP rate-limit rule on `/authorize`, `/token`,
`/register` and the portal sign-in (until the server-side rate limits of M4 exist).

Check the result from outside: `curl -sI https://mail.example.org/health` shows
`Strict-Transport-Security`; `https://mail.example.org/.well-known/oauth-protected-resource`
names the `/mcp` resource; `/mcp` without a token answers 401 with a `WWW-Authenticate`
header.

## 5. Sign-in, mail servers and `CONTENT_ORIGIN`

- `LOGIN_DOMAINS=example.org=imap.example.org[,other.org=imap.other.org]`: only these
  e-mail domains can sign in; the named server verifies the password. Required.
- `MAIL_SERVERS`: what users may add in the portal. Prefer a fixed list over free entry;
  free entry only reaches public addresses (ports 993/995/465/587, verified TLS, private and
  metadata addresses refused) but lets users point the server at arbitrary hosts.
- `CONTENT_ORIGIN`: set it. Mail HTML is rendered in a sandboxed frame from the second
  origin; without it the viewer falls back to an inline sandbox that shares the portal
  origin. The content host must be routed to the same service (section 4), have its own
  certificate name, and use the same scheme as `PUBLIC_URL`.
- `UEM_ALLOW_PRIVATE_NETWORKS` stays at its remote-mode default (`false`).

## 6. Connect a client

Add `https://mail.example.org/mcp` as a remote MCP server in the client; it discovers the
authorization server from the 401 response, signs the user in in the browser and shows the
consent page ([oauth.md](oauth.md)). Smoke test with the MCP Inspector first.

## 7. Static egress IP for mail servers (optional)

Cloud Run's outbound addresses are not fixed. If a mail server (or a firewall in front of
it) only accepts known addresses, send the egress through a VPC with Cloud NAT and a
reserved address. Mail ports 465/587/993/995 are open on Cloud Run, so skip this if the
server is public.

```bash
gcloud compute networks create uem-net --subnet-mode custom
gcloud compute networks subnets create uem-subnet --network uem-net --region "$REGION" --range 10.8.0.0/26
gcloud compute addresses create uem-egress-ip --region "$REGION"
gcloud compute routers create uem-router --network uem-net --region "$REGION"
gcloud compute routers nats create uem-nat --router uem-router --region "$REGION" \
  --nat-custom-subnet-ip-ranges uem-subnet --nat-external-ip-pool uem-egress-ip
gcloud compute addresses describe uem-egress-ip --region "$REGION" --format 'value(address)'
```

Deploy with `_NETWORK=uem-net _SUBNET=uem-subnet` after uncommenting the two
`network-interfaces` / `vpc-access-egress: all-traffic` annotations in `service.yaml`
(**Direct VPC egress**; a Serverless VPC Access connector works too but costs a
standing instance fee). All outbound traffic then leaves with the one address: give it to
the mail operator. Cost: Cloud NAT gateway plus the reserved address, roughly 35 to 40 USD
per month, plus per-GB traffic. NAT adds a small risk: all egress shares one address, so one
abusive user can get the address blocked by a mail server.

## 8. Key rotation

The key ring `STORE_KEYS` (`k1=...,k2=...`) seals the stored credentials
([stored-data.md](stored-data.md)). Rotate on a schedule, after a suspected leak, or when
someone who could read the secret leaves.

1. Add a key without removing the old one (the value goes straight into Secret Manager;
   do not paste it into a terminal history or a ticket):
   ```bash
   current=$(gcloud secrets versions access latest --secret uem-store-keys)   # stays in a variable
   printf '%s,k2=%s' "$current" "$(openssl rand -base64 32)" \
     | gcloud secrets versions add uem-store-keys --data-file=-
   unset current
   ```
2. Make `k2` the key for new blobs and deploy a new revision (the old keys still decrypt):
   `gcloud run services update universal-email-mcp --region "$REGION" --update-env-vars STORE_ACTIVE_KEY=k2`
   (put the same in your deploy substitutions; without `STORE_ACTIVE_KEY` the highest key is used,
   so the variable is optional).
3. Re-seal what nobody has written since, as a one-off Cloud Run job with the same image,
   service account and secrets (the command is safe to repeat; it prints counts per record kind):
   ```bash
   CODE='import asyncio
   from universal_email_mcp.operator import load_operator_config
   from universal_email_mcp.oauth.app import make_store
   from universal_email_mcp.store.rotation import rotate_keys
   async def main():
       store = make_store(load_operator_config())
       try:
           print(await rotate_keys(store))
       finally:
           await store.close()
   asyncio.run(main())'
   IMAGE=$(gcloud run services describe universal-email-mcp --region "$REGION" \
     --format 'value(spec.template.spec.containers[0].image)')
   gcloud run jobs deploy uem-rotate-keys --region "$REGION" --image "$IMAGE" \
     --service-account "uem-runtime@${PROJECT_ID}.iam.gserviceaccount.com" \
     --command python --args "^|^-c|$CODE" \
     --set-env-vars "STORE_BACKEND=firestore,FIRESTORE_PROJECT=${PROJECT_ID},PUBLIC_URL=https://mail.example.org,LOGIN_DOMAINS=example.org=imap.example.org,STORE_ACTIVE_KEY=k2" \
     --set-secrets "STORE_KEYS=uem-store-keys:latest,PSEUDONYM_KEY=uem-pseudonym-key:latest"
   gcloud run jobs execute uem-rotate-keys --region "$REGION" --wait
   ```
   (`FIRESTORE_PREFIX` and every other variable that affects the store must match the service.)
4. When the counts have dropped to 0 on a second run, remove `k1` from the ring: add a
   new secret version containing only `k2=...`, deploy again. **Keep the old secret version
   enabled until the backups that were sealed with `k1` have expired** (a restored backup
   needs the key that sealed it); destroy it afterwards.

Losing a key makes the blobs sealed with it unreadable (users have to add their mail
accounts again); the pseudonym key can never be rotated without a migration. Both secrets
have automatic versioning in Secret Manager: do not destroy versions casually. The job
and its definition can be deleted afterwards (`gcloud run jobs delete uem-rotate-keys`).

## 9. Backups

- **Point-in-time recovery** (enabled by the bootstrap): every version of every document
  for the last 7 days; restore by reading at a timestamp or cloning
  (`gcloud firestore databases clone`).
- **Scheduled backups**: `gcloud firestore backups schedules create --database '(default)'
  --recurrence daily --retention 14d`; restore with `gcloud firestore databases restore`
  into a **new** database, then point the service at it (`FIRESTORE_DATABASE`).
- Managed export to a bucket (`gcloud firestore export`) is an alternative for archives.
- The data is sealed with the key ring and keyed with the pseudonym key: **a backup is
  useless without both secrets**. Back up Secret Manager access by policy (keep versions;
  restrict `secretmanager.versions.access`), not by copying values around.
- Delete protection stops accidental `databases delete`; keep it on.

Test a restore once into a scratch database before you rely on it.

## 10. Logging, audit events and alerting

- The server logs **JSON lines on stdout** (`severity`, `message`, `logger`, plus fields);
  Cloud Run ships them to Cloud Logging, where `severity` is interpreted. HTTP request lines
  carry `event=http_request`, `route` (a pattern, never a message id or token), `status`,
  `duration_ms` and `request_id` (the same id is in the `X-Request-Id` response header).
- **Audit events** (`event`, `ts`, outcome, counts, size buckets, account names; never
  addresses, subjects, bodies, search terms or secrets) are JSON lines on stderr, which
  Cloud Run also collects (`jsonPayload.event`). Filter, for example:
  `resource.type="cloud_run_revision" AND jsonPayload.event=~"^(send|policy|portal.login)"`.
  The pseudonymous user id (`u_...`) is personal data for whoever holds the pseudonym key:
  route the service's logs to a dedicated log bucket with a defined retention (for example
  90 days), restrict access to it, and document the purpose (GDPR; in some countries works-council
  rules apply; not legal advice). The log fields are aligned with Cloud Logging in work package 3h.
- Never set `UEM_LOG_LEVEL=DEBUG` in production.
- **Alerting basics** (Monitoring):
  - Uptime check on `https://mail.example.org/ready` (alert if it fails from two regions).
  - Cloud Run `request_count` with `response_code_class=5xx` above a small threshold, and
    request latency p95.
  - Log-based metrics for `jsonPayload.event="ratelimit.hit"`, `policy.denied`, failed
    sign-ins, `send.failed`, with an alert on a sudden rise.
  - Secret Manager: an alert on `secretmanager.googleapis.com` access of the two secrets
    by anyone but the runtime account (Data Access audit logs).
  - Budget alert on the project.

## 11. Upgrade and rollback

Each deploy creates an immutable **revision** and by default sends 100 % of traffic to it
once its startup probe passes. If the probe fails the old revision keeps serving.

```bash
gcloud run revisions list --service universal-email-mcp --region "$REGION"
gcloud run services update-traffic universal-email-mcp --region "$REGION" --to-revisions REVISION=100   # rollback
gcloud run services update-traffic universal-email-mcp --region "$REGION" --to-latest
```

Before upgrading read the `CHANGELOG`. Stored records carry a format version (`_v`) and
the server reads older ones, but a rollback across a release that changed the stored
format may not be able to read what the newer version wrote: take a backup first and
roll back only within releases that did not change the store. For a cautious rollout
deploy with `--no-traffic --tag canary`, test the tagged URL that Cloud Run prints (`canary---...run.app`)
(add its host to `ALLOWED_HOSTS`) and then shift traffic.

The image base is pinned by digest in the `Dockerfile`; update the pin and rebuild
regularly (CI scans the image with Trivy and fails on fixed high/critical findings).

## 12. Cost notes

Orders of magnitude only; use the pricing calculator with your numbers.

- **Cloud Run** with request-based billing and min 0 instances: usually a few USD per
  month for a small team; min 1 instance adds the idle-instance price of 1 vCPU / 512 MiB
  (roughly 10 USD/month region-dependent). More instances only under load.
- **Firestore**: free quota covers a pilot; the access pattern is a few reads per tool call
  (the store is touched for tokens, grants and accounts; no mail is stored).
- **Secret Manager**, **Artifact Registry**, **Cloud Build**: cents (build minutes and
  stored images; clean old images with a cleanup policy).
- **Load balancer** (recommended): about 18 USD/month for the forwarding rule plus traffic.
- **Static egress** (optional): about 35 to 40 USD/month (Cloud NAT and address).
- **Logging**: free allotment per project; audit and request lines are small. Retention
  beyond the default 30 days costs storage.

## 13. Security checklist

- [ ] No `UEM_DEV_TOKEN` and no `--insecure-local` in the deployment (the service refuses
      OAuth mode combined with the token; check the revision's environment anyway).
- [ ] Secrets only in Secret Manager, referenced with `secretKeyRef`; not in `cloudbuild.yaml`,
      substitutions, trigger settings, `service.yaml`, images or any repository.
- [ ] Runtime service account has only `datastore.user` and access to its two secrets; no
      keys downloaded for any service account.
- [ ] `PUBLIC_URL` is the https custom domain; `ALLOWED_HOSTS` / `ALLOWED_ORIGINS` contain
      nothing you do not need (the `*.run.app` host only temporarily).
- [ ] `CONTENT_ORIGIN` set to a separate host name; both names covered by certificates.
- [ ] Ingress locked to the load balancer when one is used; Cloud Armor rate-limit rule on
      the sign-in and token endpoints.
- [ ] `MAIL_SERVERS` is a fixed list (or you accept free entry knowingly);
      `LOGIN_DOMAINS` lists only your domains.
- [ ] `UEM_SEND_POLICY` and `UEM_READ_ONLY` set to what the pilot needs (start with read-only);
      `UEM_TRUSTED_PROXY_HOPS` verified.
- [ ] Firestore: delete protection and PITR on, TTL policies active, only this service writes.
- [ ] Logs: dedicated bucket with retention; DEBUG off; access restricted.
- [ ] Alerts and a budget in place; restore tested; key rotation date in a calendar.
- [ ] The image is built from a reviewed commit, base image pinned, the Trivy job green.

## Private deploy repository

Keep everything that identifies an instance in a separate (private) repository that checks
out or pins this one. It typically holds:

- `instance.env`: the substitution values (`_REGION`, `_SERVICE`, `_PUBLIC_URL`,
  `_CONTENT_ORIGIN`, `_LOGIN_DOMAINS`, `_MAIL_SERVERS`, scaling, network names) and the
  project id; **no secret values**.
- A small `deploy.sh` that sources it and runs `gcloud builds submit` with the pinned
  version of this repository, so deployments are one reviewed command. The names of the
  secrets (`uem-store-keys`, `uem-pseudonym-key`) are the only secret-related facts to keep
  there.
- DNS and load-balancer definitions (or Terraform/gcloud scripts), the custom domain,
  alert policies and log-bucket settings, the list of people allowed to administer the
  secrets, and the incident/rotation calendar.
- Copies or overrides of `service.yaml` only where an instance needs more environment
  variables than this template has.
