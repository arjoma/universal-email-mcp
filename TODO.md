# TODO — later (not v1)

Ideas parked for after 0.1.0. See `docs/plans/2026-09-30-design.md` for the v1 scope.

## Attachments
- [ ] Read and make sense of attachments: PDF text extraction (pypdf), then
      office formats (docx, xlsx, odt), images via the AI client (embedded resource).
- [ ] Bounded extraction (page/char limits, timeouts, zip-bomb/resource guards).
- [ ] Attachment-aware search ("the PDF invoice from Huber") and summaries.

## Accounts and auth
- [ ] OIDC SSO for the portal (Entra ID, Keycloak, Authentik, Google, …).
- [ ] Admin-managed shared mailboxes granted to several users.
- [ ] OAUTHBEARER / XOAUTH2 to mail servers that offer it (Microsoft 365 only on demand).

## Platform
- [ ] SQLite store for single-VM / on-prem deployments.
- [ ] More provider presets (IONOS, Strato, World4You, Hetzner, all-inkl, …),
      each validated with `probe`.
- [ ] JMAP backend.

## Repository
- [ ] Before adding collaborators: tag ruleset `v*` (restrict create/update/delete,
      bypass: repository admin) so only admins can trigger PyPI releases. The `pypi`
      environment is already restricted to `v*` tags.

## Targets from real use (planned for M2, see design §7.2)
- [ ] Fuzzy matching of hierarchical folders used as labels (`Clients/<name>`, any group).
- [ ] Archive action like the webmailer's (probably `Archive/<year>` — verify with `probe`).
- [ ] Move mail between folders, incl. "move the mail from X and my answer to client X".
- [ ] File replies: the Sent copy of a reply goes into the conversation's folder too.
- [ ] Label management: list (tree) and create first; rename / move / delete folders later.
