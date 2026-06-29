### [359] Yahoo Calendar/Notes — "encrypted username" IDOR: `GET /ws/v3/users/<opaque>/items` looked encrypted, but supplying the PLAINTEXT yahoo username (or any other user's) returned their notes — encryption was cosmetic — John H4X00R ($5,000) [NEW ★ opaque id is decorative; server also accepts the cleartext id → downgrade]
- Where: `GET /ws/v3/users/<encrypted-or-plain-username>/items?...` (calendar.yahoo.com).
- Approach/how-found: noticed his username was sent as an opaque encrypted string; on a hunch he replaced it with his plaintext yahoo username → same notes returned; then swapped to a 2nd account's username → its notes. The app encrypted "for the eyes" but accepted plaintext usernames with no check.
- Test: when an id looks encrypted/hashed, try replacing it with the PLAINTEXT equivalent (raw username/email/numeric id) — backends often accept both; the "encryption" may be display-only.
- Q: "Does this endpoint also accept the plaintext username/id instead of the opaque token? Is the encryption actually enforced, or can I downgrade to cleartext and swap?"

### [360] Facebook Creators Studio — pending page roles disclosure: "Manage Page Roles" GET carries `page_id`; swap to any victim page → names + user ids of users invited to roles (incl. celebrity pages) — Avinash Kumar ($4,000) [DUP-reinforce: admin settings panel keyed on page_id]
- Where: Creators Studio "Manage Page Roles" GET request, `page_id` parameter.
- Approach/how-found: captured requests in the new Creators Studio; the manage-roles GET had a controllable `page_id`; swapping it returned pending role-invite names/ids for any page even with no role on it.
- Test: newly launched admin tools/dashboards (Creators Studio, beta consoles) often miss authz — capture every request and swap the container id (`page_id`/`account_id`).
- Q: "Do new/beta admin panels enforce authz on the container id? Can I read another page's roles/invites/settings by swapping page_id?"

### [361] CI/CD webhooks — delete any of 30,000+ via sequential id: `PUT /projects/<id>/notifications` (delete-webhook) carries an incremental webhook id; Intruder the id → delete all users' webhooks — Gujjuboy10x00 [DUP-reinforce: sequential id in a DELETE/state-change body → mass destruction]
- Where: `PUT /projects/<projectId>/notifications` body with sequential webhook id (`notifier:"deletewebhook"`).
- Approach/how-found: webhook ids were sequential (e.g. 1588211); created a 2nd account + webhooks, swapped the id in the delete request → deleted the other account's webhook; Intruder over `$ID$` → delete everyone's (30k+).
- Test: state-changing endpoints (delete/disable/cancel) with sequential ids in the body are mass-destruction IDORs — enumerate to gauge blast radius (even "old"/hardened targets miss these).
- Q: "Is the id in this delete/disable request sequential? Can I enumerate it to affect all users? Is this destructive action authz-checked at all?"
