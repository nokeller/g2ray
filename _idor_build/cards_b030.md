### [131] Google bughunters — submit a bug report as a victim by swapping the `email` in the submit request — Virtuvil [DUP reinforcement: action-as-victim via client-supplied email]
- Where: bughunters.google.com report submission.
- Approach/how-found: while submitting his own report he intercepted it, changed the email to `victim@mail.com` → 200, report filed under the victim's account (HTML/text injection also possible via other fields).
- Test: report/feedback/submission flows often stamp the submitter from a client-supplied email — swap it to file/act as another user.
- Q: "Does a submit/report action take a client-supplied `email`/owner I can swap to act as the victim?"

### [132] Invite-only app — brute 6-digit invite codes, then privesc via the SIGNUP `role` param (isAdmin→superAdmin) + ATO IDORs — evilmango [NEW ★ role mass-assignment at registration; revisit signup post-login]
- Where: registration requires a 6-digit invite code; responses expose `isAdmin`, later `isSuperAdmin`.
- Approach/how-found: no rate limit → Turbo Intruder brute-forced 6-digit invite codes (20-30 valid in 10 min) → registered. Post-login tampering of `isAdmin` failed. The breakthrough: the **signup** request (post-login, needs no invite code) accepts a `role` — set `role=admin` at signup → admin; the response then revealed `isSuperAdmin` → `role=superAdmin` → superadmin. Then IDORs (email+password in requests) → all-users ATO + data change.
- Test: brute short invite/referral codes when unthrottled. Privilege fields rejected post-login are often honored at **registration** — set `role`/`isAdmin` in the signup body; read responses for higher tiers (`isSuperAdmin`) to escalate again.
- Q: "Are invite/referral codes short and unthrottled? Does the SIGNUP request accept a `role`/`isAdmin` the post-login flow rejects? Do responses reveal a higher role to climb to?"

### [133] Defeat unguessable login/invite tokens by enumerating the URL-shortener hash that expands to them — Sicksec [NEW ★ shortener as the weak link]
- Where: passwordless logins / private invites sent as short links: `shortener/{HASH}` → `site.com/?token=<unguessable>`.
- Approach/how-found: the final `token` is unbruteforceable, but the **short hash** that redirects to it is short/sequential (or the links are harvestable from the company's Twitter/emails). Enumerate/expand the shortener hashes → recover the unguessable tokens → passwordless login/invite/ATO or info disclosure. (Trigger emails and view source for shortener links; scrape the company's posted links.)
- Test: when impact is blocked by an unguessable token, check if it's delivered via a URL shortener — enumerate/expand short hashes (or scrape published links) to recover the underlying token. Both third-party (bit.ly) and custom shorteners qualify.
- Q: "Are magic-login/invite tokens delivered via a shortener whose hash I can enumerate or scrape to recover the unguessable token?"

### [135] Private-project IDOR on the uploads/CDN subdomain (unauthenticated, id-enumerable) — Hamzadzworm [NEW: assets subdomain unauth + main≠subdomain security]
- Where: main site secure, but `uploads.target.com/get_image/project/<id>_282x210.png` serves project assets.
- Approach/how-found: a sibling subdomain shared the main login (reused creds → logged in). Project images came from an uploads subdomain keyed by project id → change the id → other users' projects, and it worked even **unauthenticated** (private browser) → view any private project. A second subdomain had the same function → doubled the bounty.
- Test: "main domain is secure" ≠ subdomains; test login reuse across subdomains, and check that CDN/uploads/asset URLs (`uploads.`, `cdn.`, `/get_image/`) aren't unauthenticated and id-enumerable. Sweep sibling subdomains for the same function.
- Q: "Are project/file assets served from an uploads/CDN subdomain by an enumerable id with no auth? Does login work on sibling subdomains, and do they repeat the same IDOR?"
