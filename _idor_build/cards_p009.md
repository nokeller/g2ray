### [108] "In GUID We Trust": check the UUID version digit → predict v1 reset tokens — Intruder/Daniel Thatcher [NEW: GUID version weakness]
- Where: password reset where the token is a GUID.
- Approach/how-found: the char after the 2nd hyphen is the UUID **version**. v4=random (safe), but **v1 = timestamp + clock-sequence + MAC node-id (predictable)**; v3/v5 = MD5/SHA1(name+namespace). For a v1 reset token: request a reset for YOUR account, feed the GUID to `guidtool` to extract node-id + clock-seq, note server `Date`, then generate every GUID for ±1s around the victim's reset time and submit them all → take over. Bonus: same-millisecond race — libraries +1 the timestamp of the 2nd GUID, so a visible GUID can reveal an invisible one.
- Test: decode every UUID's version; if not v4, treat it as predictable and attempt token prediction.
- Q: "Is this token a UUID, and what version is the digit after the 2nd hyphen? If v1/v3/v5, can I reconstruct the victim's reset/session token from time+node or name+namespace?"

### [111] Apple consultants subdomain numeric IDOR (write) $7,500 — apapedulimu [DUP-ish reinforcement]
- Found via `site:*.apple.com` dorking → `consultants.apple.com` (a less-audited sub-app). Two accounts; the edit/save request used a numeric ID — change A's ID to B's → B's data changed (write IDOR). Lesson: hunt lesser-known sub-applications of big targets; simplest numeric write-IDOR still pays.

### [112] TikTok tag IDOR only after remove+re-tag (state-dependent) $3,000 — apapedulimu [NEW: state-dependent IDOR]
- Where: `POST .../mention/tag/update/v1` with `aweme_id` (video id), `add_uids`, `remove_uids`.
- Approach/how-found: directly swapping `aweme_id` to a victim's video did nothing. But when he first **removed a tag then tagged someone else**, the request gained a `remove_uids` param — and *now* swapping `aweme_id` to the victim's video succeeded → tag anyone on anyone's video. The IDOR only fires in a specific request STATE/param combo.
- Test: don't conclude "not vulnerable" from one request shape — exercise the feature through different states (add/remove/edit/reorder) and re-test the swap when extra params appear.
- Q: "Does this endpoint become exploitable only after a specific prior action that changes the request body (adds a param)? Have I tried every state of this feature, not just the default?"

### [118] Instagram: drop the heartbeat request → watch livestream invisibly — xdavidhu [NEW: kill-the-telemetry trick]
- Approach: Burp match/replace to break `live/<id>/heartbeat_and_get_viewer_count` → join a (practice/public) livestream with the host never seeing you and the viewer count never incrementing; host can't even remove you. (Vendor disputed, but the *technique* is gold for hiding presence/skipping checks.)
- Test: identify presence/heartbeat/telemetry/analytics requests and drop or corrupt them to become invisible or to skip a client-enforced step.
- Q: "Which heartbeat/presence/usage request, if dropped, hides my activity or bypasses a limit (seat count, viewer count, trial usage)?"

### [144] Chain two trivial IDORs → cross-org ATO (precondition created by IDOR #1) — r29k/Sheraz Khalid [NEW: chained-IDOR precondition]
- Where: helpdesk app (admin/manager/user). IDOR#1: dept-assign request carries a manager id → swap to add ANY manager (even another org's) to your department. IDOR#2: user-edit password-change carries user id → swap to change a manager's password. Alone, each is minor.
- Approach/how-found: password-change worked then 403'd during PoC — the tell was that IDOR#2 only works for managers **currently in your department**. So: IDOR#1 to pull the target manager into your dept → IDOR#2 to reset their password → log in. Reaches admins in other orgs.
- Test: when a write IDOR intermittently 403s, look for a RELATIONSHIP precondition (membership/department/team) you can satisfy with a *different* IDOR first.
- Q: "Does this write fail due to a membership/relationship requirement I can manufacture via another IDOR (add to team/dept/share) first? Can two minor IDORs chain into ATO?"

### [155] Airline group: member-profile IDOR + remove resetToken field → mass ATO (CVSS 10) — tarekbouali [NEW: omit the token field]
- Where: unified SSO; `/api/members/<id>/profile` (unauth → email; enumerate thousands), password-change request with reset `key`.
- Approach/how-found: reset link `?key=`; the change-password body variations all errored until he **fully removed the `resetToken` field** → `HTTP 204`, password changed on his second account → ATO at scale (credit cards saved across the group's sites).
- Test: on reset/change-password, try blanking AND fully omitting the token/resetToken/credential field; enumerate `/members/<id>` for email harvest.
- Q: "Does omitting (not just blanking) the resetToken/credential field make the password change succeed? Is the member-profile endpoint unauthenticated and enumerable?"

### [156] iCloud CloudKit: title hidden in URL hash but leaked unauth via records/resolve by ShortGUID — xdavidhu [NEW: hash-is-not-protection]
- Where: `POST /database/1/com.apple.cloudkit/.../records/resolve` body `{"shortGUIDs":[{"value":"<ShortGUID>"}]}`.
- Approach/how-found: shared-file links put the document title in the URL **hash** (`#title`) — implying it's meant to stay client-side/private. But the resolve endpoint returns `share→fields→cloudkit.title` **and the owner**, unauthenticated, even when sharing = "Only people you invite". Knowing the ShortGUID isn't privileged.
- Test: anything stashed in a URL fragment/hash "for privacy" — check whether a resolve/preview/metadata endpoint returns it server-side by the object/share id, without auth.
- Q: "Is sensitive data only hidden in the URL hash? Does a resolve/preview endpoint leak it (and the owner) by share-id without authentication?"

### [158] Research lab: can't READ files (IDOR) but can RUN JOBS on others' files — machevalia [NEW: process-it-without-reading-it]
- Where: `/file?id=10001` (view blocked) vs `POST /jobs?file1=10002&file2=10003` (compute).
- Approach: direct file read via id-swap returned nothing usable, but the job/processing endpoint accepted other users' file ids and ran computations on their private data → access-control violation (and results leak).
- Test: if direct read is blocked, target the endpoints that *operate on* the object (run/compute/convert/render/export/share) with the victim's id.
- Q: "If I can't read the object, can a processing/job/render/export endpoint act on the victim's object id and return results?"

### [169] Glints (4 bugs): public JobId IDOR, ORM attributes= field leak, resume→S3 path, guest GraphQL — huli [NEW: ORM attributes= + file→S3]
- Where: job platform.
- Approach/how-found: (1) `jobApplications?where={"JobId":"<uuid>"}` — JobId is public (in job URLs) → swap to other companies' jobs → all applicants' PII. (2) RSS feed needed a secret `RSS_ID`; the company-jobs API used **Sequelize** ORM, so he injected `attributes=rssId` (Sequelize field selector) → the response coughed up the hidden rssId + owner id. (3) public-profile API redacts phone/email but leaks the `resume` **filename**, and all resumes live at a fixed S3 path `glints-dashboard.s3.../resume/<filename>.pdf` → download anyone's; harvest user ids via `inurl:profile/public site:glints.com`. (4) hidden `superpowered.glints.com` JS contained a `findRecruiters` GraphQL query callable as guest → all recruiters' PII.
- Test: feed public ids (JobId) to data APIs; on Sequelize/ORM backends add `attributes=`/`fields=`/`include=` to surface hidden fields; turn a leaked filename into a predictable S3/CDN URL; google-dork id-bearing public URLs; replay GraphQL queries found in JS as an unauthenticated guest.
- Q: "Is the object id public elsewhere? Can an ORM `attributes/fields/include` param leak a hidden id? Does a file field map to a guessable S3/CDN path? Is a GraphQL query from JS callable unauthenticated?"

### [176] Reset-password IDOR: id in URL segment + hidden HTML field leaks it — hckrt/venomnis [DUP reinforcement]
- Reset URL `…/reset-password/0-57-<token>` and POST body `id=57`; swap 57→58 → reset any user. The page also leaked the id in a hidden input `<input type=hidden name=id value=57>` next to the email → harvest + enumerate. Q: covered by reset-IDOR + hidden-field-id-leak.

### [180] Facebook Author/Publisher IDOR via GraphQL author_id+publisher_id — servicenger [DUP reinforcement]
- GraphQL add/remove "linked publications" took `author_id` (victim) + `publisher_id` (any page), first-party Android token → add/remove publications on a victim's settings. Reinforces: add/remove relationship mutations keyed by a victim id.

### [184] Gumtree: PII in HTML source (F12) + full name via unauth iOS-only API IDOR — Pentest Partners [NEW reinforcement: HTML-source + mobile API]
- Approach: every advert leaked seller postcode/GPS (even with map hidden) and email in the **HTML source**; the iOS-only API had an unauthenticated IDOR leaking full names. "Sometimes finding vulns is just looking" (F12 the source).
- Q: "Is PII present in the raw HTML/JSON even when the UI hides it? Does the mobile-only API expose more fields without auth than the web API?"

### [189] CSRF/anti-IDOR token bypassed by OMITTING it → no-rate-limit enum → plaintext creds → mass ATO — tox7cv3nom [NEW: remove-the-guard-param]
- Where: `/api/v1/users/id` gated by a CSRF token "to prevent IDOR".
- Approach/how-found: swapping the id → 401 while the CSRF token was present; **removing the CSRF token parameter entirely** → 200 (the token was the only guard). Forgot-password leaked the short numeric id; no rate limit → enumerate a 3-digit range (~2-5k requests) → 200s returning session token, user id, and password in plaintext → mass ATO.
- Test: try DELETING (not just altering) the CSRF/security/signature param that "protects" an IDOR; then enumerate the id space if rate-limiting is absent.
- Q: "Does removing the CSRF/security token param disable the IDOR check? Is the id space small and unthrottled? Does the response include credentials/session tokens?"
