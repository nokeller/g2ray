### [159] Media-company SSO — "unguessable" 32-char UID leaked via `.json` on group endpoint → changeEmail dumps PII+hashes → profile-update keyed by id+email = full ATO — tobydavenn [NEW ★ chain: id-leak hunt + id+email-as-selector ATO]
- Where: company SSO site; password-reset endpoint reflected a ~32-char UID; group "join" endpoint (`+.json`); `changeEmail` endpoint; profile-update endpoint (identifies account by UID+email).
- Approach/how-found: brute-forcing the 32-char UID got 403 (no UA/IP bypass). Instead of quitting, he recalled "never give up on hard UIDs — find where they leak." Appending `.json` to the group-join endpoint dumped **every member's UID**. Feeding a UID to `changeEmail` returned all PII incl. password hashes. The profile-update endpoint decided "which account" from a client-supplied **UID + email** (not session) → set victim's UID+email → change anything incl. password = ATO. Bonus reflected XSS via open redirect.
- Test: when an id looks unguessable, hunt leaks (member/group lists, `.json`/`.xml` suffix, search, autocomplete) before abandoning. Once you hold an id, replay it into EVERY id-keyed endpoint (read, change-email, profile-update). Flag any "update" that identifies the target by body id/email instead of the session.
- Q: "Where does this app leak the 'hard' id (group lists, `.json` suffix, search)? Does any state-changing endpoint pick the target account from a client-supplied id+email rather than my session token?"

### [160] Rivals (Yahoo) iOS — `POST /api/v1/user/{id}/follow`: denied 422 BUT error body leaks full user record (email, salt, hashes) → 3.5M PII — dhakal_bibek ($9,500) [NEW ★ "denied action leaks object in error message"]
- Where: jailbroken iPhone + Burp (mobileAssistant); mobile API `POST /api/v1/user/3123XXX/follow`.
- Approach/how-found: proxied the iOS app, swapped the numeric path id to a random one → got **422 Unprocessable Entity**, but the error message embedded the *entire* target user DB row (email, username, role, salt, hashes, ids). Numeric id → trivially enumerable → 3.5M users. Found in ~20 min.
- Test: never judge an id-swap by status code alone — read 4xx/5xx bodies; "not allowed to follow #<User …>" style errors dump the very object you were denied. Proxy mobile apps (jailbreak/Frida + Burp); social actions (follow/block/friend) with numeric path ids are prime.
- Q: "Does the error response for a denied id-swap still leak the target object's data? Is the mobile API echoing full records in validation/exception messages?"

### [161] Subdomain admin panel — client-side `window.location` redirect bypass → JS-mined endpoint → `POST id=1` deletes admin avatar (IDOR) — Rizaldi Wahaz [NEW: JS-redirect gate ≠ authz + endpoint mining]
- Where: admin subdomain (found via subfinder/sublist3r); endpoint discovered in JS; `POST ... id=1`.
- Approach/how-found: subdomain enum → admin login page. The "gate" was a client-side `<script>window.location="/login"</script>`. Bypassed by disabling JS / saving source locally / commenting the redirect → admin UI rendered. Read the included JS files, found an interesting endpoint, fired it via Postman with `id=1` → `{"success":true}` → deleted the admin's avatar (no server-side authz).
- Test: a JS `window.location` redirect is not access control — disable JS, save the page, or comment the redirect to reach gated UI. Always read every included JS file for endpoints and call them directly with `id=1`/low ids.
- Q: "Is this protected page only gated by a client-side JS redirect? Which endpoints does the JS reference, and do any accept `id=1` without server authz?"

### [162] Adobe — WAF-heavy: harvest every param with gauplus+httpx, grep `id=`/`confidential`; `/document/{id}` sequential, one increment looked dead but Intruder 100–1000 leaked internal docs — Ravaan (Medium 5.3) [NEW: don't dismiss IDOR on one increment + mass param harvesting]
- Where: `/document/{id}` (sequential numeric) on a WAF-protected Adobe asset.
- Approach/how-found: against a heavy WAF he pivoted to "slight manipulation" (IDOR). Collected all endpoints/params: `gauplus --subs -b png,jpg,... -o urls`, then `httpx -mc 200`, then grepped for `id=`, `confidential`, `secret`, `employee`. `document/200`→`201` returned nothing (almost concluded "no IDOR"), but Burp Intruder over 100–1000 surfaced many confidential/internal docs (sort by length/status).
- Test: never dismiss IDOR after one neighbor id — fuzz a wide range and sort by length/status (empty/unused ids hide real ones). Use gau/gauplus + wayback + httpx to enumerate ALL id-bearing endpoints across a large scope before testing.
- Q: "Did I conclude 'no IDOR' from a single id±1? Have I fuzzed a wide id range and sorted responses? Did I harvest every id-bearing endpoint via gau/wayback first?"

### [163] Microsoft Partner / Azure ISV — 8-digit "random-looking" sellerId is sequential; `GET .../{sellerId}/users` step ±10 dumps other publishers; no rate-limit → thousands — Meareg [NEW: long ids can be evenly-spaced; diff two known ids]
- Where: `partner.microsoft.com GET /en-us/dashboard/account/.../{sellerId}/users` (8-digit sellerId).
- Approach/how-found: sellerId looked random but two owned ids differed by a constant; stepping `+10`/`-10` returned neighboring publishers' users with no authz check (relied only on a valid session). No rate limiting → Python script extracts thousands incl. internal Microsoft teams (blockchain, AKS Engine).
- Test: "long/8-digit therefore safe" is false — diff two ids you legitimately own to detect sequential/even spacing (here ±10), then enumerate. B2B seller/org/publisher endpoints frequently skip per-tenant authz.
- Q: "Is this long id actually sequential or evenly spaced? What's the numeric step between two accounts I control? Does the org/seller endpoint verify tenant ownership or just a valid session?"

### [165] Confidential reports — IDOR+BAC chain: 403-vs-404 name oracle; direct read blocked, so pivot to clone/add-collaborator that trust client source-id (Referrer-only guard) — tobydavenn (Critical+High+Med) [NEW ★ indirect-action IDOR via clone/share + Referrer-only check]
- Where: report GET (report-name param); clone-report (hidden "source report" param, guarded only by Referrer); add-user-to-report; report image URLs (unauth).
- Approach/how-found: wrong report name → **403** (exists, not yours) vs **404** (absent) = oracle to harvest valid names. Session id too random to brute. So he used indirect actions: the **clone** feature only showed owned reports client-side, but tampering the hidden source-report id past the client cloned *any* user's report into his profile — server's only guard was a (spoofable) Referrer. Same trick on **add-user-to-report** added himself to a victim's report. Also unauth view/delete of report images (PII).
- Test: use 403-vs-404 to enumerate valid ids/names. When direct GET is protected, pivot to clone/copy/duplicate/share/add-collaborator endpoints that ingest a source-object id — they often check only Referrer/Origin (spoofable), not ownership. Always test unauth access to uploaded files.
- Q: "Does 403-vs-404 leak existence? Can I reach a protected object indirectly via clone/copy/share/add-member that trusts a client-supplied source id and only checks Referrer?"

### [166] Instagram "Interests" — brand-new feature embeds own user-id in write body; swap → add/modify/delete any account's interests — Nawaf Alkhaldi ($4,300) [NEW: hunt newly-shipped features; self-id in write body]
- Where: Instagram "Interests/Topics" feature; POST body carried the caller's own user id.
- Approach/how-found: a newly-released feature → inspected its write request → found his own account id in the post-data → swapped to another account's id → write succeeded → add/modify/**delete** any user's interests.
- Test: brand-new / recently-shipped features are under-tested — inspect their write requests for a self user-id in the body and swap it. Modify/delete (not just read) confirms impact.
- Q: "Does this newly-added feature put my own user id in its write request body? If I swap it, can I create/modify/delete another user's data?"
