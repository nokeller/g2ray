### [268] "Secure" app cracked by hidden-param brute — Arjun/Parameth found an undocumented `?id=`; 6781→6780 → other users' data — protector47 ($1,500) [NEW: brute HIDDEN params when nothing obvious is IDOR-able]
- Where: an endpoint with no visible params; a hidden `?id=` discovered via Arjun/Parameth.
- Approach/how-found: XSS/SQLi/etc. all failed on a hardened, old program. He brute-forced HIDDEN parameters (Arjun, Parameth) → found `?id=` → sequential → decrement → other users' data.
- Test: when an app looks secure and exposes no obvious id, brute hidden parameters (Arjun/Parameth/Param Miner) on each endpoint — an undocumented `id`/`user_id`/`uid` is often IDOR-able.
- Q: "Have I brute-forced hidden parameters (Arjun/Parameth) on each endpoint to surface an undocumented id that's IDOR-able? Did I stop too early because nothing visible looked vulnerable?"

### [269] Facebook creator studio — `GamesVideoStreamerDashboardProfileQuery` keys on `profileID`; swap to any game-streaming pageID → private metrics incl. `l30_live_earnings` + `supporter_count` — Kailash ($2,000) [DUP reinforcement: dashboard/analytics query keyed by swappable profile id]
- Where: FB creator-studio GraphQL `GamesVideoStreamerDashboardProfileQuery`; `profileID`.
- Approach/how-found: forwarded all requests, searched Burp for the named query, sent it to Repeater, and replaced `profileID` with a target pageID → returned that page's dashboard stats including 30-day live earnings and supporter count (data only page-role holders should see).
- Test: dashboard/analytics/insights GraphQL queries keyed by a profile/page/account id → swap to read another's private metrics (earnings, supporters, conversions). Search Burp by the GraphQL operation name to locate the exact request.
- Q: "Does a dashboard/analytics query key on a profile/page id I can swap to read another entity's private metrics (earnings/supporters)?"

### [271] Weak-crypto ATO ×2 — reset token is base64 of `senttime/<ts>/token/<email>` → swap email, re-encode, sync `senttime` (±1) → forge any reset link; OAuth `Authorization` header is base64 of the email → swap → login — Vasuyadav [NEW ★ forge base64 reset/auth tokens]
- Where: password-reset token (base64 `senttime/ts/token/email`); OAuth `Authorization` header (base64 email).
- Approach/how-found: the `==` tail revealed base64. Decoded reset token = `senttime/<timestamp>/token/<email>`. He requested a reset for his account, swapped the email to the victim's, re-encoded, and synced `senttime` (Intruder for near-identical times; ±1 if needed) → a valid reset link for any email → ATO. The OAuth auth header was base64 of the email → swap → logged into the victim.
- Test: decode base64/`==` tokens in reset links and auth headers; if they hold email/id + timestamp, forge them for a victim (match/adjust the timestamp ±1–2). Predictable token structure = ATO.
- Q: "Is the reset/auth token just base64 of email+timestamp I can re-encode for a victim? Can I sync the timestamp (Intruder, ±1) to forge a valid link/header?"

### [272] Crypto-mining app — reset link `/changePassword/{UUID}/{token}` token not bound to the UUID (swap UUID, keep your token); UUID obtained via a referral endpoint that converts a public referral param → UUID (dork the referral links) → ATO any user — Mukul Lohar [NEW ★ token-not-bound + referral-param→UUID converter]
- Where: `POST /changePassword/{UUID}/{token}`; a referral endpoint mapping a public `source` referral param → internal UUID.
- Approach/how-found: the reset link held UUID+token, but the token wasn't bound to the UUID → swap UUID to the victim's (with his own token) → change the victim's password (200). To get the "unguessable" UUID, a referral endpoint converted a public referral `source` param into the UUID; Google-dorking referral links yielded many users' source params → UUIDs → mass ATO.
- Test: when a reset link is id+token, test whether the token is bound to that id (swap id, keep token). For an unguessable UUID, find a converter endpoint (referral/share/invite/profile) that maps a public param → internal UUID; dork for the public params.
- Q: "Is the reset token bound to the UUID, or does my token work with a swapped UUID? Is there a referral/share endpoint that converts a public param into the internal UUID I need?"

### [273] US DoD — account-settings update POST carries `id` in the body (sequential, 623/624); swap to victim + change email → reset → ATO; non-standard signup page found via dorking bypassed the CaC requirement — Gal Nagli [DUP reinforcement: self-id-in-body update → ATO + dork for non-standard auth pages]
- Where: account-settings update POST with `id=<sequential>` in the body (e.g. `id=624&...&email=hacker@...`).
- Approach/how-found: Google-dorked DoD signup/login pages and found a non-standard signup (no CaC card). The settings-update POST sent the user id in the body (instead of deriving it from the session); a 2nd account got the next sequential id → logout, replay the update with the victim's id and an attacker email → victim's email changed → password reset → ATO, no interaction.
- Test: profile-update POSTs that include your own id in the body (rather than from session) → swap to a victim + change their email → reset → ATO. Dork for non-standard signup/login pages that bypass the main auth (CaC/SSO).
- Q: "Does the profile-update POST carry my user id in the body (sequential)? Swap to victim + change email → reset → ATO? Are there non-standard signup pages bypassing the primary auth?"

### [274] YouTube Video Builder (beta) — `UploadToYouTube` `__ar` takes a target channel ID (public) with no ownership check → upload Unlisted videos to ANY channel; a cross-service `scottyResourceId` mismatch leaked all decryption key hashes — Ryan Kovatch ($6,337) [NEW ★ public-id publish-to-any-asset + error leaks key hashes]
- Where: `POST /u/0/videobuilder/_/rpc/Image2VideoUiService/UploadToYouTube` `__ar` with the channel ID (`UCBCW…`, public); `scottyResourceId`.
- Approach/how-found: a beta tool rendered AND uploaded videos, letting you pick a channel. The upload request embedded the channel ID (public, from URL/source) with no ownership check → swap it → Unlisted video uploaded to a channel he didn't own (misinformation vector). Trying to point it at a custom file via a `scottyResourceId` from another YouTube service triggered a `KeyUnavailableException` that listed all stored decryption key hashes — a critical secondary leak.
- Test: upload/publish/post actions that take a target channel/page/account id (publicly known) with no ownership check → post content to others' assets. When cross-service object ids mismatch, the error may leak crypto key hashes/secrets — exceptions can be worse than the blocked feature.
- Q: "Does an upload/publish action take a target channel/account id (public) with no ownership check? Do cross-service resource-id mismatches leak key hashes/secrets in error messages?"

### [275] Google acquisition (Discourse-style) — `/u/{username}.json` returns PII; `/c/.../l/latest.json` leaks usernames → harvest usernames from one endpoint, read PII from the other — Manas Harsh [NEW: `.json` variants of profile/list pages leak PII]
- Where: `/u/{username}.json` (PII); `/c/ask/20/l/latest.json` (leaks user ids/usernames).
- Approach/how-found: spotted a URI leaking usernames/ids; found `/u/{yourusername}.json` returning his own data; swapped the username (harvested from the list endpoint) → other users' PII.
- Test: Discourse/forum-style apps expose `.json` variants (`/u/{username}.json`, `latest.json`, `/c/.../l/latest.json`) that leak usernames + PII — harvest usernames from a list endpoint, read PII from the profile `.json`.
- Q: "Are there `.json` variants of profile/list pages (`/u/{username}.json`) returning PII by a username I can harvest from a list/latest endpoint?"
