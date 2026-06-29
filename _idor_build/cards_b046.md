### [247] E-commerce — "set as default address" IDOR returns 200 EMPTY (looks dead), but the swapped address surfaces on the CHECKOUT page → leaks any user's name/address/mobile — Rahul Varale [NEW ★ empty response ≠ no impact; verify the side effect elsewhere]
- Where: address `set-as-default` POST keyed by sequential `address_id`; impact visible on the checkout page.
- Approach/how-found: direct address read validated the session (own address only). But the "set as default" action accepted a sequential `address_id` and returned 200 with an empty body (seemed useless). Going to checkout then rendered ANOTHER user's address (name, full address, mobile) — the action had set the victim's address as the attacker's default.
- Test: when an action returns 200 with an empty body, check its SIDE EFFECT on other pages (checkout/profile/confirmation/summary) — a swapped object id may surface there. set-default/select/apply/pin actions can pull a victim's object into your own view.
- Q: "Does an action with an empty 200 have a side effect (set-default/select) that surfaces the victim's object on another page? Did I verify impact beyond the immediate response?"

### [248] Forgot-password endpoint echoes the recipient email ("Email Sent successfully to x@y") and keys on a sequential numeric `id` → brute 1–50,000 → 50K private emails — savxiety [DUP reinforcement: response-echoed email + sequential id; found via waybackurls + inurl:id dork]
- Where: forgot-password `.aspx` endpoint with an `id` GET param that returns the target's email in the response.
- Approach/how-found: recon (waybackurls) found a forgot-password page; `site:subdomain inurl:id` dork surfaced an endpoint whose response echoed "Email Sent successfully to redacted@gmail.com". Changing `id` 1→2 returned another email; sequential ids → Intruder → 50,000 emails.
- Test: forgot-password / resend / "email me" endpoints often echo the recipient address and key on a sequential user id → enumerate to dump all users' emails. Find them via waybackurls + `inurl:id` dorks.
- Q: "Does a forgot-password/resend endpoint echo the recipient email and key on a sequential id I can brute to dump every user's email?"

### [249] Self-stored-XSS → IDOR → ATO — URL id change was blocked ("not allowed"), but swapping the `Id` in the intercepted edit-address REQUEST overwrote another user's address (carrying the XSS payload); guessable id + no rate limit — Vedant Tekale [NEW ★ URL-id check ≠ request-param-id check]
- Where: edit-address request `Id` param (changing it in the URL was blocked; changing it in the intercepted request body/param worked).
- Approach/how-found: address first/last-name fields held a stored (self) XSS. Editing the address by changing the id in the URL gave "you are not allowed", but intercepting the request and changing the `Id` param said "Address changed successfully" → he overwrote another user's address book (and the XSS rode along). Guessable id + no rate limit → overwrite any user → self-XSS becomes stored-XSS-on-victim → ATO.
- Test: if a URL-level id change is blocked, intercept and change the id in the request PARAMETER/body (often a different, unguarded code path). Writing to a victim's field that stores your XSS = stored XSS on them → ATO.
- Q: "Does the URL id check differ from the request-param id check (swap the param, not the URL)? Can I write my stored-XSS payload into a victim's profile field via an edit IDOR?"

### [250] ATO via hidden `uid` JSON param (Param Miner) + `csrf_token=null` bypass + current-password not required → change ANY user's password — Mohsin khan ($1,000) [NEW ★ Param Miner hidden-param discovery + null-token CSRF bypass]
- Where: change-password endpoint; hidden JSON body param `uid` (found with Param Miner "Guess JSON parameter"); `csrf_token=null`.
- Approach/how-found: chained insights — current-password wasn't actually required; the CSRF token couldn't be removed but setting `csrf_token=null` bypassed validation; no `userID` appeared in the request, so Param Miner's JSON-param guesser revealed a hidden `uid` → set the victim's uid in the change-password body → change anyone's password without interaction (demoed on admin@).
- Test: run Param Miner (Guess JSON / headers / query) to find HIDDEN params like `uid`/`user_id` absent from the normal request, then inject them into write/reset endpoints. Try `csrf_token=null` (not just removal). "Current password not required" is itself a reset bypass.
- Q: "Can Param Miner find a hidden body param (uid/user_id) that lets me target another user on a write/reset endpoint? Does `csrf_token=null` bypass CSRF? Is current-password truly required?"

### [251] Online-meeting platform — signup identity travels over a WebSocket frame (UUID+email); set UUID to the victim's + a new email → victim's email changed → reset password → ATO; UUID harvested via follow-user — Mohsin khan [NEW ★ inspect WebSocket frames for swappable identity]
- Where: signup/update WebSocket message carrying `UUID`+email+username; victim UUID exposed via the follow-user button.
- Approach/how-found: HTTP change-info was JWT-protected (401 without token). But after signup a WebSocket frame carried the UUID; setting it to the victim's UUID with a new email changed the victim's email (the victim got logged out), then password reset → ATO. 40+ hunters missed it because they ignored WebSockets; the UUID was grabbed from the profile/follow feature.
- Test: inspect WEBSOCKET frames (not just HTTP) for identity fields (UUID/user_id) you can swap to act on a victim → email change → ATO. Harvest the UUID from social features (follow/profile/search).
- Q: "Does any WebSocket frame carry a UUID/identity I can swap to change a victim's email → ATO? Where do user UUIDs leak (follow/profile/search)? Did I test WS, not just HTTP?"

### [252] Job portal — uploaded CV/resume served from a public/guessable endpoint; a login-failure email leaked that endpoint → all resumes exposed — Vishal Bharad (Critical) [DUP reinforcement: uploaded files at public URLs + transactional-email leak] (tail member-locked; technique captured from intro)
- Where: CV/resume file endpoint (publicly accessible), leaked via a login-failure email.
- Approach/how-found: entering a wrong password triggered an email containing profile info including the CV/resume endpoint URL, which was publicly available with no auth → everyone's resumes exposed.
- Test: uploaded files (CV/resume/docs/IDs) often live at public/guessable URLs with no auth; transactional emails (login-failure, profile, confirmation) leak those URLs. Check whether the file URL requires authorization.
- Q: "Are uploaded files (CV/resume/docs) served from a public/guessable URL without auth? Do transactional emails leak the file URL? Is the file id sequential/enumerable?"

### [254] Facebook Messenger Rooms — `sendMessage` (doc_id=3350161661730468) takes a recipient `id`; swap it + set `message` + random `offline_threading_id` → deliver an (ephemeral) message/notification to ANY FB user — servicenger [NEW: share/send action keyed by a recipient id → message-spoof any user]
- Where: FB `sendMessage` API (doc_id=3350161661730468); params `id` (recipient), `message`, `offline_threading_id`.
- Approach/how-found: sharing a room link via Messenger fires `sendMessage` creating an offline thread; changing `id` to the victim's user id, `message` to arbitrary text, and `offline_threading_id` to a random number delivered a message notification + thread popup to any user (ephemeral — vanishes on refresh).
- Test: share/invite/send/notify actions that build a message take a recipient `id` + content → swap the recipient to message arbitrary users (notification spoofing). Offline/ephemeral threading ids are often just random numbers.
- Q: "Does a share/send/invite action take a recipient id + message I can set to deliver a (spoofed/ephemeral) message or notification to any user?"
