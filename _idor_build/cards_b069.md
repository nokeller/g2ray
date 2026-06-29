### [400] IDOR → ATO via Facebook auth-callback `_user_id` swap: `/login/auth/facebook/callback?linking=true&...&_user_id=<UUID>`; change to a victim's user_id → your FB links to their account → "login with Facebook" → in with no password; sourced the UUID from S3 image URLs that embed `/media-uploads/<User-ID>/...` — Khizer ($1,200) [NEW ★ FB-link IDOR + harvest the "unguessable" id from an image's S3 path]
- Where: `/login/auth/facebook/callback?linking=true&_user_id=<UUID>`; user_id leaked in shared-image S3 path.
- Approach/how-found: the FB linking callback carried `_user_id`; swapping it to a 2nd account returned 200 and bound his Facebook to that account → password-less login = ATO. The triager doubted impact because user_id is a UUID — so he found it: any image the victim shared was hosted on S3 at `.../media-uploads/<User-ID>/...` → harvest the UUID.
- Test: social-link callbacks keyed on a user id → swap to bind your identity to a victim; when the id is a UUID, look for it in CDN/S3 asset paths, image URLs, profile sources.
- Q: "Can I link my OAuth identity by swapping `_user_id` in the callback? Where does the 'unguessable' UUID leak (S3/CDN image paths, asset URLs)?"

### [401] Current-password bypass + brute oracle: update-username/email POST has a HIDDEN `old_username`/`old_email` + `password`; the backend validates the credential PAIR but not that it belongs to the logged-in session → submit ATTACKER's valid creds to change username without your current password; AND put the VICTIM's username in `old_username` and brute `password` → success response = valid victim creds — Mandeep Jadon [NEW ★★ credential check not bound to session → confirm-password bypass AND offline-style brute via the update endpoint]
- Where: `POST /my/update/username` (`old_username`/`old_email`, `password`, csrf).
- Approach/how-found: the change required the current password, but the server only checked that `old_username`+`password` were a VALID pair — not that they matched the session. So any valid pair worked (bypass). Swapping in the victim's username and brute-forcing `password` turned the update endpoint into a login brute-force oracle (the "updated" response confirms valid creds).
- Test: when a sensitive change requires the current password, check whether the credential is tied to the SESSION or just validated as a pair; if the latter, it's both a confirm-bypass and a brute-force oracle — pass a victim identifier and fuzz the password.
- Q: "Is the current-password check bound to my session, or just 'is this a valid username+password'? Can I pass a victim's identifier and brute the password field for a login oracle?"

### [402] Naaptol — incremental address-id PII leak: shipping-address request returns full name/address/mobile by `address_id`; incremental (17917835→…837) → Intruder → millions of users' PII — Avinash Jain [DUP-reinforce: checkout address lookup keyed on sequential id]
- Where: checkout shipping-address request, incremental `address_id`.
- Approach/how-found: the address request returned full user details; ids were sequential → decrement/increment then Intruder to mass-harvest PII.
- Test: e-commerce checkout/address/order endpoints keyed on sequential ids are reliable mass-PII IDORs — always enumerate to quantify impact.
- Q: "Does the checkout/address endpoint return PII by a sequential id? Can I Intruder the range to prove millions-of-users impact?"

### [403] Facebook — add anyone to a page's "Top Fans" via `fan_id` swap: the "display Top Fans badge" request carries `fan_id`; change to a victim's id → adds them to a page's Top Fans without their consent — Jafar Abo Nada [NEW: consent/opt-in bypass — perform an opt-in action ON BEHALF of another user]
- Where: Top Fans join/badge request, `fan_id` parameter.
- Approach/how-found: joining "Top Fans" should require the user's own approval; the request keyed on `fan_id` with no check that it's the sender → swap to add any user to any page's Top Fans.
- Test: opt-in/consent actions (join, subscribe, accept, RSVP) keyed on a user id → swap to perform them on behalf of others (forced association / consent bypass).
- Q: "Does this opt-in/consent action verify the user id is mine? Can I subscribe/join/accept on behalf of another user by swapping their id?"
