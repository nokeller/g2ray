### [451] Hackster.io — account-link IDOR → ATO: sign up with email, then "Login with Facebook" (same email) prompts to link; the link-confirm page URL is `/users/authorization/<USER-ID>/edit` → change USER-ID to a victim's → your Facebook links to their account → log in as them — Arbaz Hussain [NEW: the OAuth link-CONFIRM page is keyed on a swappable user id]
- Where: `/users/authorization/<USER-ID>/edit` (shown during "link existing account" after OAuth).
- Approach/how-found: logging in via Facebook on an email that already had an account triggered a "link these accounts?" page whose URL carried the user id; swapping it bound the attacker's Facebook to the victim's account → remote login.
- Test: OAuth "link/merge existing account" confirmation pages keyed on a user id in the URL → swap to bind your social identity to a victim (ATO).
- Q: "Does the account-link confirmation step carry a swappable user id? Can I link my OAuth to a victim's account by changing it?"

### [452] Broken mobile API — leak any user's secret hash by sending a BLANK hash to a different action: the read/update API needs `hash`+`id` (id-swap originally leaked/edited anyone → P1, patched); the fix required a matching hash, but sending a BLANK hash to the UPDATE endpoint (different `?act=`) returned `{user_id, hash}` in the response → harvest any id's hash, replay on the read/reset endpoints; the hash never changes — zseano [NEW ★★ blank/empty secret on a DIFFERENT action leaks the secret → defeats the hash-binding fix]
- Where: mobile API read/update endpoints (`id`+`hash`); the update endpoint (`?act=...`) leaks the hash when `hash` is blank.
- Approach/how-found: after the id-swap was patched by requiring a per-user `hash`, he sent a NULL hash to the update action (different code path via `act`) → the response echoed that user_id's real hash; swap id → harvest any user's hash → use it on the protected read/password-reset endpoints. Hash was static.
- Test: when a fix adds a per-object secret (hash/token), try BLANK/NULL/0 values across EVERY action (different `act`/method/endpoint) — one path may leak the secret in its response; static secrets, once leaked, are permanent.
- Q: "Does any endpoint leak the per-user hash/token when I send it blank? Do different actions (`act`) enforce it differently? Is the secret static (leak once = forever)?"

### [453] Support-request user impersonation ($4,250): logged-OUT support uses `SuppliedEmail`; logged-IN uses a `userid` in `AuxiliaryData`; swap `userid` to a victim's → submit a support/password-reset request on their behalf — Shahmeer Amir [NEW ★ diff the logged-in vs logged-out request to find the impersonation id]
- Where: `POST /custom_api/send_support_request` `AuxiliaryData.userid` (logged-in only).
- Approach/how-found: comparing the support request with vs without a session revealed the logged-in version carried `userid` instead of an email; changing it impersonated other users in support (e.g., request a password reset / leak info for them).
- Test: diff a request made authenticated vs unauthenticated — the auth version may add an identity param (userid) you can swap to act as others; support/help flows are high-value (reset/info-disclosure on behalf of victims).
- Q: "What identity param does the authenticated request add that the anonymous one lacks? Can I swap it to file support/reset requests as another user?"

### [454] Tumblr — inject content into 23.9M domains via the EMBED feature: the embed function didn't validate that the post's owner matched the target blog → create arbitrary posts/content under any tumblr domain (incl. branded CNAMEs) — ak1t4 [NEW: a cross-post/embed feature missing owner validation → mass content injection/defacement]
- Where: Tumblr "embed" post feature (no owner-vs-content validation).
- Approach/how-found: the embed feature served attacker-created content under any blog's domain because it never checked the content belonged to that blog → mass defacement across millions of domains (incl. high-profile ones found via dorks).
- Test: embed/cross-post/syndication/import features that render YOUR content under ANOTHER tenant's domain — check whether ownership is validated; impact is mass content injection/defacement.
- Q: "Does the embed/cross-post feature verify the content owner matches the target blog/domain? Can I serve my content under arbitrary tenants?"
