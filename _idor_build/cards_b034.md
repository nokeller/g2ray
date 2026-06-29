### [141] iOS app — email-as-`UID` profile IDOR (view/update→ATO) + no-rate-limit OLD_PIN brute — Raj Singh [NEW: email-as-id + old-secret brute; iOS bypass stack]
- Where: iOS app (bypassed jailbreak detection w/ Liberty, SSL pinning w/ SSL Kill Switch 2 + Frida/objection); profile view/update keyed by `UID=<email>`.
- Approach/how-found: swapping `UID` to a victim's email returned/edited their profile — the server validates only the email, not the session. Updating `MOBILE` to attacker's number → forgot-password recovery PIN to that number → ATO. Separately, the change-PIN call (`OLD_PIN`,`NEW_PIN`) had no rate limit → brute the victim's 4-digit OLD_PIN → ATO.
- Test: when the object key is an email/username (not session-derived), swap it on read+write; update a phone/email field then trigger recovery; brute any "old PIN/password" field lacking rate limiting. Bypass mobile defenses (jailbreak/SSL pinning) first to see the API.
- Q: "Is the profile keyed by a client-supplied email/username (no session check)? Can I update the recovery phone then reset? Is the old-PIN/old-password field rate-limited?"

### [142] Airline — `/Admin/User/Activate` reachable with your own email-confirm token; `User.Id` in the body is IDOR → mass ATO — Sazouki [NEW ★ admin activate endpoint + token reuse + id mass-assignment]
- Where: subdomain signup needs admin approval; `POST /Admin/User/Activate` with `User.Id=...&User.NewPassword=...`.
- Approach/how-found: directory/endpoint fuzzing (gospider) found `/Admin/User/Activate` → "Invalid Token" → he added the **token from his own confirmation email** → now allowed to edit account details + set a new password; the body's `User.Id` → change to a victim's id → set the victim's email + password → ATO of any account (bypassing admin approval).
- Test: fuzz for admin/activate/approve endpoints; feed them tokens you legitimately received (email-confirm/invite) — they may be accepted out of context; then swap the `User.Id`/`id` in the body to act on other accounts.
- Q: "Is there an admin activate/approve endpoint that accepts my own email/invite token? Does its body carry a `User.Id` I can swap to set another account's email/password?"

### [145] Param Miner unlocks a blocked IDOR — hidden param `?wy0kvoly1=1` bypasses the check; reset-to-any-number → ATO — RyuuKhagetsu [NEW ★ discover a bypass param via Param Miner]
- Where: `/api/siswa/<id>` (student) IDOR; direct id-swap returned nothing.
- Approach/how-found: ran Burp **Param Miner** "guess headers/params" on the endpoint → it found an accepted param (`?wy0kvoly1=1`) that, when added, returned other accounts' data (a cache/authz buster) → then forgot-password sent the reset to *any* number without validation → ATO.
- Test: when an id-swap is blocked, run Param Miner (guess params + headers) — a hidden/undocumented param can flip caching or authz and unlock the IDOR. Then check whether reset/recovery accepts an arbitrary phone/email.
- Q: "Did Param Miner reveal a hidden param/header that bypasses the block on this id-swap? Does password reset accept an arbitrary recovery number?"

### [146] PayPal/Braintree — public `billingAgreementToken` reused at the unauth merchant nonce endpoint → PayPal PII + payment fraud; harvest ba_tokens from Wayback/gau/GA — h4x0r_dz [NEW ★ payment token leaked in URLs → reuse]
- Where: `POST api.braintreegateway.com/merchants/<merchantID>/client_api/v1/payment_methods/paypal_accounts` (should be merchant-authenticated; isn't).
- Approach/how-found: the endpoint generates a payment-method Nonce from a `billingAgreementToken`; sending a *victim's* ba_token returns their PayPal billing address/email + a usable Nonce → make a payment from the victim's PayPal. ba_tokens are *public* (passed in GET) and leak everywhere: `gau paypal.com | grep ba_token`, Google dorks, third parties (Google Analytics). Merchant IDs (e.g. Grammarly's public client id) are limited and discoverable.
- Test: tokens passed in GET URLs (ba_token, agreement/session tokens) leak into Wayback/gau/CommonCrawl/Analytics — harvest and replay them at the (often unauthenticated) endpoint that consumes them. Check whether a "merchant-only" API actually enforces merchant auth.
- Q: "Is a payment/agreement token passed in a URL (archived/leaked)? Can I harvest it from Wayback/gau and replay it at an endpoint that should require merchant/server auth?"
