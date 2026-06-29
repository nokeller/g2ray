### [58] Django Debug page → Swagger + reused JWT → `id`-only endpoints IDOR (500+ employees PII) — Aayush Vishnoi (pentest) [NEW ★ debug-leaked endpoints + JWT reuse into Swagger]
- Where: internal subdomain on :8443 (Django DEBUG on — append `/hacker` → error page leaks 5 endpoints incl Swagger/Redoc) and :443 (login/signup).
- Approach/how-found: signed up on :443, intercepted an API call → grabbed the **JWT**, pasted it into the Swagger UI's Authorize box on :8443 → authorized to all documented endpoints. 2-3 took only an `id` → swap → PII of 500+ employees. (Recon chain: subfinder/amass/assetfinder/alterx → httpx → naabu → nuclei to find the internal host.)
- Test: force Django/Flask/Rails debug pages (junk path / error) to leak endpoints; if Swagger needs auth, sign up on the public port and reuse that JWT in Swagger's Authorize; then swap `id` on every documented endpoint.
- Q: "Is there a debug page leaking endpoints? Can I sign up on one port and reuse the JWT in Swagger on another? Which documented endpoints take just an `id`?"

### [61] Enumerable phone-verify token leaks PII + OTP-bypass via response manipulation → mass ATO — princej_76 [NEW ★ verify-link token IDOR + OTP response-tamper]
- Where: signup makes `username.xyz.com`; phone-verify email link `username.xyz.com/<token>` where token is an integer.
- Approach/how-found: increment/decrement the token → lands on *other users'* mobile-verification pages (leaks name, email, subdomain, phone) with a "verify" button. Clicking sends an OTP he can't read → he tampered the **response** in Burp (fail→success) → bypassed OTP → set a new password → ATO. Worked at scale, even on suspended accounts (reactivated via a help-center ticket). Mass ATO, no interaction.
- Test: verification/confirmation links with integer tokens are enumerable → harvest PII; when an OTP gate blocks you, try response manipulation (`false→true`, error→200) — many OTP checks trust the client-visible response.
- Q: "Is the verify/confirm link an enumerable integer token exposing others' PII? Can I bypass the OTP by editing the success flag in the response?"

### [64] Facebook Business — datasources of any business via GraphQL `assetOwnerId`/`asset_id` (node enumeration) — Mukund Bhuva [NEW: enumerate GraphQL friendly-name nodes]
- Where: `business.facebook.com /api/graphql/`; `fb_api_req_friendly_name` / `X-Fb-Friendly-Name` selects the operation.
- Approach/how-found: found `AccountQualityHubAssetOwnerViewV2Query` parsing `{"assetOwnerId":"ID"}` → swap ID → any business owner's data. Dug deeper, enumerated related nodes → `AccountQualityDataSourceViewWrapperQuery` with `{"asset_id":"DSID"}` → read that datasource's data. No owner check on either.
- Test: on FB-style GraphQL, enumerate operations via `fb_api_req_friendly_name` (grep JS/old write-ups for query names); each query's id variable (`assetOwnerId`/`asset_id`/`pageID`) is an IDOR candidate — chain one query's output id into the next query's variable.
- Q: "What other GraphQL operations/nodes exist (friendly-name enumeration)? Does each take an owner/asset id I can swap, and can I feed one query's id into the next?"

### [68] "ATO via confusion" — change email mid-reset so the reset retargets the victim — Kullai (P1, Bugcrowd) [NEW ★ reset token not bound; email change retargets the reset]
- Where: group invite + admin-triggered password reset.
- Approach/how-found: A (admin) invites B (attacker's 2nd account) into a group; A sends B a reset link; B opens it but doesn't set a password yet; A changes B's **email to the victim's**; then B submits a new password → the **victim's** password changes → login as victim. The reset session wasn't bound to the original account, so swapping the email retargeted the pending reset. Only the victim's email is needed.
- Test: begin a reset, then change the account's email *before* completing it — if the reset isn't bound to the original identity, the new password lands on whoever the email now points to.
- Q: "Is the pending reset bound to the original account or does it act on the *current* email at submit time? Can I change the email mid-reset to retarget it to a victim?"
