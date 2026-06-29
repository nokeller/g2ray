### [96] Synack weekend — Match&Replace + AutoRepeater to surface SQLi/XSS/IDOR fast; read-only IDOR by id swap — Manas Harsh ($8k/5 bugs) [DUP — tooling/automation]
- Where: multiple endpoints on one program.
- Approach/how-found: used Burp **Match & Replace** (auto-mutate a param value like `test`→`test'` across all traffic) to catch error-based SQLi, and **AutoRepeater** (auto id-swap + match/replace) to catch read-only IDORs (other users' data by changing ids). Classic `'><input autofocus onfocus=alert(1)>` for stored XSS.
- Test: configure Match & Replace / AutoRepeater to auto-swap ids and inject quotes across your whole session so IDOR/SQLi surface passively while you browse; write thorough reports (video PoC, every step).
- Q: "Have I set up AutoRepeater/Match&Replace to auto-swap ids site-wide so IDORs surface while I browse normally?"

### [97] Gov e-learning — registration "already registered" response leaks victim userid/PII → reset-by-userid (no old password) → ATO — iamgk808 [NEW ★ register-error PII leak + reset-by-id from a valid session]
- Where: teacher portal; register requires a school "UDISE code".
- Approach/how-found: login/reset failed (wrong creds). Entering the correct UDISE code on **register** returned "Another teacher already registered" but the *response body leaked the existing user's email, mobile, and user id*. With a separate valid login (his father's), he found a password-reset request needing only a valid **user id** with no old-password check → reset the victim's password using the leaked id → ATO. Also IDOR to view any teacher's/student's PII by changing the id.
- Test: registration/"already exists" flows often leak the existing account's PII/userid in the response — harvest it; then use any authenticated reset/change endpoint keyed by user id (no old-password check) against that id.
- Q: "Does a register/'already exists' response leak the existing user's id/email/phone? Is there a reset/change-password keyed by user id with no old-password check I can invoke from my own session?"

### [98] Yii profile — per-field user ids (about-section IDOR) + HTML injection in `content` + unenforced CSRF token → mass phishing ATO — SYRINE [NEW: many distinct id params; test each]
- Where: profile edit sends multiple objects each with its OWN `id` (username, name, about, photo all different) + `YII_CSRF_TOKEN`.
- Approach/how-found: tested each id separately — the about-section `id` is IDOR-able → edit anyone's about section. `content` accepts HTML → HTML injection (not XSS) → embed a "re-login here" phishing link. The `YII_CSRF_TOKEN` isn't validated (and earlier, removing the `YII_CSRF_TOKEN` cookie bypassed reset rate-limiting) → flood requests → mass-change every user's about section to a phishing link → ATO at scale.
- Test: when one form sends several objects each with its own id, test every id independently (one may be unprotected). HTML-injectable text fields enable phishing even without XSS. If the CSRF token isn't actually enforced, you can mass-automate the IDOR.
- Q: "Does the form carry multiple distinct ids — is any one unprotected? Does a text field render injected HTML? Is the CSRF token actually validated, or can I mass-replay?"

### [99] IDOR→ATO via path-traversal on the id segment (`/addEmail/<demoId>/../<victimId>/`) — Jefferson Gonzales ($2,500) [NEW ★ `/../` defeats the authz-checked id segment]
- Where: `POST /<orgID>/addEmail/<DemoUserID>/` body `{"email":"attacker@..."}` (assigns an email to a "Demo user").
- Approach/how-found: changing `DemoUserID` to a real member's `UserID` → 403. Bypass: `POST /<orgID>/addEmail/<DemoUserID>/../<UserID>/` — the authz check validates the first (your demo) id, but path normalization resolves `/../<UserID>/` to the victim → sets the victim's email to attacker-controlled → reset → ATO.
- Test: when an id segment in the path is access-checked, append `/../<victimId>/` (or other normalization tricks) so the check sees your allowed id but the router resolves to the victim's. Demo/placeholder users you can create are great pivots for write endpoints.
- Q: "Does authz check the literal path id while the router normalizes `/../`? Can I prefix my allowed id then traverse to the victim's id on a state-changing endpoint?"
