### [11] $20,300 / 200-hour challenge: 403-on-id-swap bypassed by method+Accept header — Voorivex team [NEW: 403 bypass combo]
- Where: `GET /users/58158` (numeric id) on main web app.
- Approach/how-found: incrementing the id → 403. Tried `PATCH` method alone → still failed. The winning combo: switch method to `PATCH` AND add `Accept: application/json` → 200 OK with full PII. Two independent toggles stacked.
- Other IDOR in same report: signed up to an internal `companydemonew.com` (only @company.com emails) by registering `attacker@company.com` and bypassing activation → post-auth IDOR `id 35→36` dumped another tenant's transactions. Lesson: demo/internal/staging subdomains are post-auth IDOR goldmines once you get in. Also: auth-less Swagger UI on `test.<target>:5000` — tested each of ~100 "protected" APIs individually, 10 were open, 2 leaked PII.
- Test: on a 403'd id-swap, stack bypasses — change verb (GET→PATCH/PUT/POST) *and* add/alter `Accept`, `Content-Type`, `X-Requested-With`. Hunt `test`/`demo`/`staging` subdomains and unauth Swagger.
- Q: "Does the id-swap 403 flip to 200 if I change the HTTP method AND the Accept/Content-Type header together? Is there a demo/internal subdomain I can register into for an unguarded post-auth API?"

### [12] Google $50k LLM bugSWAT: Bard Vision resource-path IDOR + 'ask a question' meta + directive-overload DoS — Lupin/rez0/Rhynorater [DUP of P2-6 for the IDOR; NEW meta]
- IDOR (DUP, canonical): Bard "Vision" describe-image. Body of `POST .../StreamGenerate` carries a server file path `/contrib_service/ttl_1d/<id>`. As user 2, swap in user 1's path → Bard describes the VICTIM's image; OCR leaks text (revenue, emails, notes).
- NEW meta-lessons worth capturing: (1) *Finding a bug by asking a question* — they simply asked the engineers "how are signatures signed?" → exposed a hardcoded non-random signing key. In bug bounty terms: read the JS/asking yourself "where does the secret/signature come from?" often reveals it's hardcoded. (2) GraphQL **Directive Overloading**: `@Signature(...)` could be repeated N times (the signature signs everything *except* signatures) → 1,000,000 directives = 109s backend hang (DoS). (3) Markdown-image data-exfil through an LLM with a CSP bypass (`www.google.com/amp/s/<evil>.googleusercontent.com`, URL-encoded host to dodge a domain filter) — prompt-inject the AI to read Gmail/Drive then exfil via image URL.
- Q: "Does an AI 'describe/summarize my file' feature take a swappable storage path pointing at another user's object? Can a security-relevant directive/param be repeated to overload the server? Where is the signing secret — is it hardcoded in JS?"

### [30] Genie Aladdin IoT: BOLA on device_id in cloud API + mobile cleartext creds — Rapid7 / Deral Heiland [NEW surface: IoT device_id]
- Where: `GET https://<api-id>.execute-api.us-east-1.amazonaws.com/Android/devices/879267` (AWS API Gateway).
- Approach: authenticated user queries the devices API with a `device_id` other than their own → returns other users' device data (BOLA). device_id is a short sequential integer. Also found the Android app stored the password in cleartext in `shared_prefs/...MainActivity.xml` (persists after logout/reboot) and an unauthenticated device web config page on port 80.
- Test: for IoT/mobile backends, pull the cloud API base from the APK/proxy, then swap the `device_id`/`serial` in the path. Decompile the app for hardcoded API hosts + insecure storage.
- Q: "What device/serial id does the mobile app send to its cloud API, and is it sequential? Does swapping it return another customer's device? Does the app store secrets in shared_prefs/plist in cleartext?"

### [31] NCC Group — PandoraFMS Enterprise advisory [RECOVER NEEDED — extraction returned NCC boilerplate, not the advisory]
- Queued for wayback/CUA recovery. (Likely product CVEs incl. an IDOR/BAC in PandoraFMS.)

### [33] $7,000 single web app: 3 IDORs — private downloads, public-id→premium data, hidden admin panel — Voorivex [NEW: hidden admin surface]
- Where: add-on marketplace (HackerOne program).
- Approach/how-found (narrow recon, "use the product slowly"): (1) `/download/<seq-id>` served files even when the add-on was flagged **private** → fuzz 1–10000 to enumerate everyone's files. (2) Premium-only `POST /rest/paymentinfos` keyed by *add-on ID*, but add-on IDs are **public** → send someone else's id → their sales data (a public identifier feeding a privileged data endpoint). (3) A tiny button at the bottom of the admin page opened a separate **add-on settings panel that had never been audited** for IDOR → edit other add-ons' admin info.
- Test: don't trust "private" flags on download endpoints; map every *public* identifier (slug/add-on id/store id) and feed it to premium/owner-only data endpoints; click every obscure UI control to surface un-audited admin sub-panels.
- Q: "Does a 'private' object still download by direct id? Is there a PUBLIC id (slug/listing id) that a premium/owner data endpoint accepts? Is there a buried admin/settings sub-page nobody audited?"
