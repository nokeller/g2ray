### [335] Verizon — 2M Pay-Monthly contracts via employee POS subdomain: auth-bypass path sets a valid session, then modify the `a` (agreement) param → any contract PDF; range 1310000000–1311999999 — Daley Bee [NEW ★ recon→auth-bypass→2-param IDOR→range enumeration of millions]
- Where: `telestore.verizonwireless.com` (internal POS tool); contract PDF endpoint with `a` (agreement) + `m` params; a separate path set a valid session.
- Approach/how-found: recon found the employee subdomain; Google-dork + dirsearch revealed tool paths and the PDF path (auth-required, 404 otherwise); brute-forced the GET params to learn `a`/`m`; one discovered path "weirdly" set a valid authenticated session (auth bypass) linked to a fixed phone/contract. He couldn't change the bound phone, but clicking the agreement opened the PDF endpoint — and simply changing `a` returned ANY customer's contract (name/address/mobile/device serial/signature). Probed bounds → ~2M contracts (1310000000–1311999999).
- Test: hunt employee/internal subdomains (POS, admin, telestore-style); some paths silently establish a session (auth bypass); when two params "must match" (agreement+phone), test each INDEPENDENTLY — often only one is authz-checked; probe min/max to size the keyspace.
- Q: "Is there an internal/employee subdomain? Does any path hand me a valid session? When two ids 'must correspond', is each actually validated, or can I move just one? What's the id range = blast radius?"

### [337] Support tickets — print-ticket URL exposes a 5-digit `ticket_id`; Intruder-enumerate → any user's email/username/message — Evan Ricafort ($120) [DUP-reinforce: print/export URL leaks short numeric id to brute]
- Where: support dashboard "print ticket" URL with a 5-digit ticket ID.
- Approach/how-found: created a ticket, used "print" → URL contained a short numeric ticket id; Burp Intruder over the 5-digit space → read all users' tickets (email, username, message).
- Test: print/export/download variants of a page often expose a cleaner, brute-able id than the main UI; 5–6 digit ids are fully enumerable.
- Q: "Does a print/export view expose a short numeric id I can enumerate across all records? Is the print endpoint authz-checked like the main view?"

### [340] PayPal — secondary-user ATO on business accounts: `PUT /businessmanage/users/api/v1/users` edits a secondary user's permissions/identity by id; swap to a victim business's secondary user → take it over → transfer money — whitehathaji ($10,500) [NEW ★ sub-account/role-management IDOR → money]
- Where: `PUT /businessmanage/users/api/v1/users?...` (PayPal business "manage users").
- Approach/how-found: with two business accounts, he captured the edit-permission request for HIS secondary user, then swapped the secondary-user id to a victim business's secondary user → controlled that account; since secondary users can hold "Transfer money" privilege → unauthorized transfers from any business.
- Test: B2B "manage team/sub-users" APIs (`/users`, `/members`, `/roles`) key on a sub-user id — swap to edit/take over another tenant's privileged sub-user; chase the highest-privilege role (money/admin).
- Q: "Can I edit another organization's sub-user (permissions/email/password) by swapping the sub-user id in the team-management API? Which sub-role grants money movement?"

### [341] Review/rating IDOR — put-review request keyed on `client_id` (MongoDB ObjectId); harvest both ObjectIds from 2 of your own accounts, swap → change a victim's 5★ to 2★ — Md Hridoy ($300) [DUP-reinforce: ObjectId harvested from own account → tamper others' content]
- Where: submit-review request with `client_id=<ObjectId>`.
- Approach/how-found: created 2 accounts, noted each `client_id`; intercepted the review submit, replaced his client_id with the other account's → modified that user's rating (5★→2★). Shows ObjectIds aren't secret when the app shows you your own.
- Test: when an action embeds your account/object ObjectId, the values for other accounts are equally obtainable (your own 2nd account, page source, API) — swap to write to their objects (ratings, reviews, settings).
- Q: "Does this write action carry my client/account ObjectId? Can I get a victim's id from a second account or the UI and swap it to edit their content?"

### [344] "Hiding in plain sight" — sequential `user_id` → 20M users' PII; event `contact_ids` PUT adds any out-of-org contact (returns a 422 'must belong to host' error but ADDS them anyway on refresh) — A Bug'z Life ($3,000 ea) [NEW ★ "the error response lies": rejection message + successful side effect]
- Where: create-contact-from-user `?user_id=` (sequential); `PUT /events` `contact_ids[]`.
- Approach/how-found: IDOR#1 — sequential `user_id` returned full PII for any of ~20M users. IDOR#2 — adding a contact outside the org returned `{"success":false,"errors":{"contacts":["must belong to the host or owner"]}}`, yet on page REFRESH the out-of-org users were attached and their PII exposed. Same writeup: HTML→PDF SSRF to AWS metadata, CORS w/ credentials, forced-browse HackerOne `scope_versions`.
- Test: DON'T trust HTTP responses — after a 4xx/"forbidden" on a write, RE-FETCH the object to see if the side effect happened anyway; sequential `user_id` on a "create contact from existing user" flow = mass PII.
- Q: "When the API says 'not allowed', did the write still take effect (check by reloading)? Is there a 'create from existing user' feature with a sequential id leaking PII at scale?"

### [345] Airbnb/luxuryretreats — account-linking ATO: sign up via Facebook, then sign up via EMAIL with the SAME email → logged straight into the OAuth account with attacker-chosen password (no verification) — Prince Chaddha [NEW ★ OAuth↔password account merge with no email verification = ATO]
- Where: dual signup (Facebook OAuth + email/password) keyed only on the email address.
- Approach/how-found: created the account via Facebook; then "Sign up with email" using the same email set a password and logged into the EXISTING Facebook-linked account without any verification — so knowing a victim's email lets you register a password over their OAuth-only account and take it over.
- Test: when an app supports both social login and email/password, register email/password over a victim's social-only account (same email) — if it merges without verifying the email, that's ATO.
- Q: "If a victim signed up via OAuth only, can I 'sign up with email' using their address, set a password, and inherit their account? Is email ownership verified on the second signup?"
