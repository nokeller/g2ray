### [308] Unlock a blocked account — reuse the blocked account's reset token in a NON-blocked reset flow; after the fix, supply the token as a duplicate/extra param (HPP) to re-bypass — Maria Zulfiqar [NEW ★ token reuse across flows + HPP patch bypass]
- Where: password-reset flow; reset token moved between blocked and valid accounts; extra `password_reset_token` param.
- Approach/how-found: brute-locked her own account (paid unlock). The reset email still arrived when blocked, but the success page refused it. Copying the blocked account's reset token into a VALID account's reset request (Burp) completed the reset → account back. After it was fixed, adding the same token as an ADDITIONAL parameter (`password_reset_token=<blockedtoken>`) bypassed the patch again.
- Test: when an action is blocked at one layer, reuse its token/value in a different (unblocked) flow. After a fix, retry the value as a duplicate/extra parameter (HPP) — patches often guard one parameter position but not a second.
- Q: "Can I reuse a blocked/denied token in an unblocked flow? After a fix, does supplying the value as a duplicate/extra param (HPP) bypass the patch?"

### [312] Reset-submit body carries `email` → swap to victim → password set + auto-login (admin email = admin ATO); found on an overlooked subdomain — Swapmaurya (P1) [DUP reinforcement: email-in-reset-body ATO + pivot to subdomains]
- Where: `POST /login/internalResetPasswordSubmit {email, password, confirmPassword}` on a subdomain.
- Approach/how-found: main domain was picked clean (dupes); pivoted to subdomains. The reset-submit request carried the `email` in the body → swapping it to a victim set their password and logged him straight into their account; the admin email → admin ATO.
- Test: reset/change-password SUBMIT requests that carry `email` in the body → swap to a victim → set their password (auto-login). When the main domain is exhausted, move to subdomains.
- Q: "Does the reset-submit body carry an `email` I can swap to set a victim's password and auto-login? Have I pivoted to subdomains after main-domain dupes?"

### [314] REST `PUT /users/{mongoID}` honors a swapped path id with your own JWT → update + read any account's name/email/referral/company; MongoID looks secret but the endpoint has no brute-protection — vict0ni [NEW ★ keep-your-token + swap-the-path-id + MongoID brute]
- Where: `PUT /users/{24-hex ObjectId}` (own `Authorization: Bearer`, swap the path id).
- Approach/how-found: updating his own profile used `PUT /users/<myId>`; swapping the path id to account B's (while keeping his JWT) updated B's first/last name and leaked B's email, referral code (worth $30), companyID, subscription, phone, VAT, and `role`. The ObjectId is "secret", but the endpoint had no brute protection (24-hex space, generatable).
- Test: REST `PUT/PATCH /users/{id}` with the id in the path → swap to other ids while keeping your token. MongoIDs aren't fully random and there's often no rate limit → mass enumeration; responses leak role/company/referral.
- Q: "Does `PUT /users/{id}` honor a swapped path id with my token? Is the id a MongoID with no rate limit (mass-enumerable)? Does the response leak role/referral/company?"

### [315] Airline — a check-in request keys on ONLY `bookingRef` (drops the required lastname); swap → any passenger's PII; 6-char bookingRef = brute-able. Tips: accept integers where guids are shown; inject `"id":1` into JSON for blind IDOR — zseano [NEW ★ drop-the-second-factor + inject-id:1 blind IDOR]
- Where: airline check-in / booking-info endpoints keyed by `bookingRef` (a variant dropped the lastname second factor).
- Approach/how-found: used the site as intended (bought a £20 ticket → bookingRef). Viewing a booking normally needs bookingRef + lastname, but one request fetched passenger info with only `bookingRef` → swap → other passengers' PII across many features. 6-char bookingRefs → generate all combos → mass scrape.
- Test: find the request variant that drops a second identifier (lastname/DOB) and keys on a short guessable ref (PNR/bookingRef) → enumerate. Try integer ids where the UI shows guids/encrypted values; inject `"id":1` into JSON bodies that don't include it (blind IDOR).
- Q: "Is there a request variant that drops a second factor (lastname) and keys on a short guessable ref? Does the app accept integers where it shows guids? Did I inject `id:1` into JSON bodies that omit it (blind IDOR)?"

### [317] Facebook Events — co-host selection limited to friends in UI, but swapping `co_hosts[0]` in the submit to a non-friend/blocked user id adds them as co-host (server skips the friendship check) — whoisbinit ($750) [NEW: "select a friend/member" feature doesn't enforce the relationship server-side]
- Where: `POST /ajax/create/event/submit/ co_hosts[0]={userID}`.
- Approach/how-found: the UI only lets you pick friends as co-hosts; selecting a friend (User B, id 1008) and intercepting the submit, then replacing `co_hosts[0]` with a non-friend/blocked user's id (User C, 31337), added User C as co-host (with a notification) — the server didn't enforce the friendship.
- Test: when a feature restricts selection to friends/members (co-host, share-with, assign, invite), swap the id in the request to a non-eligible user — the relationship check is often UI-only. Impact: forced association / notification spoofing even on blocked users.
- Q: "Does a 'select a friend/member' feature enforce the relationship server-side, or can I swap the id to a non-friend/blocked/arbitrary user?"

### [318] Accidental delete IDOR — team-member delete request with `user_id=1` deleted the ADMIN account → delete any account — Sayaan Alam ($300) [DUP reinforcement: delete-by-user_id, admin = id 1]
- Where: team-member delete request keyed by `user_id` (admin = 1).
- Approach/how-found: while fuzzing the add/delete-team-member feature he sent a delete with `user_id=1` → the admin account got deleted (discovered via the admin's notification). Confirmed he could delete anyone.
- Test: team/member delete actions keyed by `user_id` → set to 1 (admin) or enumerate → delete admin/any user. Review Burp history for accidental destructive hits.
- Q: "Does a delete-member action key on `user_id` I can set to 1 (admin) or enumerate to delete any account?"

### [319] Second-order IDOR (canonical) — authz checked on step 1 (`show_receipt?id=`) but step 2 (`receipt_success`) reads the last id from SESSION without re-checking → desync the steps to leak a victim's receipt; also audit/activity logs re-expose denied data — Ozgur Alp [NEW ★ desync 2-step flows + audit-log second-order IDOR]
- Where: bank `show_receipt.aspx?id=` (authz here) → `receipt_success.aspx` (reads last id from session, NO recheck); account-activity/audit-log feature.
- Approach/how-found: Example 1 — request your own receipt but DON'T follow the redirect; from Repeater request the victim's `id` (don't follow); then forward the held `receipt_success` → it renders the last-requested id from session without ownership check → victim's receipt. Example 2 — `showMessageBody` returned Access Denied for others, but the account-activity AUDIT LOG re-displayed the denied data (logs fetched without access checks).
- Test: in 2-step flows where step 1 checks authz and step 2 reads from session/last-request, DESYNC them (request victim id, then trigger step 2). Always inspect audit/activity/notification logs — they frequently re-expose data the primary endpoint denied (second-order IDOR).
- Q: "Does a multi-step flow check authz only on step 1 while step 2 reads from session/last-request (desync it)? Do audit/activity/notification logs re-expose data the primary endpoint blocked?"
