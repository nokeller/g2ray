### [276] Same endpoint, two flows — `?id=` appears in the forced-password-rotation flow but not the normal one; add `?id=88` to `/myaccount` → access/edit any user → change email → reset → ATO — Harsh Bothra (P1) [NEW ★ compare flows; inject the id a sibling flow exposes]
- Where: change-password / `/myaccount` endpoints; `?id=` present in the rotation flow, absent in the normal flow.
- Approach/how-found: a forced password-rotation page exposed `?id=`; after the normal flow that param vanished. He took the `/myaccount` URL (no id) and appended `?id=88` → accessed/edited user 88 → changed email → created a controlled account → reset → full ATO.
- Test: compare ALL flows of the same endpoint (forced rotation vs normal vs mobile) — a param exposed in one flow is often injectable in another. On `/myaccount`-style endpoints with no visible id, fuzz `id/uid/user_id/oid`.
- Q: "Does the same endpoint expose an id param in one flow but not another? Can I append `?id=`/`uid=` to a `/myaccount` endpoint that normally omits it to reach other users?"

### [279] Edmodo (LMS) — 7 IDORs across every feature: quiz files, `badge_id`, schedule `user_id`, invite-by-email (add+reset student=ATO), library `file_id`+`library_id`, grade `submitter_id`, planner `group_id`; always read the RAW response — Pratyush Sarangi [NEW ★ systematically swap the object id in EVERY feature]
- Where: Edmodo endpoints — quiz files, badges (`badge_id`), schedules (`user_id`), email-invite, library (`file_id`+`library_id`), grades (`submitter_id`), planner (`group_id`).
- Approach/how-found: with teacher/student test accounts he swapped the object id in each feature → cross-account read/write (assign others' badges, create schedules for anyone, grade any student, read others' library/quiz files); invite-by-email let him add a student and reset their password (student ATO). He always checked the RAW Burp response (the API returned data the UI filtered).
- Test: in role-based apps (LMS/edtech/SaaS), every feature with an object id is a candidate — swap `submitter_id/user_id/group_id/file_id/badge_id`. Invite-by-email flows can add+control arbitrary users. Read raw API responses — clients filter sensitive fields the server still sends.
- Q: "For each feature, is there an object id (submitter_id/user_id/group_id/file_id) I can swap cross-account? Does invite-by-email let me add+reset a victim? Does the raw response carry fields the UI hides?"

### [280] Five ATOs in one site — login-failure leaks userid → JWT identity swap; Google-OAuth email swap; 4-digit OTP no-rate-limit brute; OTP response-manipulation; reset keyed by a userid (not OTP) — Vasuyadav [NEW ★ enumerate EVERY auth path on one target]
- Where: JWT (userid), Google OAuth (email param), OTP verify (no rate limit + response manip), reset set-password (userid in body, no OTP field).
- Approach/how-found: (1) login-with-wrong-password response leaked the userid → swap it in the JWT → log into account 2. (2) intercept Google sign-in, change the email → into a different account. (3) 4-digit OTP had no rate limit → brute. (4) OTP response-manipulation (wrong code, rewrite response to the success shape). (5) the set-new-password request carried an (encrypted but response-leaked) userid and no OTP field → swap userid → change anyone's password.
- Test: enumerate ALL auth paths on one target — JWT identity swap, OAuth email swap, OTP brute (no rate limit), OTP response-manip, and reset-keyed-by-userid-not-OTP. Login-failure responses frequently leak the userid.
- Q: "Across login/OAuth/OTP/reset, which trusts a client value (JWT userid, OAuth email, userid in reset) or lacks rate-limit/response binding? Does a login-failure response leak the userid?"

### [281] Reset token validates ONLY the userid (base64 `userid+email+…`), never expires; a JS-found endpoint leaks PII+email by userid → brute (id 1 = admin) → reset → ATO — Pradeep Kumar [DUP reinforcement: partial-token validation + JS-found id-leak → ATO]
- Where: reset link (base64 `588588killer@gmail.com…+++588588`; only the userid validated; non-expiring); a JS-referenced endpoint leaking PII by `userID`.
- Approach/how-found: decoded the reset token — only the userid portion was validated (email/gibberish ignored) and the link didn't expire → reset anyone by userid. A JS-referenced IDOR endpoint returned username/email/residence address by userid → brute (userID 1 = admin) → harvest email → reset → ATO.
- Test: decode reset tokens; if only the userid is validated (and links don't expire), reset by userid. Mine JS for an endpoint that leaks PII+email by userid to enumerate targets (and find admin at id 1).
- Q: "Does the reset token validate only the userid (ignoring email/signature) and never expire? Is there a JS-referenced endpoint leaking PII/email by userid to enumerate (admin = id 1)?"

### [283] NodeBB (CVE-2020-15149) — change-password request carries a `uid`; set it to the admin's (uid=1) → change admin's password → admin ATO/privesc — Muhammed Eren Uygun ($512) [DUP reinforcement: self-service password change keyed by swappable uid → admin id=1]
- Where: NodeBB change-password request with a `uid` field (admin uid=1, found by trying small numbers).
- Approach/how-found: the change-password request keyed on `uid` rather than the session; supplying your current password but replacing `uid` with `1` changed the admin's password → login as admin.
- Test: change-password/profile-update requests that carry a `uid`/`id` → swap to the admin's id (often 1) → admin ATO. For known forum/CMS software (NodeBB/Discourse/etc.), check public IDOR CVEs and the uid in self-service requests.
- Q: "Does the change-password request carry a `uid` I can set to the admin's (id=1)? Is this known software with a documented IDOR CVE?"

### [286] Fashion e-commerce — primary address endpoints resisted IDOR, but the CHECKOUT flow's alternate `saveaddress` accepted a foreign `id_customer_address` → delete a victim's address (cache hid it until re-login) — techkranti/Amey [NEW ★ alternate endpoint for the same object + cache-masked impact]
- Where: hardened `/customer/address/edit|delete` vs vulnerable `/checkout/shipment/saveaddress/` with `AddressForm[id_customer_address]`.
- Approach/how-found: the obvious address CRUD resisted IDOR (tried PP, id arrays, query-vs-body). The checkout flow had a DIFFERENT save-address endpoint; setting `id_customer_address` to another account's address id corrupted/deleted the victim's address. The change wasn't visible immediately (cache) — it appeared after the victim logged out and back in.
- Test: the same object usually has MULTIPLE endpoints (account vs checkout vs mobile/API) — when one is hardened, attack the alternates (different, weaker code paths). Verify destructive IDORs after a fresh session; caching hides the change otherwise.
- Q: "Does the same object have an alternate endpoint (checkout/mobile/API) with weaker authz? Did I re-login to confirm a destructive change the cache might mask?"

### [287] Profile-image upload — overwrite a victim's profile image; upload recon = arbitrary file type? storage location? naming convention? — Vuk Ivanovic [NEW: predictable upload path/name keyed by user → overwrite others' files] (tail member-locked; methodology captured from intro)
- Where: profile-image upload (stored on the same domain).
- Approach/how-found: upload recon — check whether arbitrary file types are accepted, WHERE the file is stored, and the NAMING CONVENTION. The bug allowed overwriting another user's profile image (the exact id/path swap is paywalled, but the lever is a predictable, user-keyed filename/path).
- Test: on uploads, note storage location + naming convention; if the path/filename is predictable or contains a user id, you may overwrite a victim's file. AWS storage → try XXE; same-domain → consider XSS via the filename in `img src`.
- Q: "Is the uploaded file's name/path predictable or keyed by a user id I can swap to overwrite a victim's file? Where is it stored (AWS→XXE, same-domain→XSS via filename)?"
