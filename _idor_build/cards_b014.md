### [69] Fintech GraphQL spend-rules — Bearer not validated + inject an undocumented `spendRuleId` to read others' rules — 0x1int ($700) [NEW: undocumented variable injection]
- Where: card spend-control "Rule Types" GraphQL; one query `FindSpendRule` backs every rule type; create via `CreateStreetAddressSpendRule(input)`.
- Approach/how-found: noticed `Authorization: Bearer` wasn't validated server-side for this feature. The docs exposed no id input, but he added `"spendRuleId":"<id>"` to the input variables anyway → the mutation/`FindSpendRule` returned another user's spend-rule data → swap the id to read any user's rules.
- Test: don't limit yourself to documented variables — inject likely id fields (`spendRuleId`/`id`/`ownerId`) into GraphQL inputs even when absent from the schema/docs; and check whether the Bearer token is actually enforced per-operation.
- Q: "Does adding an undocumented `id`/`*RuleId`/`ownerId` variable to a GraphQL input return another user's object? Is the Bearer token actually validated for this operation?"

### [71] APK source → hidden `loginToken` endpoint; the token value is another endpoint's response `id` → mass PII — Vengeance [NEW: cross-endpoint id reuse + mobile-source recon]
- Where: web+mobile scope; apktool-decompiled APK revealed a URL with a `loginToken` param the web app never used.
- Approach/how-found: random `loginToken` → 500. Searched Burp history → `/user/get-finance-user` response contained a numeric `id`; using that `id` as `loginToken` returned his data → Intruder brute-forced `loginToken` (numeric) → all customers' data. (apkleaks/apktool to extract URIs/endpoints/secrets.)
- Test: decompile the mobile app even if you only want the web bug — it reveals hidden endpoints; when a token looks opaque, hunt other endpoints' responses for a value that satisfies it (the "secret" is often a plain `id` returned elsewhere), then brute.
- Q: "What endpoints/params does the APK reveal that the web UI never calls? Is a mysterious token actually a numeric `id` returned by another endpoint I can reuse and brute?"

### [72] `user_id` cookie IDOR on email-change → forgot-password → ATO (mass lockout) — Yaseen Zubair [NEW: cookie-as-identity on a state-changing endpoint]
- Where: a `user_id` cookie (6-digit). Swapping it for page views failed, but the change-email request trusts the cookie.
- Approach/how-found: intercept change-email → set `user_id` cookie to the victim's id + a new nonexistent email (Burp Collaborator address) → success → request forgot-password to that attacker email → reset → ATO. Limitation: victim's user_id unknown, so brute = mass email-change/lockout.
- Test: even if a `user_id` cookie doesn't change what you *see*, test it on *state-changing* requests (change email/phone/password); pair with a controlled email (collaborator/catch-all) + forgot-password for ATO.
- Q: "Does any write endpoint trust a `user_id`/`uid` cookie as identity (vs. the session)? Can I set it to a victim + my email, then reset to take over?"

### [73] Team-delete keyed by member `key`; leak the key via share-profile HPP (`&u=`) → delete any user — rezaduty (Twitter) [NEW: HPP leaks the key a delete-IDOR needs]
- Where: `POST /v1/team/delete` body `{"key":"<memberKey>"}` (403 without a valid key).
- Approach/how-found: swapping `key` deletes that member (403→204), but you need the victim's key. The share-profile feature was vulnerable to parameter pollution — adding `&u=evil.com` leaked the **user key** in the response → delete any user regardless of permission. (Same write-up: HTML injection in a `name` field exfiltrated project/user ids via a collaborator `<img>` in the referer.)
- Test: when a destructive action needs a per-object key, find a share/profile/export endpoint that leaks that key — and try HPP (`&u=`/duplicate params) to make it disclose another user's key. Use `<img src=collaborator>` HTML injection to exfil ids carried in the referer/markup.
- Q: "Does a delete/action need a member/object `key` obtainable via a share/profile endpoint or HPP? Can HTML injection exfil ids through the referer?"
