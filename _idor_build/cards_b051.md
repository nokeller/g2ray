### [297] Facebook Business Manager — `RemoveFundingSourceButtonV2CCMutation {biz_id, fs_id}` deletes saved credit cards with NO role check → terminate any business's running ads — Rohit kumar [NEW: destructive billing mutation keyed by org_id+resource_id, no role check]
- Where: `business.facebook.com` GraphQL `RemoveFundingSourceButtonV2CCMutation` with `biz_id` + `fs_id` (credit card id).
- Approach/how-found: the remove-funding-source mutation keyed only on `biz_id`+`fs_id` with no admin/role verification → delete any business's saved cards (USER B deletes BUSINESS A's cards) → all their ads stop. IDs obtained from ex-admin browser history or by brute-forcing the credit card id.
- Test: destructive business/billing mutations keyed by org_id+resource_id frequently skip role checks → remove others' payment methods/resources (high operational impact). Harvest the ids from your own past-admin history or brute them.
- Q: "Does a delete-payment / remove-resource mutation key only on org_id+resource_id without a role check? Can I disrupt a business by removing its funding sources?"

### [298] Facebook Series (Creator Studio) — inject a victim's image-id into a series' Poster/Cover; deleting the series cascade-deletes the victim's image — Pouya Darabi ($10,000) [NEW ★ container claims foreign object → cascade-delete]
- Where: FB Creator Studio "Series" feature; image-ids in Poster Art / Cover Image.
- Approach/how-found: a newly-added Series feature let you attach image-ids; modifying the request with a VICTIM's image-id made the series "own" that image. Deleting the series then cascade-deleted the victim's image.
- Test: "add to series/album/collection/playlist" features that attach object-ids without ownership checks → inject a victim's object id, then delete the CONTAINER → cascade-deletes their object. New features ship this pattern repeatedly (cf. Portal albums).
- Q: "Can I attach a victim's object id to a container (series/album/collection) I own, then delete the container to cascade-delete their object?"

### [300] IDOR in the session cookie — `shoppingID=<hash>…SESSIONID<numeric-id>…` embeds a sequential user id; swap it → authenticate as other users → mass ATO — Zonduu [DUP reinforcement: IDOR lives in the cookie]
- Where: `shoppingID` session cookie containing an embedded numeric user id next to `SESSIONID` (e.g. `…SESSIONID3552522…`).
- Approach/how-found: while reproducing a CSRF issue he examined the session cookie and noticed a numeric id embedded alongside the session token; swapping that id authenticated him as other users → mass ATO.
- Test: dissect session cookies for an embedded user id (often adjacent to / labeled near SESSIONID); if sequential, swap it → session hijack. IDOR isn't only in URLs/bodies — it's in cookies too.
- Q: "Does the session cookie embed a (sequential) user id I can swap to hijack other users' sessions?"

### [302] Source/JS reading → hidden `tab=secret` param value (not in UI) on a `user_id` endpoint → sensitive data — hack4bounty [NEW: recon for hidden param VALUES, not just params]
- Where: an endpoint with `user_id` + a hidden `tab` param whose `secret` value isn't exposed in the UI.
- Approach/how-found: reading the source/JS surfaced an endpoint and a `tab` parameter; setting `tab=secret` (a value never shown in the UI) returned sensitive data the normal flow hid. The program asked how he found a param that wasn't in the UI — recon.
- Test: read source/JS for endpoints AND for hidden param VALUES (`tab=secret`, `view=admin`, `mode=debug`, `type=internal`). Enumerate enum-style param values, not just the param names.
- Q: "Does source/JS reveal hidden param values (tab=secret, view=internal, mode=debug) that unlock sensitive data on an id-keyed endpoint?"

### [303] E-commerce — order READ was 401 when swapped, but the cancel-order ACTION keyed by a sequential order id wasn't protected → cancel any user's order (200=done, 404=none) — Md Saikat (10k BDT) [DUP reinforcement: read-protected ≠ action-protected]
- Where: cancel-order endpoint keyed by a sequential order id (the order-view endpoint returned 401 on swap).
- Approach/how-found: swapping the order id on the VIEW page gave 401, but the cancel-order ACTION endpoint accepted a swapped order id → 200 → cancelled another user's order without access. 200 vs 404 confirmed hits.
- Test: when reading an object is protected, test the ACTIONS on it (cancel/refund/delete/update) — they're often unprotected separately. 200-vs-404 is the exists/hit oracle. Read-protected does not mean action-protected.
- Q: "Is the cancel/refund/delete/update ACTION on an object protected even though its read is? Can I act on any object by swapping a sequential id?"

### [304] "One Param → $10k" — harvest EVERY param from Burp history into a wordlist, fuzz across all endpoints AND fuzz method (GET/POST/PUT/DELETE) + Content-Type (json↔form) → endpoints disclose plaintext passwords — Bilal Khan [NEW ★ cross-endpoint param + method + content-type fuzzing]
- Where: `api.redacted.com /v2/*` (React app, Bearer auth, no CSRF); params cross-pollinated from other requests.
- Approach/how-found: nothing obvious, so he saved ALL parameters seen in Burp history into a wordlist and fuzzed them across endpoints with Intruder positions on method/path/param/value (`§CHECK§ /v2/§one§?§two§=§three§`) → password disclosure ($1k). Then he swapped HTTP methods (GET↔POST↔PUT↔DELETE) and Content-Types (json↔form) → many more endpoints leaked plaintext passwords ($10k). The winning params didn't belong to the original requests.
- Test: build a param wordlist from ALL of Burp history → fuzz it on EVERY endpoint; ALSO fuzz the HTTP method and Content-Type (json↔x-www-form-urlencoded). Foreign params + alternate methods unlock sensitive data the normal request hides.
- Q: "Have I fuzzed every harvested param across every endpoint with every method + content-type? Do params from unrelated requests unlock data elsewhere?"

### [305] Chained IDOR + XSS → ATO — a 'low-impact' profile IDOR controls the username, which is reflected UNSANITIZED on a points page; store XSS via the IDOR → steal auth token → ATO — Bilal Khan ($1,050) [DUP reinforcement: downgraded IDOR-write + reflected field = token theft]
- Where: profile-update IDOR (username field, couldn't change primary email); a profile-points endpoint reflecting username unsanitized.
- Approach/how-found: the IDOR only changed profile data (not the login email) and was downgraded to P4. But a points page reflected the username without sanitization → he set the username (via the IDOR) to an XSS payload → exfiltrated the auth token → ATO.
- Test: a "low-impact" profile-write IDOR becomes critical if any field it controls is reflected unsanitized elsewhere (points/leaderboard/activity/public profile) → store XSS in that field → steal the auth token → ATO. Re-examine downgraded IDORs for a rendering sink.
- Q: "Does a low-impact profile IDOR control a field rendered unsanitized elsewhere? Can I store XSS via the IDOR to steal the auth token → ATO?"
