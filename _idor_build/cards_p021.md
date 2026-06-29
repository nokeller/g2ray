### [306] Razer Pay $6,000: defeat request-signing to unlock IDORs (offline re-sign + Frida hook) — sambal0x [NEW ★ beat anti-tamper signatures]
- Where: e-wallet Android app; every GET/POST carries a calculated `signature` to prevent tampering.
- Approach/how-found: copying another user's signed request failed (sig bound to session). Decompiled APK (apktool + jadx) → found `MD5Encode` signing method → copied the Java into IntelliJ and recomputed signatures OFFLINE (matched a real one to confirm). Then on `/deleteBankAccount?id=<seq>` he computed valid sigs for predictable ids → deleted another account's bank account. Other endpoints used different/obfuscated signing → used **Frida to hook `MD5Encode`** so the app re-signs his tampered payloads automatically → mass IDOR (join chat groups, read messages, steal shared "red-packet" money, view/modify transactions/PII).
- Test: if tampering is blocked by a client signature/HMAC, either reverse the signing function and re-sign offline, or Frida-hook the signing method to auto-sign tampered requests — then run normal IDOR tests underneath.
- Q: "Is parameter tampering blocked only by a client-side signature? Can I reverse/Frida-hook the signing routine to re-sign arbitrary payloads, then swap ids freely?"

### [309] Google Crisis Map: member-permission field accepts arbitrary id → discloses that user's email (enumerate 32k) — websecblog [NEW: id→email via member list]
- Where: domain settings "Members" add form → `POST .../.admin`.
- Approach/how-found: adding a member sends `new_user`+`new_user.permission`; re-saving showed permissions keyed by a short numeric id (`123456.permission`) while the UI lists members by EMAIL. Sending `123457.permission` ADDED user id 123457 as a member → the Members page then revealed their EMAIL. IDs are incremental from 0 (latest ~32000) → enumerate every registered user's email.
- Test: a "set member/permission for id N" field that accepts an arbitrary user id, then surfaces that user's email/name in the member list = an id→PII oracle; check if ids start at 0/sequential.
- Q: "Does a member/permission/role field accept an arbitrary user id and then disclose that user's email in the member list? Are ids sequential from 0?"

### [310] VLC iOS WiFi-share unauth IDOR — inputzero [NEW: local share-server]
- "Network > Sharing via WiFi" runs an unauthenticated web server on port 80 listing shared media; crawl the device IP to download videos without consent. Test mobile "share over WiFi/local" features for unauth listing.
- Q: "Does a 'share over WiFi/local network' feature run an unauthenticated web server I can crawl for other users' files?"

### [320] Notification PUT IDOR: recipients[] mass-target + commenterId spoof — footstep.ninja [DUP reinforcement]
- Share/comment notification `PUT` body has `recipients:[{type:User,id}]` and `commenterId`. Add many ids to `recipients[]` → notify any/all users; swap `commenterId` → send the notification on behalf of another user. Q: "Is the recipients an array I can fill with victim ids? Can I swap the sender/commenter id to act as someone else?"

### [321] Self-XSS + incremental-id IDOR on suppliers = stored XSS — footstep.ninja [DUP reinforcement]
- Supplier-name self-XSS (fires when the owner deletes the supplier) + `PUT shop_account_request{id:<incremental>}` IDOR to edit OTHER users' suppliers → plant the payload in a victim's supplier → fires on their delete. Q: covered by self-XSS+IDOR.

### [325] HTTP Request Smuggling + unauth-write IDOR = capture victim's card into my account — hipotermia [NEW ★ smuggling × IDOR]
- Where: CL.TE desync (found via Burp Request Smuggler); hidden Swagger revealed `POST /addCard/<userId>` taking only a user id in the path (no auth header/cookie).
- Approach/how-found: `/addCard/<id>` alone is "why would anyone add a card to another account?" — low value. Weaponized with smuggling: prefix-smuggle `POST /addCard/<MY_id>` so the NEXT victim request gets its path rewritten → the victim's submitted card data is saved to the ATTACKER's account → steal it. "IDOR on steroids."
- Test: pair request smuggling with a low-value unauth/IDOR write keyed by your own id so an in-flight victim request writes their data into your object. Hunt hidden Swagger for the unauth write.
- Q: "Can request smuggling rewrite a victim's request into MY object id so their submitted data lands in my account? Is there an unauth write keyed only by a user id (from hidden Swagger)?"

### [326] IDOR via WebSocket comment frame (mint a fresh single-use nonce) — footstep.ninja [NEW: defeat single-use token in WS IDOR]
- WS comment frame carries `author`, `commentUUID`, `slideUUID`. Swapping `author` failed because `commentUUID` is single-use. Fix: make a NEW comment with intercept on, copy the fresh `commentUUID` from the paired HTTP PUT, DROP both requests, then in Repeater send the WS frame with the fresh UUID + swapped author → comment as any user (in/out of team).
- Test: open the WS tab; if a single-use nonce blocks replay, mint a fresh one via a parallel action and reuse it with the swapped id.
- Q: "Does the WS frame carry a user/author id plus a single-use token? Can I mint a fresh token via a parallel action then swap the id?"

### [329] Tokopedia like/dislike IDOR: swap user_id + drop params to bypass auth — fadhilthomas [DUP reinforcement]
- `reputationapp/review/api/v1/likedislike` with product_id/shop_id/user_id; swap user_id and delete some params → like/dislike as any user. Reinforces "delete params to bypass user auth."

### [331] IDOR → RCE on a docker hosting platform (creds leak + phpMyAdmin-by-id) — rahulr [NEW ★ IDOR→RCE chain]
- Where: WP/Joomla hosting platform; only an `access_token` cookie, no per-object authz.
- Approach/how-found: `GET /site/<ID>` IDOR into any user's dashboard (start/stop services etc). Fuzzed → a debug endpoint `GET /sites/<ID>/container?access_token=` leaked rancher url, LB private IP, and per-site **MySQL + SFTP credentials** (swap ID → any user's creds). The DB sits in a separate container behind a proxy, but `/site/<ID>/pmalogin` (phpMyAdmin login) authorizes by the **site ID** → swap to victim's ID → logged into their DB → edit WordPress → code execution / full site takeover.
- Test: chain IDOR with debug/container/info endpoints that leak infra creds by id, and "console/pmalogin/ssh/exec" helpers that authorize by the swappable object id → DB/code access.
- Q: "Is there a debug/container/info endpoint leaking DB/SFTP/infra creds keyed by a swappable id? Does a phpMyAdmin/console/exec helper authorize by the object id (→ RCE)?"

### [342] IDOR via inbound-email reply-to address (encodes UserID-ProjectID) — footstep.ninja [NEW: email-address-encoded id]
- The reply-to for notifications was `[const]+[projectToken]-[UserID]-[ProjectID]@inbound.postmarkapp.com`. Swap your UserID (others' ids are visible on profiles) → email the crafted address → reply/post activity on behalf of the victim.
- Test: decode inbound/reply-to email addresses — they often encode user/object ids you can swap to act as another user via email; also test persistent association of a removed email to projects.
- Q: "Does an inbound/reply-to email address encode user/object ids I can swap to act as someone else via email?"
