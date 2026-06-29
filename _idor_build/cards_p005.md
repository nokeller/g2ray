### [41] QuickBlox SDK: client-embedded app secrets → mass BOLA on /ID.json + chained IoT/telemed takeover — Claroty Team82 [NEW]
- Where: chat/video SDK under telemedicine, finance, IoT intercom apps.
- Approach/how-found: architecture review showed every client needs the app secrets (AUTH_KEY/SECRET/AccountKey) to mint a `QB-Token` → secrets are necessarily shipped in the app. Extracted them via reverse-engineering/Frida (even when encrypted/obfuscated). App-level token → `GET /users.json` (all users), `GET /<ID>.json` (PII by **sequential** id), `POST /users.json` (create rogue user). If owner disabled app-level listing, create a rogue user and still brute the sequential `/<ID>.json`. Chains: Rozcom intercom user_id = `BuildingID + phone` (structured) → leaked DB gave both; `getbuildingdetailpublic?buildingId=` (address), `gettenantauth?cellular=<phone>` returned the user's **static "OTP"** (reused forever) → login as anyone, open doors/cameras. Telemedicine app set every QB user's password to a **hardcoded per-role static string** → impersonate any doctor/patient, read medical records.
- Test: pull mobile/SDK secrets from the APK; hit the vendor API's list + by-id (sequential) routes; look for static OTP/passwords; decompose structured user_ids (building+phone).
- Q: "Does the mobile app ship API secrets that grant an app-level token? Is there a by-id route over sequential ids? Is the 'OTP'/password actually static? Is the user_id built from guessable parts?"

### [44] Cockpit CMS: relational-mapping populate() resolves {_id,_model} with no authz + NoSQL type confusion — ghostccamm [NEW: ref-injection]
- Where: OSS CMS Content API (read the source in `modules/Content/bootstrap.php`).
- Approach/how-found: `populate()` auto-resolves any value containing `_id`+`_model` into the referenced object — with **zero ownership check**. Created two collections + a Link field to see the request shape, noticed `_model`/`_id` are client-supplied, and the server never validates the link type. Because storage is NoSQL/BSON, he injected `_id`+`_model` into a *non-link* field on a public collection (type confusion), then hit `?populate=1` → server fetched and returned an arbitrary model/object. (Need model name (guessable) + ObjectID — cliffhanger to part 2.)
- Test: in OSS, grep the fetch/populate/expand code for an ownership check; try smuggling a `{_id,_model}` (or `$ref`) object into any field, then trigger the populate/expand param.
- Q: "Does an ORM 'populate/expand/include' path resolve client-supplied object refs without an authz check? Can I inject a relational ref into a plain field (NoSQL type confusion) and trigger expansion?"

### [48] Microsoft Teams: client-side 'no files to external tenants' bypassed by recipient-id IDOR → malware delivery — JUMPSEC [NEW: client-side control + cross-tenant]
- Where: `POST /v1/users/ME/conversations/<RECIPIENT_ID>/messages`.
- Approach/how-found: the "can't send files to external tenants" restriction is enforced **client-side**. Swapped the internal/external recipient ID in the POST (classic IDOR) → file delivered cross-tenant; it's hosted on a trusted SharePoint domain and appears as a file (not a link), bypassing nearly all anti-phishing controls.
- Test: any "you can't do X to an external/other party" limit — replay server-side and swap the recipient/target id; verify whether the block was only UI/client-side.
- Q: "Is this restriction enforced server-side or just client-side? If I swap the recipient/tenant id in the raw request, does the blocked action go through?"

### [63] Self-XSS → Stored XSS via company_id IDOR (low-priv → admin) — arben.sh [NEW: self-XSS upgrade]
- Where: create-folder request `project_id=0&parent_folder_id=7&company_id=10&folder_name=<payload>`.
- Approach/how-found: folder name unsanitized = XSS, but only the owner sees it (self-XSS). From a low-priv account he changed `company_id`/`parent_folder_id` to the ADMIN's org/folder → the malicious folder is created inside the victim org → stored XSS fires for other-org admins when they preview/move files. Guessable org ids + no WAF.
- Test: when you have a self-XSS, look for an IDOR (org/container/parent id in the create request) that lets you plant it in someone else's container.
- Q: "Is my self-XSS truly self-only, or can an IDOR (company_id/parent_id swap) store it in a victim's space so it becomes stored XSS against an admin?"

### [66] JS-file analysis as an IDOR source (email-keyed endpoint, hidden /rmt_stage) — screamy7 [NEW reinforcement: JS sourcing]
- Approach/how-found: workflow = browse app → set scope incl. CDNs → extract all JS (Uproot-js) → grep `/api`, `POST`, `params`, `token`, `Content-Type`. In a 90k-line JS he found an endpoint that takes the **user's email** as a param to leak confidential data (IDOR). Separately, JS referenced `/rmt_stage` (un-bruteforceable word) → an internal proxy/second server → exposed CKFinder → admin pwn.
- Test: read JS for endpoints/params that take an email/id you can swap, and for non-guessable hidden paths.
- Q: "Which id/email-keyed endpoints or hidden paths appear ONLY in JS that the UI never calls for me?"

### [76] 2FA/OTP step keyed by swappable OTPUserId → unauth mass ATO + no-role admin dashboard — z-sec [NEW: IDOR in auth flow]
- Where: post-login OTP request `OTPUserId=<5 digits>&LoginOTP=...`.
- Approach/how-found: 2FA enabled only for admins; after admin login the OTP step's request identified the user by a client-supplied `OTPUserId`. Swapping it logged into another account, and `LoginOTP` wasn't even validated. The same request sat in the JS, so it worked fully unauthenticated → log in as anyone by id. Then `/admin/dashboard` loaded for any authenticated user (no role check) → User Management → create an admin.
- Test: inspect the 2FA/OTP/step-up request for a user-id param; swap it; try blank/invalid OTP; then direct-browse admin routes as a normal user.
- Q: "Does the 2FA/OTP/step-up step identify the user by a client-supplied id I can swap, and is the OTP value actually checked? Does /admin load without a role check?"

### [79] $0 (gov) 100M+ PII: printApplication?id= decrement + DB tar in public upload dir — Jason Haddix [NEW reinforcement]
- Where: VISA/passport gov portal; "Export to PDF" → `printApplication?id=105608983`.
- Approach: decrement the id → another applicant's full PII. Then found a DB **backup .tar in the same directory user images upload to** — no authz, contained credit cards. "Always check /backup or for backup zip/tar files."
- Q: "Does the print/export PDF endpoint use a sequential id? Is there a backup .tar/.zip in the uploads/public dir?"

### [82] Meta Quest: force any Oculus user to follow you by swapping follow_requester_id — vulnano [NEW: actor-id swap in accept]
- Where: `OCAccountFollowRequestButtonsAcceptMutation` (accept-follow GraphQL), param `follow_requester_id`.
- Approach: the accept-follow-request mutation took the *requester's* id as a param; swap it to any Oculus id → that user now follows you with no approval (manufacture fake real-follower accounts).
- Q: "In an accept/approve/confirm request, can I swap the *other* party's id to force them into the relationship/action?"

### [83] $11,250 FB: delete any video via reframe/crop params + DELAYED effect — Bassem Bazzoun [NEW: destruction-by-corruption]
- Where: Meta business suite Reel crop/trim → GraphQL `doc_id:8426940007331645`, `videoID` + `reframeAspectRatios`.
- Approach/how-found: persistence — tested trim (failed) and crop on others' videos. The reframe request accepted **any videoID**; setting an extreme aspect ratio (denominator 11/numerator 1, i.e. 1×N) made the reframe library output a broken/unloadable video = effective deletion of anyone's video/reel/live. Crucial: the effect was **delayed ~5 min**, which is why he missed it on day 1 — he rechecked the next day and saw a test video gone.
- Test: an edit/transform/crop/convert endpoint with no owner check + extreme parameters can corrupt others' content; re-verify later because effects can be async.
- Q: "Does an edit/crop/transform endpoint accept another user's object id? Can extreme params corrupt/destroy it? Is the effect delayed (recheck after minutes)?"

### [92] rez0 'hacking on a plane': test the unguessable swap anyway, pivot lookup key, reset→ATO — rez0 [NEW reinforcement: pivot the key]
- Where: wifi provider; `GET /edge/apidecorator/v3/customer?...&user_name=<timestamped>`.
- Approach/how-found: `user_name` looked unguessable (timestamp) so most would skip — he tested the swap anyway → worked. Then pivoted the lookup key to fields visible in the response: `email_address` (targeted) → worked; `customer_id` (integer) → enumerate ALL (tens of millions). Separately the reset flow's `PUT /customer` had `"user":"<username>"` in the body — swap to victim → full ATO (verified on Sam Curry's account).
- Test: always try the "unguessable" swap; then change the lookup parameter to the most enumerable field present in the response (email → integer id); check the reset endpoint for a swappable user field.
- Q: "Even if the id looks unguessable, does the swap work? Can I switch the lookup key to an integer/email in the response to widen impact? Does the reset endpoint take a user field I can swap?"

### [94] IoT picture frame: sequential device_token + unauth device endpoints + unauth AcceptBind — scrawledsecurity [NEW: unauth IoT lifecycle endpoints]
- Where: Ourphoto app / frame backend.
- Approach/how-found: mobile user_id decrement failed, but `POST /device/signin` took a **sequential `device_token`** and was **unauthenticated** → enumerate every frame's info, bound users' ids, and cleartext creds. `POST /device/AcceptBind` needed only user_id+device_id (both leaked) and was unauth → bind to ANY frame without the physical "Accept" → push photos. Email-to-frame ignored the device_token subject check → spoof an authorized sender. Root cause of the original mystery found via the "Feedback → share app log" feature leaking sender_id.
- Test: for IoT, capture frame↔cloud traffic separately from app↔cloud; the device/bind/signin lifecycle endpoints are often unauthenticated and keyed by sequential device ids; app log/feedback features leak ids.
- Q: "Are the device signin/bind/accept endpoints authenticated, and is device_token sequential? Does a feedback/log-upload feature leak other users' ids?"
