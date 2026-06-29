### [191] Become Super Admin in ANY GSuite org via domains.google.com provisioning flow — secretlyhidden [NEW: swap org id across all steps of a checkout]
- Where: domains.google.com "add user/admin to GSuite" = 3 chained `POST /batchrpc` requests carrying the gsuite org id + domain.
- Approach/how-found: adding an admin runs a 3-request purchase flow. The org id (e.g. `5896212`) and domain are client-supplied in the body. Replace them with the VICTIM org's id (`25879957`) + domain across **all 3** requests → after the purchase popup, a super-admin is added to the victim's org and the new account's password is emailed to the attacker.
- Test: in multi-step provisioning/checkout/invite flows, the org/owner id is often client-controlled in every step — swap it consistently across all requests, not just the first.
- Q: "In a multi-request provisioning/checkout/invite flow, is the target org/owner id client-supplied in each step? Swapping it across ALL steps — does it provision me into the victim's org?"

### [196] Google Sites $7,500 IDOR: swap your id for account B's across the WHOLE sitemap → ListScripts leaks — r0ckin [DUP reinforcement: cross-service endpoint]
- Mapped the full sitemap with 2 accounts, then replaced every `catherinerecipespersonal` (acct A id) with `tomasideasontesting` (acct B). Most endpoints were protected, but `service=ListScripts` (which bridges to script.google.com) returned 200 with B's private script ids — a cross-service endpoint the devs forgot to protect.
- Q: "Which single endpoint, when I swap my identifier for account B's across the entire sitemap, leaks? Are cross-service/bridge endpoints (export, scripts, integrations) the weak ones?"

### [205] Google Marketing Platform IDOR via DELETING an unknown id + CSRF $3,133.70 — apapedulimu [NEW reinforcement: delete the mystery id]
- Edit-listing request carried 4 ids; one had an unknown origin. Instead of swapping it he **deleted it entirely** → request still succeeded and edited the victim's profile. Endpoint also lacked a CSRF token → CSRF on the same edit.
- Test: when you can't tell where an id comes from, try removing it (request may default to a broader/target scope); check state-changing requests for missing CSRF tokens.
- Q: "If I delete an id whose origin I don't understand, does the request still act (on a default/target)? Is this edit endpoint CSRF-protected?"

### [209] $4,300 ATO via `../` path traversal INSIDE the API route to bypass per-object 403 — usamav [NEW ★ killer technique]
- Where: `POST /workspaces/<wsId>/users` (invite); `PUT /users/<userId>/email`.
- Approach/how-found: replaying with the attacker token → `403`. He exhausted standard 403 bypasses (array-wrap id, JSON-wrap id, method swap, `/v1//v2/` versions, `*` wildcard, `%00`) — ALL failed. Then `POST /workspaces/<MY_wsId>/../<VICTIM_wsId>/users` → `200`: the authz check validates the **leading** id (his own workspace) while the server **normalizes `../`** and resolves to the victim workspace. Same trick on `PUT /users/<MY_id>/../<VICTIM_id>/email` → changed victim's email; the verification link went to the **new (attacker) email** → ATO. Sourced the victim `userId` by inviting their email (the invite response returns the invited user's id).
- Test: when per-object authz 403s, insert `/<mine>/../<victim>/` in the path so the gateway authorizes your id but the app resolves to the victim's. Source ids from invite/lookup responses. Check whether email-change verification goes to the new address.
- Q: "Does `/resource/<mine>/../<victim>/action` bypass the 403 (authz on the leading segment, path-normalization to the trailing one)? Does an invite/lookup-by-email response hand me the victim's id? Does email-change verification land on the NEW email (instant ATO)?"

### [226] Self-XSS → org takeover: state-transition surfaces a new IDOR list + image-injection delivery — r29k [NEW: state→new-endpoint + image-injection]
- Where: employee-management app; sticky-note `title` = stored (self) XSS.
- Approach/how-found: self-XSS only hit his own employees; cross-org share was 403. Marking a task **completed** (from an employee account) made an admin page "List all completed tasks" appear with a **6-digit id URL** — an IDOR: open it from another org, change the id → see anyone's completed tasks (including the one carrying his XSS). To avoid "send the victim a link," he used **image injection** in limited-HTML profile posts (`<a href="…/tasks?tab=completed&taskID=123456"><img src="evil.jpg"></a>`) visible to cross-org followers → click → XSS fires → CSRF-steals the admin csrf-token → POSTs `/admin/user` to add an attacker admin.
- Test: change an object's STATE (complete/archive/publish/submit) and watch for a NEW list/report endpoint that's IDOR-able; in limited-HTML fields, disguise a malicious URL behind `<a><img></a>` to remove the "send a link" friction.
- Q: "Does completing/archiving/publishing an object expose a new list/report URL with a guessable id? Can `<img>/<a>` in a comment/post hide my exploit URL so victims click it naturally?"

### [228] Google clientauthconfig: unauth brand lookup by project_number (even org-internal) — xdavidhu [NEW: semi-public id metadata leak]
- `GET /v1/brands/lookupkey/brand/<project_number>?readMask=*` on clientauthconfig.googleapis.com had no access control → returns any brand's info, including `isOrgInternal:true` ones that the OAuth flow refuses to reveal. The `project_number` (=brand_id) leaks from an exposed API key when you send it to an API not enabled on its project.
- Q: "Is there a metadata/brand/consent lookup endpoint with no authz keyed by a semi-public id (project_number/app_id)? Can that id be derived from a leaked API key's error?"

### [233] $2 IDOR: welcome.php?...&id= → other users' profile — evanricafort [DUP basic]
- Classic PHP `&id=` swap reveals other users' (whois-preset) profile data. Low value but reinforces: enumerate the `id` param on legacy `.php` profile pages; your own id returning your data proves the param is the object ref.

### [237] Uber Eats analytics IDOR via locationUUIDs + Burp Match&Replace to render it $2,000 — 0xprial [NEW: M&R to render victim data in the real UI]
- GraphQL `locationUUIDs` param; swap to another restaurant's UUID → their analytics, but the raw JSON wasn't human-readable. He set a Burp **Match & Replace** rule (his UUID → victim's, plus currency) so the **legit frontend parses the victim's data into the normal dashboard** (sales by hour/item, CSV export).
- Test: when an IDOR returns raw/unreadable data, use Burp Match&Replace (your id → victim's) so the application's own frontend renders it cleanly.
- Q: "Can I set a Match&Replace (my id → victim's) so the app's own UI renders the victim's data, turning a raw-JSON IDOR into a clean, demoable view?"

### [253] Podcast episode metadata IDOR (publicly visible 'random' id) $250 — evanricafort [DUP reinforcement]
- `PUT /api/podcastepisode/<episodeId>/metadata` — swap episodeId → edit anyone's episode title/description. The id is alphanumeric "random" but is shown publicly to everyone, so it's trivially sourced. Reinforces: "random ≠ unguessable if it's displayed publicly."

### [263] $5,000 steal private YouTube video frames via Google Ads "Moments" (cross-product pivot) — xdavidhu [NEW ★ cross-product pivot]
- Where: main YouTube blocked private-video access everywhere; pivoted to **Google Ads** (a different product that touches YouTube internally).
- Approach/how-found: in Ads, the video "Moments" feature `POST /aw_video/_/rpc/VideoMomentService/GetThumbnails` with `__ar={"1":videoId,"2":timeMs}` returns a base64 thumbnail. Swapping in a victim's PRIVATE video id returned a frame → loop `timeMs` by 33 (24fps) → reconstruct the private video as a GIF.
- Test: when the main product enforces per-object privacy, pivot to a SIBLING product (Ads/Studio/Cloud/partner/admin tool) that interacts with the same resource — it often lacks the main product's checks; thumbnail/preview/frame endpoints leak the object piecemeal.
- Q: "Which OTHER product or internal service touches this resource and might skip the main product's privacy check? Can a thumbnail/preview/frame/transcode endpoint there leak the private object frame-by-frame?"

### [264] $30,000 create post on ANY Facebook page via Creative Hub share/notify (newer sub-feature skips the check) — darabi [NEW: secondary action skips the check]
- Where: Creative Hub preview creates an "invisible" (unlisted) post on a selected page; invisible posts have a link+id but admins can't see/delete them.
- Approach/how-found: the main preview checked the advertiser role before generating, but the **newer Share feature** skipped the permission check — change `page_id` in the GraphQL mockup, then request the shareable link → post created on any page. After Facebook fixed it, the **`notify_mobile/<PREVIEW_KEY>` ("send to mobile")** action regenerated the preview without the check = fix bypass.
- Test: enumerate every action that triggers the same side effect (preview/share/notify/duplicate); newer/secondary ones often skip the permission check the primary one enforces — and survive the first fix.
- Q: "Does a secondary action (share/notify/duplicate/preview) trigger the same side effect WITHOUT the permission check the primary action enforces? After a fix, does another such action still skip it?"

### [265] ysamm.com post — RECOVER NEEDED (got the blog post-listing index, not the article).
