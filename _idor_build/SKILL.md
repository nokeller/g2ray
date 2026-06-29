---
name: bb-access-control-idor-bola
description: >-
  Find and prove broken access control on web/app/API targets — IDOR, BOLA (OWASP API #1),
  BFLA (API #5), BOPLA / mass assignment (API #3), horizontal & vertical privilege escalation,
  multi-tenant / cross-org isolation failures, and authorization bypass where a middleware/gateway
  checks but the final resolver does not. Covers object-id enumeration (sequential, UUID/GUID,
  hashids, base64/JSON-wrapped, gid:// global ids, ObjectId/MongoID, template-derived,
  client-side-predictable), ID sourcing for "unguessable" ids (harvest + reconstruct + keyspace-shrink
  + FDNS tenant enumeration + search-index + APK decompile), parser/format smuggling (E-notation,
  decimal, HPP, array/JSON wrap, blank/null/omit, opaque-decorative-id downgrade), object-TYPE
  confusion, multi-type/provider/asset-type inconsistency, parameter-elimination (drop the scoping
  param), id-in-body/header/cookie/JWT/WebSocket/GraphQL-variable, second-order IDOR, aggregate/derived
  field leaks, secondary-endpoint & alternate-render leaks of "hidden/private" data, step-up-auth sibling
  bypass, encryption/signing-oracle as access-key, fix-bypass (token not bound to object, "status code
  lies"), actor/subject-field IDOR, high-impact chains (ATO via recovery-email/reset/OAuth-merge,
  leaked-token→3rd-party takeover, stored-XSS→session, IDOR→SSRF→RCE, IDOR→DoS, payout/gift-card/money),
  a 200+ entry creativity question bank, and blast-radius impact framing. Use for bug bounty / authorized
  pentest hunting and for auditing your own API authorization.
---
# Bug Bounty — Access Control (IDOR / BOLA / BFLA / BOPLA) — The #1 Field Skill

> Authorized testing only. Confirm the asset/tenant is in scope before active testing. Prove access
> with objects YOU own across two test accounts — never read or scrape real users' PII; stop at the
> minimum benign marker (an id, a timestamp, a count, a seeded canary). This skill is for finding,
> proving, and fixing authorization bugs — not for harming real users.

The one test behind every bug here: **can actor A touch actor B's object or function?** Everything
else is being systematic about *every* object, *every* function, *every* property, *every* role —
and creative about *where the id hides*, *how to source a valid victim id*, and *which parser/flow/
endpoint actually enforces the check*.

This document has two layers:
1. **The engine** — the conceptual model + methodology. Read top-to-bottom once.
2. **The field playbook** — concrete patterns distilled from **deep-reading ~630 real disclosed
   IDOR/BOLA writeups** (165 Medium reports + 465 pentester.land writeups, one lesson per article).
   Use it as a creativity engine: for each surface, ask the paired question.

---

## Why it's #1
- Highest-volume + highest-paid bug class. Top API hunters report **~60% of findings are
  authorization** (IDOR/BOLA/BFLA). OWASP API Top 10: **BOLA = #1, BOPLA = #3, BFLA = #5**.
- Scanners can't model "who *should* be allowed to do what," so authz bugs survive in mature apps
  and ship constantly on new endpoints, internal APIs, GraphQL, mobile/WebSocket, and old API versions.
- The API is the truth; the UI is decoration. The UI hides the button — the API still answers.
- Developer mindset: *"If I built this, where would I have skipped the per-object check?"* — then try
  exactly that. **And: once you find ONE access-control bug, the team usually lacks a centralized
  authz layer → the same class repeats across features. Sweep the whole app** (one report yielded
  12 IDORs from a single unvalidated `userid`; another 57 in one codebase; another 30 BOLAs in one
  subdomain).

---

## Identity matrix setup (2 accounts / 2 tenants / 2 objects)
Do this once per target. **Two accounts are mandatory; two tenants are mandatory for SaaS.**

Provision at least:
- **A-owner** (Tenant A) = attacker · **A-member/viewer** (Tenant A, low role) · **B-owner**
  (Tenant B = victim) · **Anonymous** (no token / expired / revoked token).
- If roles exist, get one of *each*: admin, member, viewer, billing, support, API-only, **plus every
  mid-tier role** (a check that blocks "viewer" often passes "support"/"developer"/"editor" — test
  EVERY role, not just the lowest).
- For each object type (`user, org, file, invoice, message, key, doc, order, project, webhook,
  payout, invite, role, media, comment, ticket, campaign, subscription`), capture its id under
  **each** identity.
- For invite/sharing flows, also capture: pending / accepted / expired / revoked invite tokens,
  removed users, deleted / archived / restored objects, and **contributor/collaborator** relationships.

Keep one Burp/Caido session per identity. **Build the habit: capture B's request, replay with A's
session, diff the response.** Always capture A's own response as the baseline so you judge B's by
delta (status, length, body, timing, error class). A purpose-built rig — **pwnFox containers (one
account per tab) + Burp Autorize/Authorize** — lets you sweep BAC/IDOR across roles fast; always
re-confirm an Autorize "Bypassed" manually in Repeater (it can be intended behavior).

```
identity      session/token        owned object ids
A-owner       Bearer $TA           doc=1001 org=51
A-viewer      Bearer $TAv          doc=1001 (read-only)
B-owner       Bearer $TB           doc=2002 org=52
anon          —                    —
```

---

## BOLA / IDOR (object-level) — find, source, enumerate

### 1) Map every object reference
Walk every request; flag anything carrying an id: path (`/users/1002`), query (`?account=51`),
body (`{"orgId":51}`), header (`X-Account-Id`, `X-Org-Id`, `X-User-ID`), cookie (incl. an id segment
*inside* a composite/serialized session cookie value), JWT claim, **GraphQL variable**, **WebSocket
frame**, multipart field, and **arrays** (`ids[]`, `operator_ids[]`, `page_ids[]`). Hidden ids in JS
bundles, source maps, `doc_id` persisted GraphQL queries, batchexecute `f.req`, and prior responses
count too. **Diff the logged-in vs logged-out (and A vs B) version of the same request** — the extra
identity field that appears is the impersonation/IDOR knob.

### 2) Swap & observe
Replace A's id with B's. `200` + B's data, or the action applied = IDOR. **Test read / write / delete
independently** — a read may be locked while `PUT/PATCH/DELETE` is open (and vice-versa). **Test every
ACTION a feature exposes** (create/read/update/delete/complete/upload/download/export/share/approve/
assign/cancel/restore) — one verb is often protected while a sibling isn't. Features that need ≥2
objects (swap/merge/compare/set-default) only appear after you create them — create them, then test.

### 3) ID-shape attacks (the hard part is finding valid victim ids, not the swap)
- **Sequential / numeric:** `123→124`, `id=0`, `id=-1`, negative, very large, `id=*`, **missing id**
  (defaults to all/admin?), **id-less list/collection-root endpoint dumps everything** (`/api/Users`,
  drop the filter → all rows).
- **UUID / GUID — NOT "safe":** unpredictability stops *enumeration*, it adds **no ownership check**.
  Always run the "valid pair, wrong session" test (victim id + YOUR cookie). Source UUIDs (see §ID
  sourcing). UUIDv1 is time/MAC-based and partially predictable; **client-side-generated UUIDs**
  (from `Math.random`, a template, or a referral-param converter) may be forgeable/derivable.
- **MongoDB ObjectId:** 4-byte timestamp + 5-byte machine/process + 3-byte counter → not random;
  brute the counter/time window to reach "random" ids.
- **Template/clone-derived ids aren't random:** import the same prebuilt object/template in two
  accounts → identical child ids; clone/duplicate a resource → predictable sibling ids (Burp Comparer).
- **Hashids / slugs:** often reversible without the salt; else harvest from responses.
- **Encoding / format wrappers** (a check may run on only one representation): `123` → `"123"` →
  `[123]` → `{"id":123}`; base64 (`MTIz`), **base64-JSON** (`{"type":"userID","id":"182905"}` — decode,
  swap inner `id`, re-encode), hex (`0x7b`), URL-encoded, double-encoded, hashed-vs-raw.
- **Opaque id is decorative — downgrade to cleartext:** if a request carries BOTH an encrypted/opaque
  ref and (anywhere) the cleartext id, the server often still accepts the cleartext; also a record may
  have BOTH a 32-char id and a parallel **sequential numeric id** — use the guessable one.
- **Parser/coercion smuggling (dual-parser disagreement)** — when the exact id is blocked, try a value
  the *validator* reads as yours but the *data layer* coerces to a different id:
  - **E-notation / decimal:** `123` blocked → `123.0`/`123e0` returns YOUR data (proves coercion) →
    `123e1` (=1230) returns user **1230**; `123.1e1`=1231; `123e-1`=12.3→user 12.
  - Leading zeros / sign / whitespace: `0123`, `+123`, `%20123`.
- **Type juggling & object-TYPE confusion:** numeric vs string id, array vs scalar; AND — **feed an id
  of the WRONG object type**: an endpoint that expects a `page_id`/`app_id`/`asset_id` but never checks
  the id's *type* will happily act on a `user_id` (e.g. mint a token, return the object) — a token-/
  resource-minting endpoint that takes a `page_id` can issue a token for any *user* id.
- **Email / username / phone / company-slug / tenant-name / wallet-address** as the identifier.
- **gid:// / Relay global-id forgery.** Relay `id`/`node(id:)` values are usually `base64("Type:dbid")`
  — `VXNlcjo0Mg==` = `User:42`. Decode your own, swap the inner db id, re-encode, fetch via
  `node(id:){... on User{email}}`. Often reaches objects the REST API guards. Try inner shapes
  `Type:uuid`, `Type:tenant:id`, `gid://app/Type/<int>` (Rails/GitLab).

### 4) ID location & method tricks (authz may check only one place)
```
# Move the id between locations (auth may check one, data layer reads another):
path  vs  ?id=  vs  body {"id":}  vs  X-Account-Id header  vs  JWT claim  vs  cookie segment  vs  WS frame  vs  GraphQL variable  vs  multipart field
# URL-id check ≠ request-param-id check: app authorizes the id in the PATH but reads the id from the BODY/param.
# Parameter pollution (HPP) — auth reads one copy, the data layer reads the other:
?id=mine&id=victim     id=mine(query)+id=victim(body)     id[]=mine&id[]=victim     id=victim,mine
#   → name the polluted param EXACTLY as the response JSON key (devs are consistent); after a fix,
#     retry the pollution in a DIFFERENT location (GET↔POST↔body↔header) — precedence differs per stack.
# Parameter ELIMINATION — delete the scoping/context param entirely:
#   drop client_id / org / tenant / role / "client" → server may fall back to an UNSCOPED/ADMIN context
#   (Faveo: remove `client` → admin + all orgs). A deprecated admin panel often ignores its scope param
#   and returns GLOBAL data when you supply any valid value.
# Method confusion — GET blocked, write verbs open; or reach the object via a sibling endpoint:
GET /doc/B →403 ; try POST/PUT/PATCH/DELETE/HEAD/OPTIONS  or  /doc/B/export /print /embed /oembed /download /replies
#   (PUT /api-keys/{victim} → 404, but GET /api-keys/{victim} → dumps it: authz is often per-method.)
X-HTTP-Method-Override: GET|DELETE ;  switch Content-Type json↔form↔xml ; tamper the preflight OPTIONS
# Path tricks on ownership routes (the `/../` can defeat the authz-checked id segment):
/users/B/../A   /me vs /users/A   trailing /   ;-matrix params   /org/123/../456/   ..;/   %2e%2e   //double-slash
```

### 5) Nested / related & array objects
Parent allowed but child not re-checked — `/orgs/mine/users/{victimUser}`, `/order/{mine}/buyer/{victim}`,
GraphQL `team → members → profileData`, `order → buyer → payment`. **Array of child ids unchecked while
the parent id is checked** — pass `members:[victimId]`, `operator_ids:[foreign,many]`; arrays also enable
**mass** targeting (notifications to millions, bulk delete). **Break the id↔id relationship** — a sibling
endpoint often leaks the related id you need (chain IDOR-1's leak into IDOR-2).

### 6) Manual diff harness (own test objects only)
```bash
for id in $(seq 1000 1010); do
  a=$(curl -sk -H "Authorization: Bearer $TA" "https://HOST/api/docs/$id" -o /dev/null -w '%{http_code}:%{size_download}')
  b=$(curl -sk -H "Authorization: Bearer $TB" "https://HOST/api/docs/$id" -o /dev/null -w '%{http_code}:%{size_download}')
  echo "$id  A=$a  B=$b"
done   # B getting A-sized 200 bodies for A's ids = BOLA
```

---

## ID sourcing — defeating the "how would you guess the id?" objection
Finding/justifying a valid victim id is usually the whole game and the #1 triage objection. Sources:

- **The app hands it to you.** Read your own `/me`, then look for the same object's id rendered to
  OTHER viewers: comments, Q&A `clientId`, presence, "who reacted", shared docs, search results, the
  public profile. A "you can't view this until you're friends" screen often **still leaks the private
  object's id in the response body** — unguessable becomes guessable.
- **List/hub endpoints emit ids in bulk:** follower/following, members, search, autocomplete,
  leaderboard, "people you may know", org directory, group members. Find a **high-degree hub account**
  whose follower/member list dumps thousands of ids at once. Public **leaderboards / username lists**
  feed username-keyed attacks.
- **Object responses leak sibling/child ids** — chain them: `conversations`→`conversation_id`→
  `parts`→`participants`→`user_id`→`/users/{id}`. Devs redact "sensitive" fields but forget the ids.
- **A "protected" action leaks the owner's id in its response** even when the action itself is denied —
  harvest that "unguessable" id (AccountUid/GUID) to defeat an "IDOR-with-unguessable-ids is out of
  scope" rule, then use it on the real IDOR.
- **Registration / company-create / invite / signup-error responses** return your fresh (sequential)
  id and sometimes other internal ids; signup-collision / "email exists" errors are PII/UUID oracles.
- **History & code:** `gau`/`waybackurls` + id regex (and grep for `token=`/`jwt=`/`access_token=` —
  apps leak bearer tokens into archived URLs/logs; JWTs self-describe the `user_id`). **Recon the CNAME
  / old hostname** in Wayback, not just the live host. JS bundles, source maps, Google cache,
  `application.wadl`/Swagger/GraphQL schema, **mobile APK/`.dll` decompile** (jadx/apktool) for hidden/
  internal endpoints, hardcoded keys, and predictable **crash/log file paths** (often unauth, leaking
  creds). Crash reports / debug endpoints leak ids and secrets.
- **Invite / share / reset links** carry an identity (often base64 email or a token) — decode & swap.
- **Offline/physical artifacts:** QR codes, barcodes, NFC, printed account/reservation numbers.
- **Reconstruct structured ids:** decompose a "filename"/ref into parts — `id + username + timestamp`,
  airline AWB = `prefix + serial + checkdigit (serial % 7)`; **fbid = (number between underscores in
  the CDN URL) − constant offset**; derive an unknown id by a constant arithmetic offset from a known
  one. Script a candidate generator and keep the 200s.
- **Tenant enumeration via DNS:** for tenant-keyed endpoints (`/shops/<name>/...`), don't guess —
  enumerate the WHOLE tenant population via **Forward-DNS reverse-CNAME** (or reverse-IP) of the shared
  host all tenants point to (`shops.myshopify.com`), then mass-test.
- **Search-engine indexing** can defeat the UUID objection (the "unguessable" id is publicly indexed).
- **Shrink an "unguessable" keyspace:** if the id encodes a timestamp/sequence, create two objects at
  the *same instant* (single-packet race) so they share the time component, then diff. **Time-based
  paths** = tiny keyspace; fuzz the time window to reach "private" files.
- **Existence / behavioral oracles** (a sibling endpoint or a response delta that confirms "user X has
  feature Y / exists") let you enumerate valid ids before hitting the sensitive endpoint.

---

## Beyond the simple swap — creative vectors
- **Second-order IDOR.** The id you submit in step 1 is stored and consumed by a LATER endpoint that
  doesn't re-check ownership: a `…success.aspx` page that reads the last id from session; an
  **audit/activity log** that renders content the primary endpoint denied; a notification/export/
  receipt/cache. *Request the guarded object (hold the redirect), submit the victim id, then trigger
  the downstream consumer.*
- **A SECONDARY endpoint leaks what the primary hides.** A field made "private" on the canonical view
  is still returned by another endpoint that references the same object — featured/embed/preview/
  export/analytics/copyright-removal/"add-a-video" lookups frequently return the full object server-side
  and **ignore the per-field privacy flag** (YouTube hidden dislikes via the studio layout / removal /
  player `averageRating`).
- **Aggregate/derived value leaks the hidden field.** A hidden count/value can be reconstructed from an
  exposed average/ratio/percentage/total (knowing likes + `averageRating` → solve for hidden dislikes).
- **Encryption / signing as the access key (signing oracle).** An endpoint that will encrypt/encode/
  sign ARBITRARY input for you (`/encrypt?text=`, "generate share link", set-username-then-read-the-
  opaque-token) turns a guessable plaintext id into the access token; reuse that token cross-endpoint.
  Many "encrypted" tokens are merely **base64/Zlib/PHP-serialized** with the `profile_id`/`user_id`
  inside (and Zlib ignores bytes after the Adler-32 checksum — length-mismatched forgeries still parse).
- **Derive a secret from a PUBLIC identifier.** When a "random" secret/token gates access, hunt the
  endpoint that GENERATES/returns it from a weaker input (username/email/id) with no authz — derive the
  victim's secret instead of brute-forcing it.
- **WebSocket-frame IDOR.** WS messages are requests too and are frequently unauthorized — mutate
  ids/UUIDs/emails inside frames (signup/profile/presence frames are gold). Most hunters never open the
  WS tab.
- **GraphQL response→variable promotion.** If the id appears only in the RESPONSE (nothing in the
  request to swap), author your OWN query adding it as an argument: `query($id:ID!){ user(id:$id){…} }`.
  Resolvers are often shared with admin tooling and accept args the UI never sends. Add sensitive fields
  (`email`,`phone`,`securityAnswer`,`token`) to existing queries; use aliases/batching to probe many
  ids in one request; `node(id:)`/`me()→node(id:)` for guarded objects.
- **Resource-PATH-in-body.** The object ref is often a storage path / blob key / upload token / file
  fbid in the body, not a numeric id — swap paths between two accounts; **attach a FOREIGN file/attachment
  id to YOUR object** (send-message `image_ids[]`, "add to unit/collection") to exfiltrate or — by then
  deleting your container — destroy the victim's object. AI "describe/summarize/OCR your file" features
  make a powerful read oracle for the victim's content.
- **Mass assignment (BOPLA write).** Add privileged fields to create/update bodies — try JSON + form +
  query (HPP merge can bypass field filters). Pull real field names from `GET` responses/Swagger/JS.
  High-yield: `role, roles, isAdmin, isOwner, verified, permissions, tenantId, accountId, ownerId,
  price, amount, discount, status, paid, planId, authorId, visibility, approved, UserRoleID, page_ids`.
  **Set `roleId=1`/highest at create-user/registration** to mint a super-user above admin (revisit
  signup *after* login for the privileged fields).
- **Actor / subject-field IDOR (write content onto a foreign account).** The "who is this about / from /
  assigned-to" field (`hacker_username`, `author_id`, `assignee`, `owner`, `created_by`) is itself an
  IDOR knob — set it to a victim to post a review on their profile, email them, assign them a task, or
  impersonate them. Decouples content from the session identity.
- **Multi-type / provider / asset-type inconsistency.** One endpoint that handles several object types,
  payment providers, or asset types usually enforces the check for the common one and **forgets the
  others** — test EACH `asset_type`/`provider`/`type` variant (Pages checked, apps not; PayPal checked,
  2C2P not).
- **Import-to-container distortion / takeover.** "Add to unit / collection / featured / list / program"
  features that reference a foreign object by id can pull it into your container — distorting or locking
  the original (pair with an invite to make damage persistent), or **enrolling a foreign/under-privileged
  object into a restricted program**.
- **Limited share leaks a permanent internal id.** A view-only/"preview" share exposes an internal id
  in the HTML/JS that a separate raw fetch/download endpoint honors with **no ownership check and no
  expiry** — grab it, hit the raw endpoint, then enumerate sibling ids (mind the per-tenant prefix/step).
- **Step-up-auth sibling bypass.** A sensitive action gated by password/2FA/OTP re-entry has an ALTERNATE
  endpoint that produces the same artifact (export/album/report/legacy path) **without** the step-up —
  reuse the same job/file id there.
- **Multi-field / correlated id.** If a single-id swap fails, supply the full identity tuple (id + email,
  id + username, id + tenantId) — or **tamper ALL ids together**, since corrupting one can disable its
  check.
- **Account-linking / manufactured association.** When direct access is blocked, CREATE a relationship
  first (invite to team / add as member / share resource / connect social account / become contributor)
  — even unaccepted — then retry; the pending relationship is often treated as authorization. Conversely,
  **move a FOREIGN user/object into YOUR tenant** to gain control over it.
- **Null/blank/missing credential bypass.** Send `access_token=null`, blank `hash=`, removed signature,
  omitted id, junk CSRF token (`X-Csrf-Token: ABCD` — presence checked, not validity), **stripped cookie
  header**. Persisted-query (`doc_id`) and `/ads/graphql/`-style endpoints often skip authz with an
  empty token.
- **Cross-tenant via header / Host.** Tenant id frequently rides in `X-Account-Id`/`X-Org-Id`/
  `X-Tenant-ID`/Host with no membership check — swap it (works even for orgs you don't belong to).

---

## BFLA (function-level)
The UI hides admin/staff actions; the API often has no role check. Take every privileged action and call
it as a **low-priv** user (or anon).
- Replay an admin-only request (captured as admin) as a normal user — many apps gate only the UI. When
  a low-priv panel **shares cookies/host/backend** with a high-priv panel, capture the ENTIRE high-priv
  API surface and replay every call in the low-priv session (a subset will be unguarded).
- Find admin/internal endpoints in **JS / source maps / API docs / Swagger / batchexecute** (`isAdmin`,
  `/admin/api`, role constants, the SPA route table) and call them directly. **Unauthenticated admin
  panels** keyed on `?page=`/an id show up via blind-XSS-leaked source or recon.
- Direct-browse: `/admin`, `/api/admin/*`, `/internal/*`, `/api/v1/admin/*`, `/settings/org/<other_org>`.
  Check **`internal_api` vs public api**, ALL subdomains, AND every api version.
- **Derive sibling functions** from any one you see — don't only test the visible verb:
```
add remove update delete list export import bulk approve reject archive restore
invite revoke assign unassign impersonate enable disable complete download upload cancel
# /api/members/add exists ⇒ test /remove /update /invite /bulk /api/admin/members /api/v1/members
```
- **Privesc via role/permission fields:** replay your own update with a higher `UserRoleID`/`roleId`/
  `isAdmin`; learn valid role values from API docs. Role/group/org ids are often **serialized** — guess
  a higher tier. Mass-assign a role BEYOND your grant; activate-endpoints + token reuse compound it.

---

## BOPLA — excessive data exposure (read)
API returns more than the UI renders (other users' emails, internal flags, hashes, tokens, IP, phone).
Read the **raw JSON**, not the page. Force more fields: `?expand=*`, `?fields=*`, `?include=all`,
`?pageSize=1000`, GraphQL field selection, and **add known field names** to an under-selecting query.
When a rendered page filters/hides data, hit the **raw underlying API** (`/work-order/<id>/replies`,
`/get_creator_videos`) — it frequently returns everything the HTML stripped. The browser hides it but
the intercepted **response still contains it** — render the intercepted response to confirm.

---

## Horizontal vs vertical escalation & multi-tenant isolation
- **Horizontal** = same privilege, other user's/tenant's data (the IDOR/BOLA core). **Vertical** = lower
  role → higher action (BFLA, or mass-assigning `role/is_admin/plan/owner_id`).
- **Ownership transfer / state:** can you change `owner`, `assignee`, `created_by` to take an object over?
  Pre-account-creation object claiming (claim resource, then register that email)?
- **Multi-tenant:** replace org/tenant ids with B-org values while authed as A-org. Devs check the tenant
  id in one place and *use* it from another:
```
tenant id lives in: subdomain · path · ?query · body · header(X-Tenant-ID/Host) · cookie/localStorage · JWT claim · GraphQL var
mismatch tests: path=A + body=B | header=B + query=A | JWT tenant=A + object tenant=B | stale tenant cookie after switching orgs
```
- Invite/role flows: can A add themselves to B's org (self-invite as owner via a role param + foreign
  `project_id`/`tenant_id`), or escalate role via the invite-accept/role-update endpoint? Cross-tenant via
  shared resources: file ids, share links, webhooks, exports, reports.
```
Escalation ladder:
read one other record → enumerate all records → write/modify others' records →
call admin functions → org/tenant takeover → full data compromise
```

---

## Middleware != authorization (verify the FINAL resolver)
Authentication ≠ authorization. A gateway/middleware that authenticates the request, or authorizes a
*root* route, does not protect each object the handler ultimately returns. **Verify the check in the final
data-returning resolver/handler**, per object, per request.
- **Gateway vs app path-normalization skew:** gateway authorizes the *pre-normalized* path, app serves the
  *normalized* one — `/org/123/../456/`, `..;/`, `%2e%2e`, double-slash, `X-Original-URL`/`X-Rewrite-URL`.
- **Frontend-only enforcement:** authz only on the public/frontend API; hit the **backend/internal API
  directly** (error-leaked paths, source maps, `application.wadl`) and per-object checks are gone.
- **GraphQL resolver-level BOLA:** route auth ≠ object auth; nested edges leak if only the root resolver
  checks. Recover schema without introspection via suggestion errors / persisted queries / JS (InQL).
- **API versioning gaps:** `/api/v1/` often lacks a check present in `/api/v2/`; `/internal`, `/legacy`,
  singular vs plural, mobile API hosts, out-of-scope sibling domains.
- **JWT/token trust bugs:** `alg:none`/unverified signature → forge `uid` ("shortest token ever");
  token validated for **freshness/timestamp window** but not bound to the user (keep your token, swap the
  id, align the timestamp); a token-minting endpoint that accepts an arbitrary/`uid`/wrong-type id.
- **403/401 mini-bypass:**
```
path:   /admin → /admin/  /admin/.  //admin  /%2e/admin  /admin..;/  /admin%20  /Admin  /./admin
header: X-Original-URL: /admin  X-Rewrite-URL: /admin  X-Forwarded-For: 127.0.0.1  X-Custom-IP-Authorization: 127.0.0.1
method: GET→POST/HEAD/OPTIONS ; X-HTTP-Method-Override: GET ; Content-Type json↔form↔xml
```

---

## "The status/error code lies" — act despite the rejection
A `403`/`422`/`400`/empty body does NOT mean the action failed. **Always re-fetch / verify the side
effect elsewhere:**
- An OAuth-connect / account-link / add-admin / add-editor returns an error but the link/role **silently
  persisted** → re-check the dashboard → often a no-interaction ATO or privesc.
- "You must belong to the host / not allowed" yet the object was **added/changed anyway**.
- Empty response ≠ no impact: the foreign user got linked to your account / your payload got stored on
  the victim. Verify in a second account or the UI.
- **Parameter elimination after an error:** when the obvious id-swap errors, delete each param in turn
  until only `email`/the weak selector remains → the server falls back to a weaker check.
- A denied action frequently **leaks the object in the error body** (422 → full PII; "invalid template →
  here are all valid templates"). Weaponize verbose validation errors as enumerators.

---

## Fix-bypass / retest playbook (always revisit a "patched" IDOR)
Patches are usually narrow. After any fix, try:
- **Token validated for existence, not BOUND to the object:** use YOUR OWN valid access code/token with
  the VICTIM's id (the classic "valid code, wrong reservation"); the "reset token" may even be a constant
  reused for all users, or analyzable across samples to FORGE one (spot the decoy param).
- **A different action/endpoint leaks the new secret:** switch `act=`/operation/`doc_id`; probe each with
  blank/null/missing values — one code path often returns the per-user hash/token.
- **Move the param:** GET↔POST↔body↔header; HPP in a new location; alternate id format (E-notation,
  decimal, array, encoded). **Repro pitfall:** some fixes require a `version`/`app_version` param to match
  — keep it identical when proving the bypass.
- **Sibling/old surface:** another endpoint, old API version, mobile/WebSocket, frontend-fixed-but-backend-not.
- **The patch's own response reveals the removed param** (or which field it now requires) — re-add it.
- **Incomplete patch:** re-test a week later; many fixes regress or miss a second endpoint with the same data.

---

## High-impact chains (turn a read into Critical)
- **IDOR → ATO via recovery/reset:** add YOUR email/phone as a victim's *secondary/recovery* contact (IDOR)
  then trigger their reset → link comes to you. Or the reset-link carries a guessable email/id; or change
  the victim's email then reset; or `up_uid`/`uid`-swap phone-update → reset. OTP not coupled to the email,
  or returned in the response / resend-OTP response, or a known/zero value → bypass.
- **IDOR → leaked secret → ATO / 3rd-party takeover:** an endpoint returns the victim's reset token /
  security answer / per-user hash / **OAuth/first-party access token** → log in / reset as them, or take
  over the linked 3rd-party (Drive/Slack/Oculus); a sequential id leaks a chainable OAuth token → pivot to
  another platform.
- **OAuth↔password account MERGE with no email verification** = ATO; account-linking your social identity
  to a victim's account id = silent ATO.
- **IDOR that WRITES into others' accounts → stored XSS → mass session hijack:** write a stored-XSS payload
  (or self-XSS made stored via channel/chat takeover) into a field rendered to OTHER users (filename,
  metadata, group name, email template, chat) keyed by a guessable id → zero-click on victims.
- **IDOR → SSRF → cloud RCE** (e.g. AWS SSM); **IDOR → admin → RCE**; **IDOR → RCE** via upload/import/
  code-exec platforms; **IDOR → DoS** (corrupt a shared/contributor object; WAF-invisible).
- **Money:** redirect another org's payout/withdrawal (PayPal email / bank details); enumerate
  gift-card/reservation ids with a balance oracle (+ redeem race); modify campaigns/orders/discounts/
  subscriptions; client-controlled `price`/`amount`/quantity (or negative) in checkout.
- **Mass PII/breach:** enumerable id space over PII/KYC (passports)/financial/support-tickets = "mass"
  impact (state the range, don't scrape). Helpdesk **ticket/`workOrderId`** ids are a mass-PII+KYC magnet;
  invoice/receipt/order export endpoints leak PII (name, GST, phone) that feeds an OTP/reset ATO.

---

## Oracles & response deltas (incl. Blind IDOR)
You don't need the data to prove access — you need a reliable signal that A reached B's object.
- **Status:** `200` vs `403/404`. `403` (exists, denied) vs `404` (hidden) is itself an enumeration oracle.
- **Body size / content:** B getting an A-sized body for A's id. Diff against your own baseline.
- **Timing:** valid-but-denied id is often slower (hits the DB) than a non-existent one.
- **Error class / shape:** "you don't own this" vs "not found" vs 500; **status-code/response-shape oracle**
  (empty-CSV = no orders vs `500` = has orders). Verbose validation errors enumerate params/enums/ids.
- **Behavioral-difference oracle** on UID-in-URL endpoints → deanonymization / membership confirmation.
- **Blind IDOR:** the response is an identical generic `200` for success AND failure — **don't dismiss it;
  USE the feature afterward** (or check a second account) to detect the silent side effect (LinkedIn
  blind-unlink). "No body but it happened" is the write oracle.
- **Side effects:** action reflected in B's account, an email/webhook fired, an audit-log entry, a push/SMS
  delivered, your bot added to the victim's room.

---

## Creativity question bank — ask these per surface
The core prompt: **"If I am user A, can I read/modify/delete user B's ___ by changing ___?"** Expand it:

**Per object (user, order, invoice, file, message, project, key, payout, comment, media, webhook, ticket,
campaign, subscription):**
- Can I READ B's object by swapping its id (path/query/body/header/cookie/JWT/WS/GraphQL var/array)?
- Can I UPDATE / DELETE / EXPORT / SHARE / DOWNLOAD / ASSIGN / CANCEL it, even if READ is blocked?
- Is there a parallel guessable id (sequential / cleartext / ObjectId / template-derived) alongside the
  "random" one? Is the opaque ref decorative — does the server also accept the cleartext id?
- What happens with id = `0 / -1 / huge / * / omitted / id.0 / id e1 / [id] / duplicated (HPP)`? What if I
  DROP the scoping param (client/org/tenant/role) entirely?
- Where does the app show me B's id for free (lists, followers, comments, search, "who viewed", a
  protected action's error/response, a view-only share, the CDN URL, JS, Wayback, the APK)?
- Does a child/nested/array object skip the parent's check (`/order/mine/buyer/{victim}`, `members:[B]`)?
- Is this endpoint multi-type/provider — does it check one type and forget another? Will it accept an id of
  the WRONG type (user_id where a page_id is expected)?

**Per feature/flow:**
- Does any LATER step (success page, audit log, notification, export, receipt) re-use my submitted id
  without re-checking ownership? (second-order)
- Does a DIFFERENT endpoint (embed/featured/preview/export/analytics/raw-replies/player) return the field
  this view hides? Can I compute a hidden count from an exposed average/ratio/total?
- Is a sensitive action's step-up auth (password/2FA/OTP) enforced on EVERY path, or does a sibling
  export/album/legacy endpoint skip it?
- Can I add MY email/phone/role to B's account, or set B's `owner/role/payout-email/assignee`? Is the
  "who is this about/from" field attacker-controlled?
- If a fix added a token/code — is it BOUND to this object, or just "valid/fresh"? Does another action leak
  it? Is the reset token a constant / forgeable / not retargeted when the email changes?
- Does the WebSocket / GraphQL / mobile / internal / old-version path enforce the check the main web API does?
- Does the app encrypt/sign/generate MY secret for me (signing oracle), and is that ciphertext the only
  check? Is the "random" secret derivable from a public username/email via a generator endpoint?
- Can I import a foreign object into my container (collection/unit/featured/program) to read, distort, lock,
  or destroy it? Can I manufacture a relationship (invite/share/link/contributor) to gain access?
- Does an error/403/422 actually fail, or did the side effect persist (re-check the dashboard)?

**Per role / tenant:**
- For each CRUD action: which roles are blocked, and does a DIFFERENT non-admin role slip through?
- Can a viewer/anon call admin/staff functions (BFLA)? Can I set `isAdmin/role/plan/roleId=1` via mass
  assignment (at create AND at update, JSON+form+query)?
- Does the low-priv panel share a session/backend with the admin panel — can I replay the whole admin API?
- Swap `X-Account-Id`/Host/tenant id — does it act on an org I'm not a member of? Can I self-invite as
  owner, or move a foreign object into my tenant?

**Sourcing / proof:**
- If the id is "unguessable": which list/hub/response/error/share/wayback/JS/APK/QR/CDN-arithmetic/
  FDNS-reverse-CNAME/search-index source emits it? Can I reconstruct it from parts or shrink the keyspace
  with a race / time-window fuzz?
- Can I prove the id is APP-SUPPLIED (not guessed) to beat triage? What's the cheapest benign oracle?

---

## Field-tested mini-patterns (one-liners from real reports)
- `/api/users/me` → swap `me` for your numeric id (confirm), then decrement to a neighbor → enumerate.
- Open any uploaded asset (image/avatar/attachment) directly → its url has a guessable id → +/- across tenants;
  derive the real id from the CDN filename by a constant offset.
- "Add secondary/recovery email" IDOR is the single highest-value target → reset → ATO.
- Company/group/role/org ids are frequently **serialized** — enumerate orgs and grab a higher-tier role id.
- Use **Autorize/Caido Authz + pwnFox containers** to auto-replay every request with a low-priv & no token.
- Burp **Sitemap built from responses** reveals endpoints the UI never calls for you (BFLA candidates);
  **Param Miner** finds hidden/bypass params; **Comparer** spots template-derived id patterns.
- Decode every opaque token: base64/Zlib/PHP-serialized may wrap `{type,userID,id}`/`profile_id` → edit, re-encode.
- New features ship with broken authz first — subscribe to program-update emails and test the latest feature first.
- Out-of-scope or self-hostable (OSS) products: stand one up / read the source, then hunt object checks.
- Decompile the mobile APK/`.dll` → hidden/internal endpoints, hardcoded keys, predictable crash/log paths (unauth).
- After ANY find, sweep EVERY feature for the same id param (centralized-authz failure ⇒ class repeats).

---

## Tooling
- **Burp Autorize / AuthMatrix / Auth Analyzer / Param Miner / Comparer**, **Caido "Authz"**, **pwnFox**.
- **ffuf / nuclei** access-control + 403-bypass templates; Burp `403bypasser`.
- GraphQL: **InQL, GraphQL Raider, batchql, GraphCrawler, graphw00f** (readable queries, schema recovery, batching).
- **gau / waybackurls / katana / JS parsers / source-map extractors**, **FDNS / reverse-CNAME** for id, endpoint & tenant sourcing.
- **jadx / apktool / dnSpy** to decompile mobile apps for hidden endpoints, keys, and log paths.
- **Single-packet attack** (Burp Repeater "send group in parallel") for race-to-align-id / keyspace shrink / redeem race.
- WebSocket: Burp's WS history + repeater; don't skip the WS tab.
- Sibling-endpoint generation from observed routes (`/x/add ⇒ remove/update/list/invite/bulk/v2`).

---

## Validation gate (kill weak/dup findings before reporting)
- [ ] Reproduced with **two owned identities**, sessions captured side-by-side.
- [ ] It's authorization, not just authentication (request *was* authenticated as A, yet reached B).
- [ ] Mass-assignment / write actually **persisted** and affects privilege/state (not a cosmetic echo);
      verified the side effect even if the response was an error/empty.
- [ ] Valid victim-id sourcing is demonstrated or the id is provably **app-supplied / enumerable** (beats triage).
- [ ] Real attacker impact stated; chain only if the chain creates impact. Avoid: existence-only leaks,
      "maybe if victim does X," own-account no-op mass assignment.
- [ ] No third-party PII exfiltrated; proof uses owned/canary objects or minimal markers.

---

## Master checklist
- [ ] Two accounts + two tenants + EVERY role set up; sessions captured; baselines recorded.
- [ ] Every object id swapped (seq, UUID, ObjectId, hashid, template-derived, email/slug/name/wallet, encoded,
      base64-JSON, decoded gid, cleartext-downgrade, E-notation/decimal, array/JSON wrap) for **read / write /
      delete / export** independently, across EVERY feature that carries it.
- [ ] Victim ids sourced (lists/hubs, /me, responses' child ids, protected-action error leaks, view-only shares,
      CDN-arithmetic, wayback/JS/source maps/APK, invite/reset links, QR/physical, reconstructed, FDNS reverse-CNAME,
      search-index, race/time-window shrink).
- [ ] ID location moved (path/query/body/header/cookie/JWT/WebSocket/GraphQL var/multipart) + HPP + parameter
      ELIMINATION + URL-id-vs-param-id mismatch (and after-fix GET↔POST).
- [ ] All verbs + sibling/export/embed/preview/raw-replies endpoints + old/internal API versions + WebSocket + mobile tried.
- [ ] Object-TYPE confusion + multi-type/provider/asset-type variants tested.
- [ ] Every admin/staff function called as low-priv user and anon (BFLA); derived siblings; serialized role/org ids;
      shared admin/low-priv backend replayed wholesale.
- [ ] Mass-assignment fields tried on all create/update endpoints (JSON+form+query), incl. registration & roleId=1.
- [ ] Excessive-data-exposure checked in raw JSON / GraphQL field selection / `?expand=*` / raw underlying API.
- [ ] Secondary-endpoint & aggregate leaks of "hidden/private" fields checked; step-up-auth sibling bypass checked.
- [ ] Tenant id mismatched across path/header/Host/body/JWT; invite, self-invite, account-linking, move-into-my-tenant,
      and shared-resource flows tested.
- [ ] Second-order paths checked (success page / audit log / notification / export reuse of a submitted id).
- [ ] Encryption/signing-oracle, derive-secret-from-public-id, null/blank/junk-token, stripped-cookie,
      multi-field-correlated, tamper-all-ids, and resource-path-in-body / attach-foreign-file vectors tried.
- [ ] "Status code lies" — re-verified side effects after every 403/422/empty response.
- [ ] Final resolver verified (gateway/frontend bypass, path-normalization skew, GraphQL nested edges, JWT trust).
- [ ] Every found IDOR triggered a full-app sweep for the same class (centralized-authz failure).
- [ ] Patched bugs retested (token-binding, secret-leak via other action, moved param, sibling surface, constant/forgeable token).
- [ ] Impact + blast radius quantified with owned canaries/counts; validation gate passed.
