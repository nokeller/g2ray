---
name: bb-access-control-idor-bola
description: >-
  Find and prove broken access control on web/app/API targets — IDOR, BOLA (OWASP API #1),
  BFLA (API #5), BOPLA / mass assignment (API #3), horizontal & vertical privilege escalation,
  multi-tenant / cross-org isolation failures, and authorization bypass where a middleware/gateway
  checks but the final resolver does not. Covers object-id enumeration (sequential, UUID/GUID,
  hashids, base64/JSON-wrapped, gid:// global ids), ID sourcing for "unguessable" ids (harvest +
  reconstruct + keyspace-shrink), parser/format smuggling (E-notation, decimal, HPP, array/JSON
  wrap, blank/null/omit), id-in-body/header/cookie/JWT/WebSocket/GraphQL-variable, second-order
  IDOR, encryption-as-access-key, fix-bypass (token not bound to object), high-impact chains
  (ATO via recovery-email/reset, OAuth-token theft, stored-XSS→session, IDOR→RCE, payout/money),
  a creativity question bank, and blast-radius impact framing. Use for bug bounty / authorized
  pentest hunting and for auditing your own API authorization.
---
# Bug Bounty — Access Control (IDOR / BOLA / BFLA / BOPLA) — The #1 Field Skill

> Authorized testing only. Confirm the asset/tenant is in scope before active testing. Prove access
> with objects YOU own across two test accounts — never read or scrape real users' PII; stop at the
> minimum benign marker (an id, a timestamp, a count, a seeded canary). This skill is for finding,
> proving, and fixing authorization bugs — not for harming real users.

The one test behind every bug here: **can actor A touch actor B's object or function?** Everything
else is being systematic about *every* object, *every* function, *every* property, *every* role —
and creative about *where the id hides*, *how to source a valid victim id*, and *which parser/flow
actually enforces the check*.

This document has two layers:
1. **The engine** — the conceptual model + methodology (identity matrix, BOLA/BFLA/BOPLA, oracles,
   impact). Read top-to-bottom once.
2. **The field playbook** — concrete, battle-tested patterns distilled from ~640 real disclosed
   IDOR/BOLA writeups: where to look, what to send, the creativity question to ask, and the
   high-impact chains. Use it as a creativity engine: for each surface, ask the paired question.

---

## Why it's #1
- Highest-volume + highest-paid bug class. Top API hunters report **~60% of findings are
  authorization** (IDOR/BOLA/BFLA). OWASP API Top 10: **BOLA = #1, BOPLA = #3, BFLA = #5**.
- Scanners can't model "who *should* be allowed to do what," so authz bugs survive in mature apps
  and ship constantly on new endpoints, internal APIs, GraphQL, mobile/WebSocket, and old API versions.
- The API is the truth; the UI is decoration. The UI hides the button — the API still answers.
- Developer mindset: *"If I built this, where would I have skipped the per-object check?"* — then try
  exactly that. **And: once you find ONE access-control bug, the team usually lacks a centralized
  authz layer → the same class repeats across features. Sweep the whole app.**

---

## Identity matrix setup (2 accounts / 2 tenants / 2 objects)
Do this once per target. **Two accounts are mandatory; two tenants are mandatory for SaaS.**

Provision at least:
- **A-owner** (Tenant A) = attacker · **A-member/viewer** (Tenant A, low role) · **B-owner**
  (Tenant B = victim) · **Anonymous** (no token / expired / revoked token).
- If roles exist, get one of *each*: admin, member, viewer, billing, support, API-only, **plus every
  mid-tier role** (a check that blocks "viewer" often passes "support"/"developer" — test EVERY role,
  not just the lowest).
- For each object type (`user, org, file, invoice, message, key, doc, order, project, webhook,
  payout, invite, role, media, comment`), capture its id under **each** identity.
- For invite/sharing flows, also capture: pending / accepted / expired / revoked invite tokens,
  removed users, deleted / archived / restored objects.

Keep one Burp/Caido session per identity. **Build the habit: capture B's request, replay with A's
session, diff the response.** Always capture A's own response as the baseline so you judge B's by
delta (status, length, body, timing, error class).

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
*inside* a composite session cookie value), JWT claim, **GraphQL variable**, **WebSocket frame**.
Hidden ids in JS bundles, source maps, `doc_id` persisted GraphQL queries, and prior responses count too.

### 2) Swap & observe
Replace A's id with B's. `200` + B's data, or the action applied = IDOR. **Test read / write / delete
independently** — a read may be locked while `PUT/PATCH/DELETE` is open. **Test every ACTION a feature
exposes** (create/read/update/delete/complete/upload/download/export/share/approve) — one verb is
often protected while a sibling isn't.

### 3) ID-shape attacks (the hard part is finding valid victim ids, not the swap)
- **Sequential / numeric:** `123→124`, `id=0`, `id=-1`, negative, very large, `id=*`, **missing id**
  (defaults to all/admin?), **id-less list endpoint dumps everything**.
- **UUID / GUID — NOT "safe":** unpredictability stops *enumeration*, it adds **no ownership check**.
  Always run the "valid pair, wrong session" test (victim id + YOUR cookie). Source UUIDs (see §ID
  sourcing). UUIDv1 is time/MAC-based and partially predictable.
- **Hashids / slugs:** often reversible without the salt; else harvest from responses.
- **Encoding / format wrappers** (a check may run on only one representation): `123` → `"123"` →
  `[123]` → `{"id":123}`; base64 (`MTIz`), **base64-JSON** (`{"type":"userID","id":"182905"}`),
  hex (`0x7b`), URL-encoded, double-encoded, hashed-vs-raw.
- **Parser/coercion smuggling (dual-parser disagreement)** — when the exact id is blocked, try a value
  the *validator* reads as yours but the *data layer* coerces to a different id:
  - **E-notation / decimal:** `123` blocked → `123.0`/`123e0` returns YOUR data (proves coercion) →
    `123e1` (=1230) returns user **1230**; `123.1e1`=1231; `123e-1`=12.3→user 12. Validator checks
    leading digits, backend re-parses the whole number.
  - Leading zeros / sign / whitespace: `0123`, `+123`, `%20123`.
- **Type juggling:** numeric vs string id, array vs scalar; a record that has BOTH a 32-char id and a
  parallel **sequential numeric id** — try the guessable one.
- **Email / username / phone / company-slug / tenant-name** as the identifier instead of an id.
- **gid:// / Relay global-id forgery.** Relay `id`/`node(id:)` values are usually `base64("Type:dbid")`
  — `VXNlcjo0Mg==` = `User:42`. Decode your own, swap the inner db id, re-encode, fetch via
  `node(id:){... on User{email}}`. Often reaches objects the REST API guards. Try inner shapes
  `Type:uuid`, `Type:tenant:id`, `gid://app/Type/<int>` (Rails/GitLab).

### 4) ID location & method tricks (authz may check only one place)
```
# Move the id between locations:
path  vs  ?id=  vs  body {"id":}  vs  X-Account-Id header  vs  JWT claim  vs  cookie segment  vs  WS frame  vs  GraphQL variable
# Parameter pollution (HPP) — auth reads one copy, the data layer reads the other:
?id=mine&id=victim     id=mine(query)+id=victim(body)     id[]=mine&id[]=victim     id=victim,mine
#   → name the polluted param EXACTLY as the response JSON key (devs are consistent); after a fix,
#     retry the pollution in a DIFFERENT location (GET↔POST↔body↔header) — precedence differs per stack.
# Method confusion — GET blocked, write verbs open; or reach the object via a sibling endpoint:
GET /doc/B →403 ; try POST/PUT/PATCH/DELETE/HEAD/OPTIONS  or  /doc/B/export /print /embed /oembed /download
X-HTTP-Method-Override: GET|DELETE ;  switch Content-Type json↔form↔xml
# Path tricks on ownership routes:
/users/B/../A   /me vs /users/A   trailing /   ;-matrix params   /org/123/../456/   ..;/   %2e%2e   //double-slash
```

### 5) Nested / related objects
Parent allowed but child not re-checked — `/orgs/mine/users/{victimUser}`, `/order/{mine}/buyer/{victim}`,
GraphQL `team → members → profileData`, `order → buyer → payment`.

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
  OTHER viewers: comments, Q&A `clientId`, presence, "who reacted", shared docs. If the server shows
  other users' object ids in normal responses/DOM, the "unguessable" defense is void — harvest & replay.
- **List/hub endpoints emit ids in bulk:** follower/following, members, search, autocomplete,
  leaderboard, "people you may know", org directory, group members. Find a **high-degree hub account**
  (exec/celebrity/auto-followed account) whose follower list dumps thousands of ids at once.
- **Object responses leak sibling/child ids** — chain them: `conversations`→`conversation_id`→
  `conversation_parts`→`part_id`→`participants`→`user_id`→`/users/{id}`. Devs redact "sensitive" fields
  but forget the ids that unlock them.
- **Registration / company-create / invite responses** frequently return your fresh (sequential) id
  and sometimes other internal ids.
- **History & code:** `gau`/`waybackurls` + id regex, JS bundles, source maps, Google cache,
  `application.wadl`/Swagger/GraphQL schema, mobile APK/source URLs, crash reports.
- **Invite / share / reset links** carry an identity (often base64 email or a token) — decode & swap.
- **Offline/physical artifacts:** QR codes, barcodes, NFC, printed account/reservation numbers — scan
  /decode to reach the backing endpoint and its embedded id.
- **Reconstruct structured ids:** decompose a "filename"/ref into parts — `id + username + timestamp`,
  airline AWB = `prefix + serial + checkdigit (serial % 7)`. Each part is predictable → script a
  candidate generator and keep the 200s.
- **Shrink an "unguessable" keyspace:** if the id encodes a timestamp/sequence, create two objects at
  the *same instant* (single-packet race) so they share the time component, then diff to isolate the
  few random chars.
- **Existence oracles** (a sibling endpoint that confirms "user X has feature Y") let you enumerate
  valid ids before hitting the sensitive endpoint.

---

## Beyond the simple swap — creative vectors
- **Second-order IDOR.** The id you submit in step 1 is stored and consumed by a LATER endpoint that
  doesn't re-check ownership: a `…success.aspx` page that reads the last id from session; an
  **audit/activity log** that renders content the primary endpoint denied; a notification/export/
  receipt/cache. *Request the guarded object (hold the redirect), submit the victim id, then trigger
  the downstream consumer.*
- **Encryption / signing as the access key.** An endpoint that will encrypt/encode/sign ARBITRARY input
  for you (`/encrypt?text=`, "generate share link", "token") turns a guessable plaintext id into the
  access token. If the ciphertext is the only check and the plaintext is sequential → full IDOR.
- **WebSocket-frame IDOR.** WS messages are requests too and are frequently unauthorized — mutate
  ids/UUIDs/emails inside frames (signup/profile/presence frames are gold). Most hunters never open the
  WS tab.
- **GraphQL response→variable promotion.** If the id appears only in the RESPONSE (nothing in the
  request to swap), author your OWN query adding it as an argument: `query($id:ID!){ user(id:$id){…} }`.
  Resolvers are often shared with admin tooling and accept args the UI never sends. Add sensitive fields
  (`email`,`phone`,`securityAnswer`,`token`) to existing queries; use aliases/batching to probe many
  ids in one request; `node(id:)` for guarded objects.
- **Resource-PATH-in-body.** The object ref is often a storage path / blob key / upload token in the
  body, not a numeric id — swap paths between two accounts. AI "describe/summarize/OCR your file"
  features make a powerful read oracle for the victim's content.
- **Mass assignment (BOPLA write).** Add privileged fields to create/update bodies — try JSON + form +
  query (HPP merge can bypass field filters). Pull real field names from `GET` responses/Swagger/JS.
  High-yield: `role, roles, isAdmin, isOwner, verified, permissions, tenantId, accountId, ownerId,
  price, amount, discount, status, paid, planId, authorId, visibility, approved, UserRoleID`.
- **Multi-field / correlated id.** If a single-id swap fails, the server may cross-check a SECOND field
  — supply the full identity tuple (id + email, id + username, id + tenantId) together.
- **Account-linking / manufactured association.** When direct access is blocked, CREATE a relationship
  first (invite to team / add as member / share resource / connect social account) — even unaccepted —
  then retry; the pending relationship is often treated as authorization.
- **Null/blank/missing credential bypass.** Send `access_token=null`, blank `hash=`, removed signature,
  omitted id. Persisted-query (`doc_id`) and `/ads/graphql/`-style endpoints often skip authz with an
  empty token.
- **Cross-tenant via header.** Tenant id frequently rides in `X-Account-Id`/`X-Org-Id`/`X-Tenant-ID`
  with no membership check — swap it (works even for orgs you don't belong to).

---

## BFLA (function-level)
The UI hides admin/staff actions; the API often has no role check. Take every privileged action and call
it as a **low-priv** user (or anon).
- Replay an admin-only request (captured as admin) as a normal user — many apps gate only the UI.
- Find admin/internal endpoints in **JS / source maps / API docs / Swagger** (`isAdmin`, `/admin/api`,
  role constants, the SPA route table) and call them directly.
- Direct-browse: `/admin`, `/api/admin/*`, `/internal/*`, `/api/v1/admin/*`, `/settings/org/<other_org>`.
- **Derive sibling functions** from any one you see — don't only test the visible verb:
```
add remove update delete list export import bulk approve reject archive restore
invite revoke assign unassign impersonate enable disable complete download upload
# /api/members/add exists ⇒ test /remove /update /invite /bulk /api/admin/members /api/v1/members
```
- **Privesc via role/permission fields:** replay your own update with a higher `UserRoleID`/`roleId`/
  `isAdmin`; learn valid role values from API docs. Role/group/org ids are often **serialized** — guess
  a higher tier.

---

## BOPLA — excessive data exposure (read)
API returns more than the UI renders (other users' emails, internal flags, hashes, tokens). Read the
**raw JSON**, not the page. Force more fields: `?expand=*`, `?fields=*`, `?include=all`, `?pageSize=1000`,
GraphQL field selection, and **add known field names** to an under-selecting query.

---

## Horizontal vs vertical escalation & multi-tenant isolation
- **Horizontal** = same privilege, other user's/tenant's data (the IDOR/BOLA core). **Vertical** = lower
  role → higher action (BFLA, or mass-assigning `role/is_admin/plan/owner_id`).
- **Ownership transfer / state:** can you change `owner`, `assignee`, `created_by` to take an object over?
  Pre-account-creation object claiming (claim resource, then register that email)?
- **Multi-tenant:** replace org/tenant ids with B-org values while authed as A-org. Devs check the tenant
  id in one place and *use* it from another:
```
tenant id lives in: subdomain · path · ?query · body · header(X-Tenant-ID) · cookie/localStorage · JWT claim · GraphQL var
mismatch tests: path=A + body=B | header=B + query=A | JWT tenant=A + object tenant=B | stale tenant cookie after switching orgs
```
- Invite/role flows: can A add themselves to B's org, or escalate role via the invite-accept/role-update
  endpoint? Cross-tenant via shared resources: file ids, share links, webhooks, exports, reports.
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
- **Frontend-only enforcement:** authz only on the public/frontend API; hit the **backend API directly**
  (error-leaked paths, source maps, `application.wadl`) and per-object checks are gone.
- **GraphQL resolver-level BOLA:** route auth ≠ object auth; nested edges leak if only the root resolver
  checks. Recover schema without introspection via suggestion errors / persisted queries / JS (InQL).
- **API versioning gaps:** `/api/v1/` often lacks a check present in `/api/v2/`; `/internal`, `/legacy`,
  singular vs plural, mobile API hosts, out-of-scope sibling domains.
- **403/401 mini-bypass:**
```
path:   /admin → /admin/  /admin/.  //admin  /%2e/admin  /admin..;/  /admin%20  /Admin  /./admin
header: X-Original-URL: /admin  X-Rewrite-URL: /admin  X-Forwarded-For: 127.0.0.1  X-Custom-IP-Authorization: 127.0.0.1
method: GET→POST/HEAD/OPTIONS ; X-HTTP-Method-Override: GET ; Content-Type json↔form↔xml
```

---

## Fix-bypass / retest playbook (always revisit a "patched" IDOR)
Patches are usually narrow. After any fix, try:
- **Token validated for existence, not BOUND to the object:** use YOUR OWN valid access code/token with
  the VICTIM's id (the classic "valid code, wrong reservation"). Confirm the primary id is still enumerable.
- **A different action/endpoint leaks the new secret:** switch `act=`/operation/`doc_id`; probe each with
  blank/null/missing values — one code path often returns the per-user hash/token.
- **Move the param:** GET↔POST↔body↔header; HPP in a new location; alternate id format (E-notation,
  decimal, array, encoded).
- **Sibling/old surface:** another endpoint, old API version, mobile/WebSocket, frontend-fixed-but-backend-not.
- **Incomplete patch:** re-test a week later; many fixes regress or miss a second endpoint with the same data.

---

## High-impact chains (turn a read into Critical)
- **IDOR → ATO via recovery flow:** add YOUR email/phone as a victim's *secondary/recovery* contact (IDOR),
  then trigger their password reset → link comes to you. Or reset-link carries a guessable email/id.
- **IDOR → leaked secret → ATO:** an endpoint returns the victim's password-reset token / security answer /
  per-user hash / OAuth access token → log in / reset as them, or take over the linked 3rd-party (Drive/Slack).
- **Profile/identity IDOR → id harvest → ATO:** edit-profile IDOR plus the public profile leaking the id.
- **IDOR → stored XSS → session hijack:** write a stored-XSS payload into a field rendered to OTHER users
  (filename, metadata, group name) keyed by a guessable id.
- **IDOR → RCE:** upload/import endpoints, code-execution platforms; object access escalates to code.
- **Money:** change another org's payout/withdrawal PayPal email; enumerate gift-card/reservation ids with a
  balance oracle; modify campaigns/orders/discounts.
- **Mass PII/breach:** enumerable id space over PII/KYC/financial = "mass" impact (state the range, don't scrape).

---

## Oracles & response deltas
You don't need the data to prove access — you need a reliable signal that A reached B's object.
- **Status:** `200` vs `403/404`. `403` (exists, denied) vs `404` (hidden) is itself an enumeration oracle.
- **Body size / content:** B getting an A-sized body for A's id. Diff against your own baseline.
- **Timing:** valid-but-denied id is often slower (hits the DB) than a non-existent one.
- **Error class:** "you don't own this" vs "not found" vs 500 each leak existence/ownership. **Verbose
  validation errors** ("title is required", "invalid template → here are all valid templates") enumerate
  hidden params/enums/object ids — weaponize them.
- **Side effects:** action reflected in B's account, an email/webhook fired, an audit-log entry, a push/SMS
  delivered. The "no body but it happened" oracle for writes.

---

## Creativity question bank — ask these per surface
The core prompt: **"If I am user A, can I read/modify/delete user B's ___ by changing ___?"** Expand it:

**Per object (user, order, invoice, file, message, project, key, payout, comment, media, webhook):**
- Can I READ B's object by swapping its id (path/query/body/header/cookie/JWT/WS/GraphQL var)?
- Can I UPDATE / DELETE / EXPORT / SHARE / DOWNLOAD it, even if READ is blocked?
- Is there a parallel guessable id (sequential numeric) for this object alongside the "random" one?
- What happens with id = `0 / -1 / huge / *` / **omitted** / `id.0` / `id e1` / `[id]` / duplicated (HPP)?
- Where does the app show me B's id for free (lists, followers, comments, search, "who viewed")?
- Does a child/nested object skip the parent's check (`/order/mine/buyer/{victim}`)?

**Per feature/flow:**
- Does any LATER step (success page, audit log, notification, export, receipt) re-use my submitted id
  without re-checking ownership? (second-order)
- Can I add MY email/phone/role to B's account, or set B's `owner/role/payout-email`?
- If a fix added a token/code — is it BOUND to this object, or just "valid"? Does another action leak it?
- Does the WebSocket / GraphQL / mobile / old-version path enforce the check the main web API does?
- Does the app encrypt/sign MY input for me, and is that ciphertext the only access check?
- Can I manufacture a relationship (invite/share/link) to B to gain access?

**Per role / tenant:**
- For each CRUD action: which roles are blocked, and does a DIFFERENT non-admin role slip through?
- Can a viewer/anon call admin/staff functions (BFLA)? Can I set `isAdmin/role/plan` via mass assignment?
- Swap `X-Account-Id`/tenant id — does it act on an org I'm not a member of?

**Sourcing / proof:**
- If the id is "unguessable": which list/hub/response/wayback/JS/QR source emits it? Can I reconstruct it
  from parts or shrink the keyspace with a race?
- Can I prove the id is APP-SUPPLIED (not guessed) to beat triage? What's the cheapest benign oracle?

---

## Field-tested mini-patterns (one-liners from real reports)
- `/api/users/me` → swap `me` for your numeric id (confirm), then decrement to a neighbor → enumerate.
- Open any uploaded asset (image/avatar/attachment) directly → its url has a guessable id → +/- across tenants.
- "Add secondary email" / "recovery email" IDOR is the single highest-value target → reset → ATO.
- Company/group/role/org ids are frequently **serialized** — enumerate orgs and grab a higher-tier role id.
- Use **Autorize/Caido Authz** to auto-replay every request with a low-priv & no token, flag matching responses.
- Burp **Sitemap built from responses** reveals endpoints the UI never calls for you (BFLA candidates).
- Decode every opaque token: base64 may wrap `{"type":"userID","id":N}` → edit, re-encode.
- New features ship with broken authz first — test the latest feature / latest API version.
- Out-of-scope or self-hostable (OSS) products: stand one up, read the source, then hunt object checks.

---

## Tooling
- **Burp Autorize / AuthMatrix / Auth Analyzer**, **Caido "Authz"** — per-identity replay + auto-flag.
- **ffuf / nuclei** access-control + 403-bypass templates; Burp `403bypasser`.
- GraphQL: **InQL, GraphQL Raider, batchql, GraphCrawler, graphw00f** (readable queries, schema recovery, batching).
- **gau / waybackurls / katana / JS parsers / source-map extractors** for id & endpoint sourcing.
- **Single-packet attack** (Burp Repeater "send group in parallel") for race-to-align-id / keyspace shrink.
- WebSocket: Burp's WS history + repeater; don't skip the WS tab.
- Sibling-endpoint generation from observed routes (`/x/add ⇒ remove/update/list/invite/bulk/v2`).

---

## Validation gate (kill weak/dup findings before reporting)
- [ ] Reproduced with **two owned identities**, sessions captured side-by-side.
- [ ] It's authorization, not just authentication (request *was* authenticated as A, yet reached B).
- [ ] Mass-assignment / write actually **persisted** and affects privilege/state (not a cosmetic echo).
- [ ] Valid victim-id sourcing is demonstrated or the id is provably **app-supplied / enumerable** (beats triage).
- [ ] Real attacker impact stated; chain only if the chain creates impact. Avoid: existence-only leaks,
      "maybe if victim does X," own-account no-op mass assignment.
- [ ] No third-party PII exfiltrated; proof uses owned/canary objects or minimal markers.

---

## Master checklist
- [ ] Two accounts + two tenants + EVERY role set up; sessions captured; baselines recorded.
- [ ] Every object id swapped (seq, UUID, hashid, email/slug/name, encoded, base64-JSON, decoded gid,
      E-notation/decimal, array/JSON wrap) for **read / write / delete / export** independently.
- [ ] Victim ids sourced (lists/hubs, /me, responses' child ids, wayback/JS/source maps, invite/reset links,
      QR/physical, reconstructed from parts, race-shrunk).
- [ ] ID location moved (path/query/body/header/cookie/JWT/WebSocket/GraphQL var) + HPP (and after-fix GET↔POST).
- [ ] All verbs + sibling/export endpoints + old API versions + WebSocket + mobile tried.
- [ ] Every admin/staff function called as low-priv user and anon (BFLA); derived siblings; serialized role/org ids.
- [ ] Mass-assignment fields tried on all create/update endpoints (JSON+form+query).
- [ ] Excessive-data-exposure checked in raw JSON / GraphQL field selection / `?expand=*`.
- [ ] Tenant id mismatched across path/header/body/JWT; invite, account-linking & shared-resource flows tested.
- [ ] Second-order paths checked (success page / audit log / notification / export reuse of a submitted id).
- [ ] Encryption-as-key, null/blank-token, multi-field-correlated, and resource-path-in-body vectors tried.
- [ ] Final resolver verified (gateway/frontend bypass, path-normalization skew, GraphQL nested edges).
- [ ] Every found IDOR triggered a full-app sweep for the same class (centralized-authz failure).
- [ ] Patched bugs retested (token-binding, secret-leak via other action, moved param, sibling surface).
- [ ] Impact + blast radius quantified with owned canaries/counts; validation gate passed.
