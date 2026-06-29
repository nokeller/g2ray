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
