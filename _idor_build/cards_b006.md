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
