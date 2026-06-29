### [93] Google Chat — removed space CREATOR can still read members: `batchexecute` member-list RPC keyed on space ID only; swap your old space ID for the victim's → names+emails — hoangkien/hope ($1337) [NEW: removed-privileged-user retains read access via direct RPC]
- Where: `POST /u/0/_/DynamiteWebUi/data/batchexecute?rpcids=` (EmdhDb/vWUt9 member-list RPCs); key = `space/<spaceID>`.
- Approach/how-found: when a Space *creator* is removed by another manager they lose UI access, but the underlying member-list `batchexecute` RPC only checks the space ID, not current membership. Intercept "View Members", swap the attacker's space ID for the target space ID (one the attacker used to belong to) — no need to change the user ID — 200 + members' names/emails in response.
- Test: after you're removed/downgraded from a resource, REPLAY the old data-fetch RPC directly — revocation often only hides the UI, not the API. Batched RPC endpoints (Google `batchexecute`) carry the object id inside `f.req`.
- Q: "After my access is revoked, can I still hit the underlying fetch RPC by id? Does the server re-check *current* membership, or only that the id is well-formed?"

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

### [157] Support/contact-us form — account DELETION on behalf of victim: email field unchangeable in UI but editable in the intercepted request; no verification ticket is from the owner — pwnsec.ninja [NEW: support-ticket IDOR/BAC → account closure]
- Where: contact-us / support form submit request, `email`/`subject=Close Account` field.
- Approach/how-found: the form locked the email field in the UI; intercept the submit and change `email` to the victim's, subject "Close Account". Support team actioned the closure with no verification that the requester owned the account → victim's account closed (DoS/ATO-adjacent).
- Test: any "request via support/contact form" flow — change the locked identity field (email/account id) in the request to act on another user; human-actioned tickets rarely verify ownership.
- Q: "Can I submit a destructive support request (close/reset/refund) on behalf of a victim by editing the locked email/account field in the request? Does support verify ownership?"

### [167] Mozilla support (kitsune) — IDOR found by READING the open-source code: `question reply` view honors a `delete_images` POST param that deletes any image id with no owner check — noob3xploiter ($1,500) [NEW ★ source-code review to find a hidden/legacy IDOR param]
- Where: Django `questions.reply` view (`^/(?P<question_id>\d+)/reply$`); undocumented `delete_images` POST param.
- Approach/how-found: practicing static analysis on GitHub projects, he downloaded kitsune (powers support.mozilla.org). The `reply` view deleted any image whose id was in `delete_images` WITHOUT the owner check that the real image-delete function had. Not referenced in the frontend (legacy snippet) — only findable by reading code. Confirmed on staging with permission.
- Test: when the app is open-source (or JS is readable), DIFF similar handlers — one path enforces ownership, a sibling/legacy path doesn't. Hunt for action params (`delete_images`, `*_id`) not exposed in the UI.
- Q: "Does the source contain a legacy/secondary handler for this object that skips the ownership check the main handler has? Are there hidden action params I can send?"

### [244] YouTube Studio — hidden like/dislike counts leak: analytics POST keyed on `videoId`; swap to a victim video whose counts are hidden → counts in response — bloggerrando [NEW: privacy toggle is UI-only; analytics API still returns the metric]
- Where: YouTube Studio analytics `POST {"entity":{"videoId":X}}` → response `metrics.likeCount/dislikeCount/viewCount/commentCount`.
- Approach/how-found: even when an owner sets "Don't show how many viewers like/dislike", the Studio analytics endpoint returns those metrics for any `videoId` swapped in — the privacy setting only hides the public widget.
- Test: when a UI privacy toggle "hides" a metric/field, check whether the analytics/detail API still returns it for an object id you don't own.
- Q: "Does hiding a field in the UI actually remove it from the API response, or can I read it by swapping the object id into the analytics/detail endpoint?"

### [255] Facebook — developer task list of ANY app: GraphQL `app_tasks` keyed on `appId`; swap to a third-party app's id → its private dev tasks — Amine Aboud [DUP-reinforce: swap resource owner id in GraphQL]
- Where: `POST /graphql` `variables={"appId":X}&doc_id=265437575802287` → `data.app_tasks[]`.
- Approach/how-found: noticed a GraphQL request returning his own app's task list; changed `appId` to another app's id → returned that app's private developer tasks (objective, deadline, completion_time).
- Test: developer/console GraphQL queries (apps, projects, integrations) key on an owner/app id — swap it for an id you don't own; harvest app ids from public app pages.
- Q: "Do developer-console queries (`appId`/`projectId`) enforce ownership, or return any id's private config/tasks?"

### [259] Markdown editor — IDOR to CDN image links incl. DELETED/private images: comment markdown stores `[IMAGE]ID[IMAGE]`; swap the image ID → CDN URL of others' images — Susan Wagle [NEW: "deleted" images still live on CDN; reference by id]
- Where: comment/markdown body containing an image reference `...ID...`; rendering returns the CDN link by id.
- Approach/how-found: uploading an image into a comment produced a markdown token wrapping an image ID. Swapping that ID to other values returned other users' private images — and images users had "deleted" (still on the CDN, just dereferenced).
- Test: when an attachment is referenced by a guessable/sequential id in body content, swap the id to pull others' files; "deleted" objects often remain on the CDN and are reachable by id.
- Q: "Is the uploaded file referenced by a swappable id in the saved content? Are deleted files actually purged from the CDN, or just unlinked?"

### [282] Travel app — payment IDOR by brute-forcing `req_reference_number` at the payment-gateway redirect → other users' SSN/passport/ticket — Ganesh (haxor8595) ($800) [DUP-reinforce: brute a reference number in a payment redirect]
- Where: payment-gateway redirect request body, `req_reference_number` parameter.
- Approach/how-found: at checkout the app redirected to a payment processor; out of curiosity he brute-forced `req_reference_number` in the request body → listed other users' payments incl. SSN, passport number, name, ticket IDs.
- Test: payment/redirect requests carry a `reference_number`/`order_ref` — fuzz it; checkout/3rd-party-handoff steps are weakly authorized and leak PII.
- Q: "Is there a reference/order number in the payment redirect I can increment/brute to read other buyers' transactions and PII?"

### [292] Facebook — "Make Featured Product in any video": GraphQL mutation accepts arbitrary `video_id` (not owned) + your `product_item_id` → tag your product as featured on anyone's video — abdellah yaala [NEW: cross-object write — attach YOUR object to a VICTIM's object]
- Where: `POST /api/graphql/` mutation `doc_id=2781671041948682`, `variables.input.video_id=<victim>`, `product_item_id=<attacker>`.
- Approach/how-found: as a page admin he created a shop product, then issued the "feature product" mutation with `video_id` set to a video he didn't own → his product appeared as Featured on the victim's high-traffic video; only removal was deleting the video.
- Test: "attach/tag/link my X to a Y" mutations — set Y (the container) to a victim's object id while X stays yours. Cross-object writes are a distinct IDOR class (parasitic placement, not data theft).
- Q: "Can I attach my own object (product/tag/comment/link) to a victim's object by swapping only the container id in a create/feature mutation?"
