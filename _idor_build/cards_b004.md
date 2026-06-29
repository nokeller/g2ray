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

### [17] Oculus Developer support — comment on a private bug by swapping the CHILD id (`external_post_id`), not the checked parent bug id — Sarmad (Meta BB) [NEW ★ swap the secondary id]
- Where: `graph.oculus.com /graphql` add-comment mutation with `comment_parent_id` (bug id) + `external_post_id` (the comment being replied to).
- Approach/how-found: Plan A (swap the bug id) failed — bug ownership is checked. Plan B: swap `external_post_id` to a victim's private comment id → succeeded, because authz validated only the **bug id**, not the comment id → comment on others' private bugs. Limitation: needs the victim's (private) comment id, so impact is gated by id discovery.
- Test: when swapping the obvious parent id is blocked, swap a *secondary/child* id in the same request (comment/attachment/reply/thread id) — backends often authorize only the primary object.
- Q: "If the parent id is access-checked, is there a secondary id (comment/reply/attachment/thread) in the same request that isn't?"

### [22] Reset endpoint leaks email by `id` + Host/Referer injection → mass ATO (scripted) — nullr3x [NEW ★ id→email oracle + reset-link host control]
- Where: forgot-password POST with `email` + `id`.
- Approach/how-found: the `email` field is ignored for lookup; `id` selects the account, and when email≠id the server **discloses the victim's email** → enumerate id 1..N → id→email list. Then submit the matching email+id but inject `Referer`/Host = attacker server → the reset link is generated against the attacker host → token delivered to attacker → ATO. Two bash scripts automate it (id→email harvest, then reset-token capture). The server only emails a link when email+id match; otherwise it leaks the email — either branch helps the attacker.
- Test: send reset with mismatched email+id; if it returns the account email, that's an id→email oracle. Then tamper `Host`/`Referer`/`X-Forwarded-Host` to point the reset/verify link at your server.
- Q: "Does the reset endpoint disclose the account email when id≠email? Does `Host`/`Referer`/`X-Forwarded-Host` control the domain in the generated reset link?"

### [25] "IDOR from a blank page" — an empty page still ships JS endpoints; F12 → API → IDOR — kerstan [DUP — recon reminder]
- A page that renders blank still loads JS that calls API endpoints; open DevTools/Sources, harvest the endpoints, then test each for id swaps. (Member-locked past the intro; the value is the recon move of not dismissing empty pages.)
- Q: "Did I dismiss an empty/blank/placeholder page without reading its JS for hidden API endpoints to IDOR-test?"
