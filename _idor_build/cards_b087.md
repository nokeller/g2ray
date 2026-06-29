### [16] Facebook Social-Learning groups — distort/lock others' posts via `post_id` swap: `POST /groups/learning/create_with_post/?group_id=<mine>&post_id=<victim>` doesn't validate the post belongs to your group → add any group's post into your unit → renders it "Attachment not available"; invite the post owner to your group → their post becomes undeletable even by their admin — Sarmad Hassan [NEW ★ cross-group post-id import → content distortion + undeletable via invite]
- Where: `POST /groups/learning/create_with_post/?group_id=&post_id=` (Units feature).
- Approach/how-found: the add-post-to-unit request trusted `post_id`; pointing it at another group's post pulled it into the attacker's unit, corrupting the original ("Attachment not available") and—after inviting the owner—making it undeletable by owner and admin.
- Test: "add/import to unit/collection/list" features that reference a foreign object by id → import others' content to distort or lock it; pair with an invite to make damage persistent.
- Q: "Can I import another group's post/object into my container by id, and does it corrupt or lock the original? Does inviting the owner make it undeletable?"

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
