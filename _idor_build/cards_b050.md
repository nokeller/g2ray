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

### [293] Microsoft Teams — Endpoint B leaks `itemid`/`ThreadId`; Endpoint A (PUT) writes by those ids with no ownership check → change file ownership, override content (`fileUrl`), or delete ANY user's chat file (cross-chat) — Aly Anwar [NEW ★ one endpoint leaks ids, another writes by them = full file takeover]
- Where: Teams chat file upload — Endpoint A PUT (`imidisplayname`, `itemid`, `fileUrl`, `content`); Endpoint B POST (leaks `ThreadId`, `itemid`).
- Approach/how-found: Endpoint B disclosed the object references (`itemid`, `ThreadId`); Endpoint A accepted them with no ownership check. Crafting a PUT with a victim's `itemid`+`id` (and `ThreadId` for other chats) let him change displayed ownership, override file content via `fileUrl`, and delete files — full takeover across chats. (MS controversially declined it, but the technique is sound.)
- Test: when one endpoint LEAKS object ids (itemid/threadId/messageId) and another WRITES by those ids without authz, combine them → take over/modify/delete others' objects. Swap the container id (threadId/chatId) for cross-tenant reach. Collab tools (Teams/Slack) file & message objects are prime.
- Q: "Does one endpoint leak object ids that another writes to without an ownership check? Can I override file content (fileUrl), spoof ownership, or delete by swapping itemid/threadId across chats?"

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
