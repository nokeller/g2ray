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
