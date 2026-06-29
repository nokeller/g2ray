### [256] OTP login ATO — `/login/signin {email, code}`: OTP not bound to the email; request a code for YOUR email, then swap the email param to the victim while keeping your valid OTP → logged in as anyone — Avanish Pathak [NEW ★ OTP not coupled to email (defeats rate-limit)]
- Where: `POST /login/signin {email, code}` (4-digit OTP; 429 after 10 tries; not leaked in response).
- Approach/how-found: brute was rate-limited and the OTP wasn't in the response, so neither worked. But the server validated only that the OTP was valid, not that it was issued for that email → enter your own email, receive your OTP, then change `email` to `admin@example.com` with your correct OTP → logged into the victim ("loose coupling of email with OTP").
- Test: on OTP/magic-link login, check that the code is bound to the email/account — request a code for your account, then swap the email param to the victim while keeping YOUR code. This bypasses rate-limiting entirely (you use a valid code).
- Q: "Is the OTP/code cryptographically bound to the email it was sent to? Can I get a code for my account and swap the email param to a victim's while keeping my valid code?"

### [257] Stolen-device portal — Privilege-Management request takes `modifyUserId`; a low-priv admin swaps it to a high-priv account → set its privileges (vertical BAC via IDOR); plus stored XSS by escaping a JS-reflected `name` field (`'));`) — cysek [NEW: privilege-mgmt target-id swap + escape-the-JS-context XSS]
- Where: Privilege-Management page request with `modifyUserId`; user-details `name` reflected unencoded into a JS function (`setProfValues`).
- Approach/how-found: with two admin roles, he captured the privilege-set request (keyed by `modifyUserId`) from the low-priv admin and swapped in a high-priv account's UserId → set privileges he shouldn't control (vertical BAC). Separately, profile fields were reflected unsanitized into a JS string; escaping the string (`test'));`) then `</script><script>alert(1)</script>}'));` → stored XSS.
- Test: in role/privilege-management features, swap the target user id (`modifyUserId`) so a low-priv role modifies a high-priv account. For fields reflected into JS, escape the JS string context (`'));`) instead of brute-forcing XSS payloads.
- Q: "Can a low-priv admin swap the target id in privilege management to modify a higher-priv account? Are profile fields reflected into a JS context I can escape with `'));`?"

### [260] "A token is not the same on all endpoints" — a backup/export endpoint authed by a POST token (no cookies) validates it loosely → obtain any user's backup data — Tommaso De Ponti ($600) [NEW: replay the same token across ALL endpoints; secondary endpoints enforce it weakly] (tail member-locked; technique captured from intro+title)
- Where: a backup endpoint returning user backup data, authorized only by a token in POST data (no cookies), formatted `1234-randomletters`.
- Approach/how-found: every login fired a backup-data call authed by a token (not cookies). The core takeaway (title): the token is NOT validated the same way on every endpoint → a backup/secondary endpoint accepts it without the per-user binding the main flow enforces → read any user's backup.
- Test: replay one token/session across ALL endpoints — auth is often enforced strictly on primary endpoints but loosely (or differently) on backup/export/secondary/legacy ones. Don't assume consistent validation.
- Q: "Is the token validated identically on every endpoint, or does a backup/export/secondary endpoint accept it without the per-user check the main endpoints enforce?"

### [261] Reset PIN == user id (predictable OTP) + IDOR leaks uid/email → ATO everyone; no rate limit — Takester (Critical) [NEW ★ the OTP is a known value; chain with an id-leaking IDOR]
- Where: password reset (4-digit pin sent on mail that equals the user's assigned id); a `.../{uid}` endpoint that echoes the user's submitted admin-request form (name, email, mobile).
- Approach/how-found: reset had no rate limit (already High). Then a `.../{uid}` endpoint opened in incognito showed any user's name/email/mobile by swapping `uid` (IDOR). Critically, the reset PIN was the user's id — so the IDOR leaked exactly the uid+email needed → reset → ATO of every user in seconds.
- Test: check whether the reset OTP/pin is derived from a known/sequential value (user id). IDOR endpoints that echo a submitted form (admin request, application) by id leak the uid+email needed for reset. No rate limit compounds it.
- Q: "Is the reset PIN/OTP actually a known value (user id/sequential)? Does an IDOR leak the uid+email so I can derive the pin and take over?"

### [262] CSRF + IDOR account deletion — `GET /{userName}/account/cancelTrial/` keys on the username in the path with only a Referer check → CSRF PoC with the victim's username + forged Referer deletes any account — Jerry Shah [NEW ★ destructive GET with id-in-path + Referer-only guard]
- Where: `GET /{userName}/account/cancelTrial/?googleAnalyticsId=&mktToken=` (username in path; no CSRF token; Referer-checked).
- Approach/how-found: IDOR alone (swap username) didn't delete; the action was a GET with no CSRF token, only a Referer guard. Crafting a CSRF PoC with the victim's username in the URL and a forged Referer header → account deleted. Burp Comparer between two accounts isolated the username and which params mattered.
- Test: destructive actions that are GETs with the target id/username in the path and only a Referer/Origin guard = CSRF+IDOR. Forge the Referer; swap the id. Diff two accounts' requests (Comparer) to find the target field.
- Q: "Is a destructive action a GET with the target username/id in the path and only a Referer check? Can I combine IDOR (swap id) + CSRF (no token, forged Referer) to delete/modify any account?"

### [266] Async access-logs API keyed by `UserID` → brute → access-logs (incl. private IPs) of 6,000 businesses — Rafi Ahamed ($4-digit) [DUP reinforcement: always-on interception catches the async API; logs leak infra]
- Where: access-logs API POST with `UserID` (loads asynchronously after the page).
- Approach/how-found: always-on interception caught that the access-logs loaded via a separate API carrying `UserID`; Intruder brute over UserID → 6,000 businesses' access logs, leaking private IP addresses.
- Test: data that loads asynchronously (logs, widgets, panels, charts) fires its own API with an id in the body → brute it. Access/activity logs frequently leak private IPs and infrastructure details.
- Q: "Does an async-loaded panel (access logs, analytics, activity) fire an API with a UserID I can brute? Do those logs leak private IPs/infra?"

### [267] Integration-hijack IDOR — connect a VICTIM's form to the ATTACKER's Zendesk by swapping `form_id` in both the initiate (GET) and enable (PATCH) steps → all the victim's future form responses flow to the attacker; form_id leaked via share link/dork — Ronak [NEW ★ route a victim's data stream to your own external sink]
- Where: integration flow — GET (initiate, `form_id`) → 3rd-party auth/mapping → PATCH (enable, `form_id`); both IDOR-vulnerable.
- Approach/how-found: started integrating his own form, swapped `form_id` to the victim's in the GET → landed on auth/mapping which fetched the VICTIM's form questions → configured the ATTACKER's Zendesk Sell → PATCH (enable) with the victim's form_id → integration enabled on the victim's account → every future form response delivered to the attacker's Zendesk. form_id enumerable via the form's share link / Google dork.
- Test: integration/connect/webhook/export flows keyed by an object id → swap to attach a VICTIM's object to YOUR external sink (Zendesk/Sheets/Slack/webhook) → continuous exfiltration of their incoming data. Test every step (initiate + enable). The object id often leaks in share links.
- Q: "Can I attach a victim's resource (form/store/repo) to MY integration/webhook by swapping its id → ongoing data exfiltration? Is the id leaked in share links/dorks? Did I test both the initiate and enable steps?"
