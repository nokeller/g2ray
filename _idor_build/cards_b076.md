### [424] Travel-booking `payment_id` enumeration → booking PII (author's own-blog mirror of [423]) — YoKo Kho [DUP of 423: same finding on firstsight.me]
- Where: same `POST /xyzabc/checkout payment_id=` flow as [423].
- Note: identical to card [423]; recorded for per-index completeness (Intruder with "always follow redirect" automates the booking-PII dump). See [423].
- Q: "(see [423]) Which flow id is unauthorized, and is the PII in the source?"

### [425] Flickr — spoof another user as the author of a group blast/description: `flickr.groups.addBlast` carries BOTH `user_id` (the attributed author) and `viewerNSID` (your session); change `user_id` to a victim's NSID → the content posts AS the victim — Samuel (saamux) [NEW ★ author/owner field decoupled from the session id → impersonation]
- Where: `POST /services/rest method=flickr.groups.addBlast` (`user_id` ≠ `viewerNSID`, plus `csrf`).
- Approach/how-found: editing his group's blast sent a request where `user_id` named the author separately from the session (`viewerNSID`); swapping `user_id` to another user's NSID (harvested from their photo comments/likes) made the blast appear authored by the victim — even with a CSRF token present.
- Test: when a create/edit request has BOTH an author/owner id AND a session/viewer id, set the author id to a victim's → spoof authorship/attribution; harvest the victim's id from public activity (comments/likes).
- Q: "Does this write carry a separate author/owner id alongside my session id? If I set it to a victim, does the content get attributed to them (impersonation)?"

### [427] Practo (healthcare) — send-SMS IDOR adds victims to YOUR account: send-SMS to a patient/staff keyed on an INCREMENTAL id; the response shows nothing, but REFRESHING the dashboard reveals the targeted user was added to the attacker's account with full details → brute the id → harvest patients' PII — Avinash Jain [NEW ★ empty response but the side effect (foreign user linked to my account) leaks PII; verify via dashboard]
- Where: send-SMS request (`patient_id`/`staff_id`, incremental).
- Approach/how-found: changing the id sent SMS to other users but the HTTP response was unrevealing; on returning to his dashboard, the targeted user had been ADDED to his account with their details visible → enumerate the id to collect many users' PII (healthcare data).
- Test: when an IDOR's response looks empty/useless, check OTHER surfaces (your dashboard, lists, exports) for the side effect — the data may surface elsewhere; incremental patient/staff ids = mass PII.
- Q: "Did the action import/link the foreign object into MY account where I can then read it? Have I checked my dashboard/lists after the request, not just the response?"
