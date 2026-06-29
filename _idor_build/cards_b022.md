### [100] "Bidirectional/stored IDOR" — blank a field + swap `_id` → the save endpoint backfills your blank from the victim's record (read) and can write to theirs — Hassan Farooq [NEW: blank-field save reflects victim data]
- Where: bank profile update; many params incl. `_id`.
- Approach/how-found: normal id-swap found nothing. Then he cleared the last-name field, saved, intercepted, and changed `_id` (1211221→1211220) → his last name auto-filled with the **victim's** name. So a blanked field + swapped id makes the update return/store the target's value → read other users' data by blanking fields, and also write data into their profiles (and store XSS). Other endpoints leaked CC data.
- Test: on update/save endpoints, try *blanking* fields then swapping the id — some "upsert" flows backfill empty fields from the referenced record (read primitive) or save your data onto it (write primitive). Test both directions.
- Q: "If I blank a field and swap the id on save, does the response backfill the victim's value (read) or write mine onto their record (write)?"

### [101] Google/AppSheet — send/spam docs into a victim's Google Docs via id swap; id via Google search; `version` irrelevant — Caesar Evan (Google VRP) [DUP reinforcement: action-on-victim by id + OSINT id]
- Where: AppSheet "send template to Google Docs" request carrying an `ID` (+ a `version`).
- Approach/how-found: two accounts; Intruder-swap attacker `ID`→victim `ID` → the doc is created in the **victim's** Google Docs (spam/write). The victim's id is discoverable via Google search; the `version` need not match the victim's.
- Test: action endpoints (send/share/export to a third-party store) keyed by an id let you write into a victim's space — swap the id; harvest ids via Google/OSINT; ignore "version"/secondary params that aren't validated.
- Q: "Does a send/share/export action take an id I can swap to write into the victim's account/store? Can I find that id via Google/OSINT?"

### [102] Time-object IDOR — bypass deadline/immutability by tampering the time param (app checks time, not the id↔time binding) — nxenon [NEW ★ time-parameter IDOR class]
- Where: any request carrying a time/date param alongside object ids (schedules, deadlines, editable windows).
- Approach/insight: devs often accept a time from the client for repeated/timeline items; the backend validates the *time* (is the window open?) but doesn't verify the supplied IDs actually belong to that time → set the time to a future/open date and edit or add items that should be locked (past deadline). "Time objects" are an IDOR blinker.
- Test: when a request has a time/date param, change it to an open window (future/now) while keeping a locked object's id — if the edit succeeds, the app gates on time but not on the id↔time relationship.
- Q: "Does this action gate on a client-supplied time? If I move the time into the allowed window, can I still act on a past/locked object's id?"

### [103] Unsubscribe IDOR — base64-JSON `{user_id}` in the link; token after `%3D` not bound to the body → unsubscribe anyone — shbugger1 ($200) [DUP reinforcement: base64-JSON ref + unvalidated token]
- Where: email unsubscribe link = `base64(JSON{"user_id":...,"preference":...})%3D` + a separate token.
- Approach/how-found: decoded the base64 JSON, changed `user_id`, re-encoded → unsubscribe any user; the trailing token wasn't validated against the modified body.
- Test: decode every base64/JWT-ish blob in emails/links; if it contains a `user_id`/`preference`, swap and re-encode — and check whether an accompanying token is actually bound to the payload.
- Q: "Is the unsubscribe blob base64-JSON with a `user_id` I can swap, and is the accompanying token bound to the payload or ignored?"

### [104] Base64-encoded numeric id + hidden client-side PII — Graham Zemel ($750+) [DUP reinforcement: decode-decrement-reencode + read full response]
- Where: `?id=MjQzNDU%3D` = URL-encoded base64 of `24345`.
- Approach/how-found: URL-decode → base64-decode → `24345`; decrement to `24344`, re-encode (`MjQzNDQ%3D`) → another user's record. The rendered HTML showed only a name, but the **page source/client-side data** held full PII (name, email, phone, DOB). 20-line parser to automate.
- Test: `%`-containing ids are encoded — URL+base64 decode, change the number, re-encode. Always read the full response/page source, not just rendered text — apps hydrate client-side state with far more PII than they display.
- Q: "Is the id base64-of-a-number I can decrement and re-encode? Does the raw response/page source contain PII beyond what's rendered?"
