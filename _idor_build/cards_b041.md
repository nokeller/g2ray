### [200] Change-password ATO — flip the RESPONSE "Incorrect Old Password"→"Success" to skip old-pw check; cookie holds a base64 user-number → enumerate → take over anyone — Sarvesh Salgaonkar [NEW: response-tamper bypass + enumerable id-in-cookie]
- Where: change-password flow (server returns incorrect/success); session cookie = value + base64-encoded user-number (non-expiring).
- Approach/how-found: entered a random old password, intercepted the RESPONSE, changed "Incorrect Old Password" to "Success" → app accepted it and changed the password (client trusts the response verdict). The cookie embedded a base64 user-number that's enumerable and the token didn't expire → swap it to any user → change their password = ATO.
- Test: on change-password / sensitive verifies, tamper the RESPONSE (failure→success) — many flows trust the client-side verdict. Decode session cookies for an embedded user id/number; if present and enumerable (and non-expiring), you can impersonate.
- Q: "Can I flip the verify response from failure to success to skip old-password checking? Does the cookie embed an enumerable (base64) user id, and is the token non-expiring/reusable?"

### [201] TikTok family-pairing — parental-control request has `child_user_id`; swap it → change ANY account's privacy/lives/comments/DM settings — s3c [NEW ★ guardian/delegate feature acts on a swappable controlled-user id]
- Where: TikTok family-pairing settings; params `restriction_type`, `restriction_value`, `child_user_id`.
- Approach/how-found: linked a parent+child pair; toggling the child's privacy generated a request with `child_user_id`; swapping it to any user id applied the restriction to that account → set anyone private, kill their lives/videos/comments/DMs.
- Test: parental/guardian/delegate/manager/"linked account" features act on a controlled-user id — swap it to any account. These complex backends are under-tested; the controlled-id is the IDOR knob.
- Q: "Does a parental/guardian/delegate feature act on a controlled-user id I can swap to change any account's settings? What sensitive toggles does it expose?"

### [202] Google Dialogflow CX — "random" testCase UUIDs are TEMPLATE-DERIVED: import the same prebuilt agent in two accounts → identical testCase ids, only `agent_id` differs (leaks via web-demo embed) → delete victim's test cases — Raidh ($3,133.70) [NEW ★ template-derived ids aren't random; Burp Comparer]
- Where: Dialogflow CX delete request `agents/{agent_id}/testCases/{testCase_id}` (two UUIDs).
- Approach/how-found: both ids looked unbruteforceable. Insight: import the SAME prebuilt/template agent in attacker AND victim accounts → the `testCase_id` is IDENTICAL (derived from the template). Burp Comparer showed only `agent_id` differs. The `agent_id` leaks via the web-demo integration JS snippet / share link → swap attacker→victim agent_id → delete the victim's test cases (all at once).
- Test: when an object id looks random, check if it's TEMPLATE-DERIVED — create the same prebuilt/template/sample object in two accounts and diff the ids (Burp Comparer); often only the container/parent id varies, and that leaks via embed snippets, share links, or docs.
- Q: "Are these 'random' ids actually template-derived (identical across accounts that imported the same template)? Does only the container id differ, and does it leak via an embed/share/demo snippet?"

### [203] IRCTC — Booked-Ticket-History `GET /historySearchByTxnId/{txnId}` is enumerable → millions of passengers' PNR/names/seat/age; same backend → cancel, change boarding, order food, book hotel/bus — Renganathan [DUP reinforcement: txn-id IDOR + shared-backend impact multiplier]
- Where: `GET /eticketing/protected/mapps1/historySearchByTxnId/{transactionId}?currentStatus=N`.
- Approach/how-found: the booking-history GET keyed on a transaction id; decrement it → a random user's full ticket + PII (PNR, passenger names, seat, gender, age). Since the same backend powers cancel/modify/order, those actions are equally unauthorized.
- Test: booking/order/transaction-history endpoints keyed by a txn id → decrement for others' records+PII; then enumerate the sibling actions (cancel/modify/order/refund) sharing that backend — they multiply impact from disclosure to account/financial actions.
- Q: "Is the transaction/booking id enumerable to read others' records+PII? Do cancel/modify/order/refund actions reuse the same unauthorized backend (escalating to control)?"

### [206] GraphQL `sendEmail` — object guarded by id+hash, but server validates ONLY the id (hash unchecked) → swap id to a neighbor's file, set your own `emails` → exfiltrate any file — Aidil Arief [NEW ★ hash/signature not actually validated + delivery-redirect]
- Where: GraphQL `mutation sendEmail($Id, $Hash, $emails)`; `Id` sequential, `Hash` unchecked, `emails` = delivery target.
- Approach/how-found: the design pairs a sequential `Id` with an "unguessable" `Hash` (looks IDOR-proof), but `sendEmail` only checks the `Id` and ignores the `Hash`. Swap `Id` to a neighbor's file (keep any hash), set `emails` to the attacker → the victim's file is emailed to the attacker.
- Test: when an object needs id+hash/signature/token, verify BOTH are actually validated — keep your own (or a wrong) hash and swap only the id. Any "delivery" field (emails/phone/webhook) lets you redirect the fetched object to yourself.
- Q: "Does the server actually validate the hash/signature, or only the id (so I swap the id and keep my hash)? Is there a delivery field (email/phone) I can point at myself to receive the victim's object?"

### [207] WeTransfer-like share — remove-file POST keyed by sequential `file_id`, no authz → delete anyone's file; escalated to logical DOS via a self-advancing brute range that deletes files as fast as users upload — Abhijeet Singh [NEW ★ IDOR→DOS chain (WAF-invisible)]
- Where: file-remove `POST` keyed by sequential `file_id` (returned at upload, visible in inspector).
- Approach/how-found: sequential file_id + no access control on delete → remove any user's file by id. Escalated severity: a Python script deletes file_ids in a window that auto-advances on each success → continuously wipes new uploads → service unusable, undetectable by WAF (requests look legitimate).
- Test: sequential ids on DELETE = cross-user destroy. Escalate to a logical DOS by continuously deleting newly-created ids in a moving window (chase the counter). Chaining IDOR→DOS upgrades High→Critical and evades WAFs.
- Q: "Is delete keyed by a sequential id with no authz? Can I escalate cross-user delete into a rolling DOS that wipes resources as fast as they're created (moving-window brute)?"

### [208] Dutch gov — subdomain fingerprinted as GitLab → known "User Information Disclosure via Open API" (`/api/v4/users/{id}`) discloses user 31; brute last digits → many users — Veshraj Ghimire (swag) [NEW: fingerprint product → apply its known id-based disclosure misconfig]
- Where: a `bkwi.nl` subdomain running GitLab; GitLab open users API `/api/v4/users/{id}`.
- Approach/how-found: subdomain enum → spotted GitLab → applied known GitLab misconfigs → the open users API disclosed user info by id; brute-forcing the trailing digits dumped many users.
- Test: fingerprint third-party products (GitLab, Jira, Jenkins, Grafana, etc.) on subdomains and apply their DOCUMENTED id-based info-disclosure endpoints (e.g. GitLab `/api/v4/users/{id}`, `/api/v4/projects`). Brute the numeric id.
- Q: "Is a known product (GitLab/Jira/etc.) on a subdomain exposing its documented id-based user/info API? Can I brute the id to enumerate users/projects?"
