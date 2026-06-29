### [116] CMS-delete + user-delete IDOR — GET is protected but DELETE/PUT aren't; test every HTTP method on the id — jedus0r (P1) [NEW: write verb unprotected where read is]
- Where: `/api/v1/cms/<id>` and `/api/v1/users/<id>`.
- Approach/how-found: `PUT /api/v1/cms/419` → 200 (edit others' CMS); `DELETE` → deletes any customer's CMS (P3). On users, `GET /api/v1/users/<other>` → 403 (read protected!), but `DELETE /api/v1/users/<other>` → 200 → delete any user (PII exposed in the flow) = P1, mass user wipe.
- Test: never conclude "no IDOR" from a blocked GET — replay the same id with PUT/DELETE/PATCH; authz is frequently enforced only on the read path. Map identity (numeric id), send all id-bearing calls to Repeater, method-fuzz each.
- Q: "Is GET protected but DELETE/PUT/PATCH on the same id unprotected? Did I method-fuzz every id-bearing endpoint, not just read it?"

### [117] IDOR `building_id` → visitor PII → image `?url=` proxy → redirect-bypassed SSRF → AWS IMDS keys → SSM RCE — 0x0Asif ($3,200) [NEW ★ IDOR→SSRF→AWS SSM RCE chain]
- Where: `GET /visitors/?...&building_id=1266` (numeric IDOR → all visitors' PII+photos); visitor images served via an `?url=` proxy (S3).
- Approach/how-found: swap `building_id` → mass visitor PII. The image `?url=` only allowed the index page → he hosted a `header('Location: http://169.254.169.254/...',303)` redirect → the proxy followed it → full-read SSRF → AWS instance metadata → IAM access/secret/session keys → AWS CLI → `aws ssm describe-instance-information` then `aws ssm send-command --document-name AWS-RunShellScript` → RCE across instances.
- Test: an `?url=`/image-proxy that "only allows X" can be bypassed with a 30x redirect from your server; once SSRF reaches IMDS, pull IAM creds and try `ssm send-command` for RCE. Pair an IDOR (mass PII) with any url-fetcher in the same data.
- Q: "Is there a `url`/image-proxy param I can point at 169.254.169.254 (via redirect bypass)? Do leaked IAM creds allow `ssm send-command` (RCE)?"

### [119] Two-step login — username-check response leaks full PII (user-enumeration → PII oracle) — Eslam Akl (P1) [NEW: login step-1 as PII oracle]
- Where: username-first login; submitting a username (before password) returns whether it exists.
- Approach/how-found: entering `test` returned an existing user AND all their PII (name, email, phone, firm, userID) in the response → Intruder a username wordlist → mass PII. No throttling.
- Test: in multi-step logins (username then password), inspect the username-validation response — it often returns far more than `exists:true` (PII, userID); enumerate usernames to harvest it.
- Q: "Does the username/identifier step of login leak PII or userID in its response? Can I enumerate usernames to harvest it at scale?"

### [120] Unsubscribe IDOR via `id`; `?u=` base64 timestamp required but not validated; userID from a leaky profile API — Sagar Sajeev [DUP reinforcement: unsubscribe id-swap + chained id leak]
- Where: unsubscribe link `?u=<base64 timestamp>&id=<userID>`.
- Approach/how-found: `?u=` is a base64 timestamp (must be present or 400, value not validated); swap `id` to the victim's → unsubscribe anyone. UserID is leaked by a profile API → chained to identify victims.
- Test: unsubscribe/notification links keyed by a user `id` with an unbound timestamp/token = IDOR; chain a profile/API that leaks userID to raise severity.
- Q: "Is the unsubscribe link keyed by a swappable `id` with an unvalidated timestamp, and can I source userIDs from a profile API?"
