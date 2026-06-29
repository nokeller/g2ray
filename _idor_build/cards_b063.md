### [371] AntiHack — create submissions on ANY program (even LOCKED) via `comp_id` swap: generate comp_ids, Intruder the create-submission request → bypass program lock — Syahrul Akbar [DUP-reinforce: create-action IDOR bypasses an access restriction, not just reads]
- Where: create-submission POST, `comp_id` parameter.
- Approach/how-found: intercepted "create submission", found `comp_id`; generated a list of ids and Intruder'd → created submissions against programs he wasn't allowed into, including locked ones.
- Test: "create/submit/join" actions keyed on a container id (`comp_id`/`program_id`) — swap to act on restricted/locked/private containers; access restrictions enforced only in the UI are bypassable via the raw request.
- Q: "Can I create/submit into a locked/private container by swapping its id in the create request? Is the lock enforced server-side or only in the UI?"

### [372] Privilege escalation to SUPERUSER: admin "create user" POST takes `roleId`; admin may only create moderator(3)/vendor(4), but sending `roleId=1` created an account ABOVE admin; then EVERY admin endpoint (`PUT /admin/role-permissions`, `GET /users/<id>`) is callable by low-priv users with their own session — Gaurav Narwani [NEW ★ role mass-assignment beyond your grant + function-level authz missing everywhere]
- Where: admin create-user POST (`roleId`); `PUT /admin/role-permissions` (`{roleId,permissionId}`); `GET /users/<id>`.
- Approach/how-found: the create-user form only let admin pick roles 3/4; tampering `roleId` to 1 minted a superuser (more than admin). Then he replayed admin-only endpoints as moderator/vendor sessions — none checked function-level authz → low-priv users could add/delete roles, grant permissions, and read any user by id.
- Test: in role-bearing create/update requests, set the role to values OUTSIDE your allowed set (1/0/superadmin); after finding one privesc, replay ALL privileged endpoints with a LOW-priv session to map function-level authz gaps (vertical IDOR).
- Q: "Can I assign myself a role higher than the UI offers (roleId=1)? Do privileged endpoints check the caller's role, or just that the request is well-formed? Which admin actions work with my low-priv session?"

### [379] Facebook Workplace — logo id → owner name via object type-confusion: upload an event cover picture, then replace its `fbid` with another workplace's LOGO id → response leaks that workplace's owner/admin name — Ajay Gautam [NEW: feed an id of type A into a context expecting type B to leak its metadata]
- Where: event cover-picture object URL, `fbid` parameter set to a foreign workplace-logo id.
- Approach/how-found: a workplace logo's id is the admin's id; he created an event, uploaded a cover photo, then swapped the photo `fbid` to another workplace's logo id → the rendering exposed the owner's name.
- Test: swap object ids ACROSS types (photo↔logo↔video↔doc) — a viewer for type A may resolve a type-B id and leak its owner/metadata; ids that "are" a user (logo=admin id) leak identity.
- Q: "Can I put a different object-type's id into this viewer to leak its owner/metadata? Is any id actually a user/admin id in disguise?"

### [380] OTP/verification-code disclosure via `customerID` swap: signup verification page has `customerID` in URL; the RESEND-code request returns the confirmation code in its response, and is keyed only on `customerID` (poorly serialized → direct object) → change 6204→6203 to read other users' OTPs — vulnerables [NEW ★ resend-OTP response leaks the code; swap the account id]
- Where: signup "resend code" request, `customerID` only → response contains the code.
- Approach/how-found: the verify page carried `customerID`; the resend-code request (just `customerID`) returned the confirmation code in its RESPONSE; since the value maps directly to the account object, swapping `customerID` exposed other users' verification codes.
- Test: OTP/verify/resend endpoints sometimes return the code in the response body — check; if keyed on a swappable account/customer id, you can read others' codes (→ account creation/ATO).
- Q: "Does the send/resend-OTP response leak the code itself? Is it keyed on a swappable customer/account id I can decrement to read other users' codes?"

### [381] Vine/Twitter — harvest any user's IP via reposted-vine id: endpoint returns `ipAddress` as a DECIMAL/long (e.g. 2130706433 = 127.0.0.1); copy a reposted vine's POST id into the endpoint → decode the decimal → real IP — Prial ($5,040) [NEW: sensitive field present but encoded (decimal IP); object referenced by repost id]
- Where: vine detail endpoint keyed on a (reposted) post id; response field `ipAddress` in decimal form.
- Approach/how-found: the response held `ipAddress` as a long integer; converting decimal→dotted-quad gave the poster's real IP. Any reposted vine's id worked → harvest many users' IPs. (Companion to his earlier $7,560 PII leak.)
- Test: scan API responses for sensitive fields in non-obvious encodings (decimal/long IPs, base64, epoch); object ids harvested from public reposts/shares feed the lookup.
- Q: "Does the response contain sensitive data in an encoded form (decimal IP, base64)? Can I source object ids from public reposts/shares to enumerate users?"
