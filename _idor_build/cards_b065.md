### [386] Change anyone's profile picture: upload reveals your `id` (84) in the request; victim is 85; re-upload with `id=85` → victim's avatar replaced — Rupika Luhach (Bugdiscover) [DUP-reinforce: learn your id from your own write, then ±1 to hit neighbors]
- Where: profile-image upload request, `id` parameter (sequential).
- Approach/how-found: uploaded his own photo to observe the assigned `id` (84), inferred the victim's (85), re-sent the upload with `id=85` → changed the victim's picture.
- Test: do a write on your own object to learn the id format/value, then ±1 to act on adjacent users; upload/replace endpoints often trust a client-supplied owner id.
- Q: "Does my own upload expose my numeric id? Does the upload trust a client `id` I can change to a neighbor's?"

### [387] Uklon (HackenProof) — driver-image IDOR by `uid` (edit/delete/upload any driver's avatar, type `driveravatar`); feedback IDOR by SEQUENTIAL id (`PUT /api/v1/feedbacks`, `GET /api/v1/drivers/<id>/feedbacks`) → edit/delete any driver's reviews, `id+1` sweep deletes ALL reviews → manipulate competitor ratings — multiple researchers [NEW: business-impact framing — rewrite competitors' reviews]
- Where: driver avatar endpoint (`uid`); `/api/v1/feedbacks` (sequential id); `/api/v1/drivers/<driverId>/feedbacks`.
- Approach/how-found: the avatar action keyed on a driver `uid` with no ownership check (edit/delete/upload anyone's). Feedback ids were a simple increment → edit/delete any comment; a competitor driver could swap positive↔negative reviews and wipe all feedback by enumerating ids.
- Test: marketplace/gig apps — driver/vendor objects (avatar, feedback, ratings) keyed on uid/sequential id; frame impact as competitive sabotage (rewrite/delete rivals' reviews), not just data access.
- Q: "Can one vendor/driver edit or delete another's reviews/avatar by swapping the uid/feedback id? Are feedback ids sequential (mass-delete)?"

### [389] CRM — invitation IDOR → ATO chain: `POST /invitations/<id>/resend` returns the invitee email in JSON and id is sequential (enumerate other companies' invited emails); then register with a leaked email → app shows "Company X invited you, click resend" → the resend URL uses `resend_invitation` while the real accept link uses `join` → swap `resend_invitation`→`join` in the URL → joined the victim org — Plenum [NEW ★ email-leak IDOR + URL-VERB swap to self-accept an invitation → ATO]
- Where: `POST /invitations/<seq-id>/resend` (leaks email); accept URL path segment `resend_invitation` vs `join`.
- Approach/how-found: the unguessable 32-byte invite token seemed safe, but resend leaked the email by sequential invitation id. Registering with a leaked email surfaced a page whose "resend" link differed from the emailed "join" link only by a path word; changing `resend_invitation`→`join` accepted the invite without the token → org access/ATO.
- Test: even with strong invite tokens, the resend/status endpoint may leak the email by sequential id; compare the on-screen action URL to the emailed link — swapping a path verb (`resend`→`join`/`confirm`/`accept`) can self-accept without the secret token.
- Q: "Does resend/status leak the invitee email by enumerable id? Can I change a URL verb (resend→join/accept) to accept an invitation without the emailed token?"
