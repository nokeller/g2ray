### [404] Facebook Messenger Rooms — non-admin can reject join requests: the reject-member endpoint (`thread_id`+`user_id`) never checks the caller is the room admin → any room member rejects pending users — Jafar Abo Nada [NEW: function-level authz missing on a moderation action (not id-swap, role-check absent)]
- Where: Messenger Rooms reject-member POST (`thread_id`, `user_id`).
- Approach/how-found: only the room admin should accept/reject; the reject endpoint authorized neither role nor ownership — as long as you were in the room you could set `thread_id`=target room, `user_id`=target user → reject them.
- Test: moderation/admin actions (accept/reject/kick/approve) — test them as a NON-privileged member; the server may check membership but not ROLE.
- Q: "Does this admin/moderator action verify my ROLE, or just that I'm in the room/group? Can a regular member perform it?"

### [405] Yahoo — delete any product comment: delete-comment request keyed on a comment `id`; swap from your id to another user's → their comment deleted — black_b [DUP-reinforce: destructive comment IDOR by id swap]
- Where: product-comment delete request, comment `id`.
- Approach/how-found: on a Yahoo product-reviews page, the delete action keyed only on the comment id; replacing his with another user's deleted theirs.
- Test: comment/review delete endpoints keyed on a comment id with no owner check → delete others' content.
- Q: "Can I delete another user's comment/review by swapping the comment id? Is ownership checked on delete?"

### [406] Food-delivery app — ATO chain: `/auth` returns `USER_ID`+`PHONE` even on FAILED login (info disclosure); `/otp` sends an OTP to any number; `/update` changes the phone keyed on `up_uid` (IDOR) → set `up_uid`=victim's USER_ID with your own OTP → victim's phone becomes attacker's → reset → ATO — s0cket7 [NEW ★ failed-auth response leaks USER_ID + phone-update IDOR via up_uid → ATO]
- Where: `POST /auth` (leaks USER_ID/PHONE on failure), `POST /otp` (send OTP to attacker number), `POST /update` (`up_uid`, `upvf_ph`, `upvf_pin`).
- Approach/how-found: a failed login still returned the account's USER_ID and phone. The phone-change verified an OTP, but the update request bound the change to a client-supplied `up_uid`; swapping it to a victim's USER_ID (from stage 1) while supplying an OTP sent to the attacker's own number updated the VICTIM's phone → password reset → ATO.
- Test: check auth responses on FAILURE for leaked ids/PII; phone/email-change flows that "verify an OTP" may still bind the update to a swappable user id — supply your own OTP but the victim's uid.
- Q: "Does a failed login leak USER_ID/phone? Does the verified phone/email update bind to a client `uid` I can swap? Can I verify with MY otp but change the VICTIM's contact?"
