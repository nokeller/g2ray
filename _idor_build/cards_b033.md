### [139] Apple email-verification bypass — replace the opaque token in the verify link with your plaintext email — Aravind [DUP reinforcement: verification keyed by swappable email]
- Where: subdomain email-verification link with `email id=<opaque string>`.
- Approach/how-found: replaced the opaque `id` string with the literal email (`abc@gmail.com`) → verification passed / signup completed without truly verifying.
- Test: in verify/confirm links, try replacing the opaque token with the plaintext email/username — some flows accept the identifier directly and skip token validation.
- Q: "Does the verification link accept my plaintext email in place of the opaque token (skipping real verification)?"

### [140] Admin↔admin change-password IDOR — defeat `412 Precondition Failed` by swapping the id across the full OPTIONS/GET/PATCH sequence (fresh ETag) — dhakal_bibek ($2,000) [NEW ★ ETag/If-Match conditional-header IDOR technique]
- Where: `PATCH /api/v3/myhealth/users/<id>` `{password}` (old password not validated); two admins.
- Approach/how-found: swapping the victim admin's id in Repeater → `412 Precondition Failed` because the request carries conditional headers (`If-Match`/`If-None-Match` ETag) tied to the object. Fix: swap the id in the live **intercept across all three requests** (OPTIONS → GET → PATCH) so the GET fetches the victim's *current* ETag that the PATCH's `If-Match` then satisfies → password changed → ATO of the other admin. (Tools: Autorize, PWNfox for Firefox containers, Crane for iOS app containers; same-role access control is often overlooked.)
- Test: a `412` on id-swap means an ETag/`If-Match` is bound to the object — replay the *whole* conditional sequence (OPTIONS/GET/PATCH) with the swapped id via intercept so the GET supplies the matching ETag. Always test access control between same-role users (admin↔admin), and whether change-password validates the old password.
- Q: "Did a 412/precondition error stop me? Can I swap the id through the full OPTIONS/GET/PATCH flow so the GET fetches the victim's ETag for the PATCH? Is there access control between same-role users, and is the old password checked?"
