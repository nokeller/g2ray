### [418] Password reset via base64(email) link + OSINT emails: the reset link is just `base64(email--company)/base64(timestamp--company)` with no real token; harvest valid user emails from the company's Facebook-page comments → forge reset links → ATO — Dr. Gupta [DUP-reinforce: reset token is decodable/forgeable email; source victim emails via OSINT]
- Where: reset URL = base64(email) + base64(timestamp); same scheme as the signup verify link.
- Approach/how-found: Burp-decoded the reset link → it only encoded the email + timestamp (and company name), no signed token; the signup verification link used the same scheme. So any email → forge the reset link. Valid emails were public in the company's Facebook page comments.
- Test: decode base64/hex/JWT in reset & verify links — if they only wrap email+timestamp with no signature, forge them; harvest target emails from social comments, breach dumps, `site:` dorks.
- Q: "Is the reset/verify link a forgeable encoding of email+timestamp (no signature)? Where can I source valid victim emails (social comments, dorks)?"

### [419] Currency exchange — STATIC reset token: the password-reset hash is identical for every request AND every account → just open the reset form (new/confirm password) for any account, including admin → ATO — Aayush Pokhrel [NEW ★ the "reset token" is a constant, reused across all users]
- Where: password-reset completion form; reset hash is constant.
- Approach/how-found: requested reset twice → identical hash; requested for a different account → STILL the same hash. The token was a fixed constant, so the reset form worked for any account → reset admin's password → admin ATO.
- Test: request a reset several times and for several accounts and COMPARE the tokens — if the token is static/repeating (or predictable), you can complete anyone's reset; try the reset form directly with the known constant.
- Q: "Is the reset token actually unique per request/account, or is it static/repeating? Does the same token complete a reset for a different account (incl. admin)?"

### [420] Facebook Workplace — disclose a private video thumbnail via CANVAS `video_id` swap + send-to-phone bypass: the page CANVAS edit request carries `video_id`; swap to any public/friends-only/Workplace-PRIVATE video id → it loads into your canvas; preview is blocked, but "send canvas preview to your phone" renders the thumbnail of the private Workplace video — Sarmad Hassan ($3,000) [NEW ★ media_id swap across product (Workplace) + alternate render channel to bypass a preview block]
- Where: `POST /v2.11/<page_id>` CANVAS edit, `video_id`; "send canvas to phone" preview channel.
- Approach/how-found: the canvas video element keyed on `video_id`; swapping it embedded others' videos (incl. Workplace posts, which are private to a company). Web preview just showed a spinner (blocked), but sending the canvas preview to his phone rendered the thumbnail → leaked private Workplace video content.
- Test: media/content-id IDORs that "don't preview" on web may render through an ALTERNATE channel (mobile preview, email, PDF/export, oEmbed) — try those; the same id often reaches private cross-product content (Workplace/Groups).
- Q: "Does a media_id swap pull private/cross-product content? If web preview is blocked, does an alternate render channel (mobile/email/export) show it (even just a thumbnail)?"

### [421] Newsletter — confirm anyone's subscription without consent: the confirmation email link splits into endpoint+action+`data`(token); the token isn't bound to the requester → reuse/tamper to confirm-subscribe arbitrary emails — Mohammed Israil (bof.nl) [NEW: opt-in confirmation link not bound to the subscriber → forced subscription]
- Where: newsletter confirmation link (`endpoint`/`action`/`data` token).
- Approach/how-found: the confirm link's token wasn't tied to who requested it, so the confirmation step could be driven for other addresses → activate subscriptions without the user's knowledge (spam/annoyance, and a building block for trust abuse).
- Test: double-opt-in confirm links — check whether the token is bound to the specific email/session or reusable/forgeable to confirm others; same pattern applies to verify/accept/opt-in flows.
- Q: "Is the confirm/opt-in token bound to the requester, or can I confirm subscriptions/actions for other emails? Is it forgeable?"
