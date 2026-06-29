### [23] Facebook Help Community — delete ANY user's image via `attachment={"fbid":<id>}` IDOR in `POST /help/community/async/post_answer/`; derive the victim fbid from the CDN URL by a constant offset — Sarmad Hassan ($1,500) [NEW ★ id-derivation: fbid = (number between underscores in the CDN filename) − 3,333,333]
- Where: `POST /help/community/async/post_answer/?question_id=...` body `attachment={"fbid":<imageId>}`; delete the answer to delete the referenced image.
- Approach/how-found: the answer-with-image request referenced the image only by `fbid`; swapping it to a victim's image fbid and then deleting your answer deleted the victim's image (shared fbid, no ownership check). To get a victim's fbid he used "Max Pasqua's method": take the CDN URL, read the second number between underscores in the filename, subtract a constant `3333333` → the real fbid.
- Test: when a media object is referenced by an opaque id you "can't guess", check if that id is derivable from a public artifact (CDN filename, thumbnail URL, embed code) via a fixed transform/offset. Destructive actions that bind an attachment by id without ownership are deletion IDORs.
- Q: "Can I derive the 'unguessable' media id from its public CDN/thumbnail URL (a constant offset/encoded segment)? Does deleting my container delete a foreign attachment I referenced by id?"

### [24] Facebook Workplace — disclose any video's thumbnail via `video_id` IDOR in the Canvas builder upload; "send canvas to mobile preview" to render it — Sarmad Hassan ($3,000) [NEW: builder/canvas component fetches media by id; preview channel renders the foreign object]
- Where: Page → Publishing Tools → Canvas → add Video; `POST /v2.11/<pageId>?access_token=...` body `...&video_id=<id>` (`reqName=object:canvas_video`).
- Approach/how-found: the canvas video component accepted an arbitrary `video_id`; swapping it to a victim's Workplace video id and using "Preview on mobile" rendered the victim's thumbnail (the mobile-preview path bypassed the on-page restriction).
- Test: page/ad/canvas/story BUILDERS let you embed an object by id — swap it to a foreign id; if the inline render is blocked, use an alternate render path (mobile preview, export, share) to surface the data.
- Q: "Does this builder component embed media by a swappable `video_id`/`media_id`? If inline render is blocked, does preview/export/share render the foreign object anyway?"

### [27] Facebook Messenger — disclose ANY private attachment via `image_ids[0]`/`file_id[0]`/`video_id[0]`/`audio_id[0]` IDOR in `POST /messaging/send/` (brute-forceable) — Sarmad Hassan ($15,000) [DUP-reinforce: send-message attachment id params reference foreign private media across FB/Messenger/Workplace/Portal]
- Where: `POST /messaging/send/` body `has_attachment=true&image_ids[0]=<id>` (and `file_id[0]`,`video_id[0]`,`audio_id[0]`).
- Approach/how-found: sending a message with your own attachment, then swapping the attachment id to a victim's, made the server attach/disclose the victim's private media — the send endpoint never checked you owned the referenced attachment. Works for every attachment type and is brute-forceable.
- Test: messaging/compose endpoints attach media by id; swap the attachment-id arrays to foreign ids to leak private files. Test EVERY media-type param (image/file/video/audio) — each may be independently unguarded.
- Q: "Does composing/sending a message let me reference (and thereby disclose) an attachment id I don't own? Are all attachment-type params (image/file/video/audio) equally unchecked?"

### [181] Massive ATO — default test phone numbers (`9999999999`,`8888888888`…) accept ANY OTP, and the signup endpoint's `uid` param is IDOR → log into any account by phone; no rate limit → brute — Anurag Verma [NEW ★ dev OTP-bypass backdoor left in prod + `uid`-swap login-as-victim]
- Where: phone-login app; signup `POST` carrying `mobileNo`, `uid`, `socialMediaId`; response `{isExistingUser, message:"Login Successful"}`.
- Approach/how-found: noticed repdigit phone numbers (`9999999999`…`1111111111`) logged in with ANY OTP — leftover dev/test accounts (with employee PII). Then analyzed the signup request's params; swapping `uid` to a victim's value returned `isExistingUser:true` + "Login Successful" → full ATO by phone number alone. Phones harvested via Google/GitHub/LinkedIn dorks; no rate limit on signup → Intruder over numbers filtering `isExistingUser=true`.
- Test: try repdigit/sequential "test" phone numbers/emails with any OTP (dev backdoors). On signup/login responses, swap identity params (`uid`,`userId`) and watch for a "login successful"/session in the response — auth flows sometimes authenticate the supplied id, not the verified one.
- Q: "Do test/default phone numbers accept any OTP? Does the signup/login endpoint trust a `uid`/`userId` param so I can log in as a victim by swapping it? Is there rate-limiting to stop phone enumeration?"

### [238] YouTube — recover a video's HIDDEN dislike count from `averageRating` via `POST /youtubei/v1/player` `videoId=<victim>`: rating + known likes → solve for dislikes — Alessandro Rumampuk (Google VRP) [DUP-reinforce of the YouTube hidden-metric family: a computed field leaks the hidden one]
- Where: `POST /youtubei/v1/player?key=...` body `videoId:<victim_video_id>`; response `averageRating` (1–5 scale).
- Approach/how-found: even with dislikes hidden, the player endpoint returned `averageRating` for any video id; since rating is a function of likes:dislikes, knowing the (visible) like count lets you algebraically recover the hidden dislike count.
- Test: hidden counts can be reconstructed from any DERIVED/aggregate value the API still exposes (average, ratio, percentage, rank, total). Don't only look for the raw field — look for math that reveals it.
- Q: "Is there an average/ratio/percentage/total that, combined with a visible value, lets me compute the field that's supposed to be hidden?"

### [336] Facebook — remove ANY user's profile picture via GraphQL `profile_picture_remove` mutation: `profile_id` accepts a user id (mutation meant for pages) — Philippe Harewood ($2,500) [DUP-reinforce: GraphQL mutation's `profile_id`/`actor_id` unvalidated + page→user type-confusion]
- Where: `POST /graphql` `Mutation{profile_picture_remove}` with `query_params={input:{profile_id:<victim>,actor_id:<attacker>,client_mutation_id:0}}`.
- Approach/how-found: a new (FB5) mutation removed a page's profile picture; changing `profile_id` to any user id dissociated that user's profile picture (the mutation didn't verify the id was a page the actor controlled). Non-destructive-ish (original photo recoverable) but clearly cross-user.
- Test: GraphQL mutations are write-IDOR targets — swap `*_id`/`actor_id`/`input.id` to a victim and test object-type confusion (a page-scoped mutation accepting a user id). Newly shipped mutations (post-redesign) are under-tested.
- Q: "Does this mutation validate that `profile_id`/`actor_id` belongs to me and is the right object type, or will it act on any id I pass?"

### [445] Terapeak — IDOR via per-user `token` in the URL: `PUT /services/users/information?token=<victim_token>` edits any user's info / deletes saved searches; writing into the profile yields stored XSS in their account — Shubham Gupta ($5,000) [NEW ★ the URL `token` IS the object ref; profile-write IDOR → stored XSS "into anyone's account"]
- Where: `PUT /services/users/information?token=<TOKEN>` (and DELETE for saved searches); body `{"firstName":...,"type":"userDetail"}`.
- Approach/how-found: the per-user `token` in the query string was the object reference; swapping it let him edit another user's information and delete their saved bulk searches. Because the written name field rendered unsanitized in the victim's UI, the IDOR became a vector to plant stored XSS into any account.
- Test: treat per-user `token`/`key`/`hash` values in URLs as object refs, not auth — swap them. A profile-field write IDOR is also an XSS delivery mechanism into the victim's session (self-XSS → stored-on-victim).
- Q: "Is the `token`/`key` in this URL an authenticator or just an object id I can swap? If I can write a victim's profile field, does it render unsanitized in their session (stored XSS)?"

### [446] Terapeak — cancel/edit/add ANY user's subscription via `email` in the body: `PUT /svc/cancel_subscription` `{"email":"<victim>","zuoraSubscriptionId":...}` — Shubham Gupta [DUP-reinforce: billing action keyed on a body `email`, not the session identity]
- Where: `PUT /svc/cancel_subscription` body `{"email":"victim@x","productName":...,"zuoraSubscriptionId":"2039653",...}`.
- Approach/how-found: the subscription cancel/edit/add actions identified the target by the `email` field in the JSON body; swapping it to a victim's email cancelled (or modified) their paid subscription — no check that the email matched the session.
- Test: billing/subscription/plan actions often carry the account identifier (`email`,`customerId`,`subscriptionId`) in the body — swap it to a victim's to cancel/modify/add their plan. The session should determine the target, not a body field.
- Q: "Does this subscription/billing action target whoever the `email`/`customerId` in the body says, instead of my session? Can I cancel or change another user's plan by swapping it?"
