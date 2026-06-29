### [168] Meta — trim ANY private live video by known `video_id` → trim mutation regenerates a NEW video id → second GraphQL returns its CDN link — abdellah yaala ($7,500) [NEW ★ derivative-object IDOR: transform a private object into a new readable one]
- Where: `business.facebook.com POST /api/graphql/`; mutation `doc_id=3859231820860792` (trim by `video_id`), then `doc_id=3561288230642336` (video_id→CDN).
- Approach/how-found: with a victim's private live `video_id`, the trim mutation (with attacker `actor_id`/page) trims 15s and **regenerates a new video id**; a second GraphQL call resolves that new id to a CDN URL → watch the private video.
- Test: "transform/edit" operations (trim, crop, convert, thumbnail, re-encode, export) that accept a target object id often emit a NEW derivative object you own/can read — bypassing the original's ACL. Hunt operations that regenerate ids, then resolve the new id.
- Q: "Can a transform/edit mutation on someone's private media produce a new derivative object (new id/CDN link) I can read, sidestepping the original ACL?"

### [170] Two-bug ATO — API IDOR (`POST /Account?handler=GetUserData`, id in body) leaks victim ids; client posts a session object (id/rights/perms) the server trusts → swap → full ATO — Kwadwo Amoako [NEW ★ client identity-object replay]
- Where: `POST /xyz.com/Account?handler=GetUserData` (id in POST body); client-side "User Account" JS holds a session object {id, rights, permissions} posted back to the API as the identity.
- Approach/how-found: IDOR #1 — swap id in the GetUserData body → victim data (incl. their ids). Static JS review revealed the account page sends a **client-held session object** (id + rights + perms) to the API as the source of truth. Reload account page, intercept, replace own ids with victim's → full account access → changed victim's password.
- Test: read client JS for an identity/session object (id, role, permissions) that's POSTed back and trusted server-side; swap its id to impersonate. Pair a data-leak IDOR (to harvest victim ids) with this identity replay = ATO. Static code analysis surfaces these.
- Q: "Does the client send back an identity object (id/rights/perms) the server trusts as 'who I am'? Can I swap it (using ids from an IDOR) to fully impersonate?"

### [173] E-commerce — order/invoice fetch by sequential number leaks PII + payment-receipt image; reset response leaks a usable token (≠ email token) → chain to ATO — Damaidec (P1-ish) [NEW: invoice IDOR + reset-token-in-response]
- Where: order-history item fetch `.../item/{n}` (sequential); password-reset flow (token leaked in HTTP response, distinct from the email token but accepted); admin panel also leaks token.
- Approach/how-found: post-purchase "view order" fetched an item by sequential number → swap → other customers' PII (billing, receipt) incl. the payment-receipt image URL. Reset flow returned a token in the Burp response that still completed the password change → reset bypass. Combining the email-leaking IDOR with the reset-token leak → ATO.
- Test: order/invoice/receipt views keyed by sequential ids leak full PII + receipt-image links. On reset, diff the token in the HTTP response vs the email — if the response token is accepted, it's a bypass; chain with an email-IDOR for ATO.
- Q: "Does the invoice/order endpoint leak PII + receipt image by sequential id? Does the reset HTTP response leak a usable token? Can I chain email-IDOR + reset-token leak into ATO?"

### [174] XSS filter evasion + IDOR — stored XSS and IDOR on the same `customerID` endpoint; IDOR is the delivery vehicle for the payload to victims — systemweakness ($800) [DUP reinforcement: IDOR delivers XSS; filter-break technique]
- Where: a customer endpoint vulnerable to BOTH IDOR (customerID) and stored XSS.
- Approach/how-found: stored XSS landed via filter evasion: `" onf<x>ocus="alert(document['cookie'])" autofocus">` (junk `<x>` splits the blocked `onfocus`; `autofocus` = zero interaction). Since other customerIDs can't be guessed, the IDOR provides delivery — create a customer object carrying the payload, share its (IDOR-reachable) link → executes in the victim's browser → ATO/data theft.
- Test: when XSS needs a victim to view attacker data, an IDOR-reachable shared object is the carrier. Defeat keyword filters by splitting the handler with a junk tag (`onf<x>ocus`) and trigger with `autofocus`/`onerror` for zero-click.
- Q: "Can an IDOR-reachable object carry my stored-XSS to a victim? Can I evade the filter by splitting the event handler with a junk tag and fire it via autofocus?"

### [175] Instagram Shop — `merchant_id` in the "send invoice" DM controls the displayed seller identity → swap to any (verified) account = brand/identity spoof for scams — Nawaf Alkhaldi ($1,000) [NEW ★ IDOR as identity spoofing, not data read]
- Where: Instagram DM "shops send invoice to customer" feature; request `merchant_id` determines the seller username/avatar shown.
- Approach/how-found: the displayed seller identity is taken from a client-supplied `merchant_id`, not the authenticated sender. Swap it to any user id (e.g., @Instagram verified) → the recipient sees an order/invoice "from @Instagram ✓" though it came from the attacker → high-impact phishing.
- Test: wherever a message/invoice/notification/order renders a sender/seller/brand identity, check if that identity comes from a client-supplied id you can swap → impersonation (impact is trust/phishing even with no data read).
- Q: "Is the displayed sender/seller/owner identity derived from a client-supplied id rather than my session? Can I spoof a verified/brand account by swapping it?"

### [177] Small-scope target — fuzz Seclists + inspect EVERY request → `/endpoint/{id}/info` (signup id) → Intruder leaks others' ID, auth_details, org name, private subdomain info — annonymous [DUP reinforcement: per-account /{id}/info exposes infra metadata]
- Where: `/endpoint/{id}/info` keyed by the unique id assigned at signup.
- Approach/how-found: small scope → fuzz wordlists + manually capture/inspect all requests. The per-account info endpoint keyed by the signup id → Intruder sniper over id → other users' ID, auth_details, Org_name, and private subdomain info.
- Test: on small-scope targets, replay every captured request manually; "/{id}/info" account endpoints frequently expose auth/org/infrastructure metadata, not just profile fields. Miss no endpoint.
- Q: "Is there an `/{id}/info` account endpoint returning auth/org/infra metadata when I swap the id? Have I manually reviewed every request, not just the obvious ones?"

### [178] Zero-click ATO chain — PII IDOR dismissed "can't get the id" → JS link-finder reveals a bulk-id-listing endpoint → a `PushToken` endpoint returns resetToken by UserID → ATO of every user — Veshraj Ghimire [NEW ★ defeat the id-source objection via JS + token-leaking endpoint]
- Where: `/api/Customer/GetAdditional?customerId=` (PII), `/api/AdditionalCustomerFields` (dumps ALL UserIDs, found via BurpJSLinkFinder), `/api/PushToken` (UserID → passwordHash + resetToken).
- Approach/how-found: the PII IDOR was closed informative because he couldn't obtain other UserIDs. He didn't give up — BurpJSLinkFinder surfaced a JS endpoint that lists every customer's UserID (defeats the "how would you get the id?" objection → reopened High). Digging more, `PushToken` returned a reset token by UserID with no authz. Chain: list UserIDs → get email → trigger reset → read resetToken via PushToken → take over any account, zero-click.
- Test: when an IDOR is closed "can't obtain the id," mine JS (BurpJSLinkFinder/LinkFinder) for a list/enumerate endpoint that dumps all ids. Hunt endpoints returning reset tokens / password hashes by user id — they upgrade any IDOR to ATO.
- Q: "Is there a JS-referenced endpoint that enumerates all object ids (killing the id-source objection)? Does any endpoint return a reset token / password hash keyed by a user id I control?"
