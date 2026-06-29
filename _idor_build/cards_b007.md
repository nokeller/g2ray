### [39] Instagram — submit bug reports as any user via `user_identifier`; feature revealed by mobile emulation — Faizan Wani [NEW: device-emulation surfaces hidden features + spoofable actor id]
- Where: mobile-only "Report Bug" in profile settings; `POST graph.facebook.com` with `user_identifier` = profile id.
- Approach/how-found: noticed the app exposes more options on mobile than desktop → DevTools device toolbar → iPhone view unlocked "Report Bug"; its POST carries `user_identifier`; tamper to any user's id (read off their profile) → submit reports on their behalf.
- Test: toggle mobile/device emulation (and different app versions) to surface hidden features; any report/submit/feedback action carrying an actor/user id is spoofable.
- Q: "Did I check features that only appear under mobile/device emulation? Does a report/feedback/submit action carry a spoofable `user_identifier`/actor id?"

### [40] JS source review → shared web API key = no per-user authz on `/videos/<id>/cta`; private sticker view — Mohammed Waleed [NEW ★ shared API key + source-derived endpoints + method-from-presence]
- Where: React app; frontend downloaded via "Resources Saver"; an `api/` folder revealed endpoints.
- Approach/how-found: `/v1/videos/<video_id>/cta` required only `api_key=WEB_API_KEY` — identical for ALL users (verified across accounts) → add/delete a CTA link on ANY video with no per-user check (the client chose `method: ctaText ? 'put' : 'delete'`). `/v1/videos/<id>/associations` let any account view stickers on a private video.
- Test: download the SPA source (DevTools Sources / Resources Saver), enumerate the `api/` modules, test each endpoint. A single global/web API key shared by all users is not authorization — every id-keyed endpoint behind it is IDOR-able. Watch how the client derives the HTTP method from a field's presence.
- Q: "Is there a shared/global web API key all users get (not real auth)? What endpoints does the SPA source list that the UI never calls? Does the client pick PUT vs DELETE from a field's presence?"

### [42] CEO ATO via a reset-confirm page that lets you set target id (`u`) and drop expiry (`x`) — Cristi Vlad (pentest) [NEW: reset-confirm parameter tampering + locate id by decrement]
- Where: reset link → confirm page URL with `u` (numeric user id) + `x` (expiry token).
- Approach/how-found: removing `x` and refreshing still worked → expiry disabled (link reusable days later). Incrementing `u` showed *another user's* email on the page; he set `u` to a second account's id (exposed in Account Settings), set a new password → logged into that account. Decremented `u` to locate the CEO (ids near 551xxxxxxx, not 1). The reset string was "encrypted" but irrelevant once the user controls the URL params at the next step.
- Test: on the reset-confirm page, tamper each param — a numeric `u`/`id` selects whose password changes; an `x`/`exp`/`ts` often only enforces expiry (drop it to reuse). The shown email confirms the target before submit.
- Q: "On reset-confirm, does a `u`/`id` param choose the account (does the displayed email change when I swap it)? Does removing an expiry param make the link reusable?"
