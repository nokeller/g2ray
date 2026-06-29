### [74] IDOR in browser sessionStorage `user_id` (trusted client-side identity) — Jerry Shah [NEW: client-storage identity trust]
- Where: balance/account page reads `user_id` from sessionStorage.
- Approach/how-found: DevTools → Application → Session Storage → change `user_id` to the victim's → reload → you're in the victim's account (manipulate funds). Horizontal (sometimes vertical) privesc. Changes are session-scoped (revert on browser close) but impact while live is the same.
- Test: inspect localStorage/sessionStorage/IndexedDB for `user_id`/`role`/`accountId` the app trusts as identity; edit and reload. Combine with cookie/JWT/body id swaps — the app may trust any of these stores.
- Q: "Does the app read identity (`user_id`/`role`) from sessionStorage/localStorage and trust it on reload? What happens if I edit it to a victim's id?"

### [78] chatId IDOR + derive chatId from a leaked `messageId` via fixed byte offset → read all chats — Abhisek R ($900) [NEW ★ break the id↔id relationship; sibling endpoint leaks the related id]
- Where: `POST /get-messages` body `chatId` (anti-CSRF header present → not CSRF, but IDOR-able).
- Approach/how-found: a dummy account's `chatId` swapped in → info disclosure (IDOR confirmed). Couldn't enumerate `chatId` directly. Found a `messageId` param + an endpoint leaking `messageId`s for many users; the `messageId`↔`chatId` relationship was a **fixed byte increment** → compute every chatId from leaked messageIds → read all users' private messages.
- Test: when the target id is unguessable, find a related id you *can* leak/enumerate (messageId/orderId/eventId) and test for a deterministic relationship (fixed offset/transform) to derive the target id. Note every id+endpoint as a lead.
- Q: "Is there a related id I can leak from a sibling endpoint, and is it a fixed transform away from the id I actually need?"
