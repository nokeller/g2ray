### [124] Business-logic IDOR — swap `PID` at checkout (price stays); "share product" leaks the PID → buy $400 item for $10 — Sagar Sajeev [NEW: product/price binding mismatch]
- Where: e-commerce checkout POST with `amount` (server-validated) + `PID` (product id).
- Approach/how-found: `amount` couldn't be tampered (server validation), but `PID` could — add a $10 Product A to the cart, grab Product B's ($400) PID (from its cart entry or the "share this product" link), replace A's PID with B's while keeping `amount=$10` → checkout delivers the $400 product for $10. Price and product are validated independently, not bound.
- Test: at checkout, if `amount`/price is locked, swap the *product* id instead — many carts bind the charge to the cart total, not to the product fulfilled. "Share product" links leak the PID.
- Q: "Is the charged amount bound to the *product* id, or can I keep a cheap item's price while swapping in an expensive product's id? Where does the PID leak (share link, cart)?"

### [125] "Unexpected IDOR" + bypass checklist — whitespace suffix (`%20`) flips 401→200; HPP, special chars, method change, inject id into id-less requests — Bharat Singh [NEW ★ IDOR-bypass checklist]
- Where: `POST /account/teamsetting/retired_team?team_id=12345`.
- Approach/how-found: swapping `team_id` → 401, but appending `%20` (`team_id=<victim>%20`) → 200 → retire any team (no rate limit → mass). His reusable bypass list: (1) **HPP** `?custom_id=<me>&custom_id=<victim>`; (2) append special chars/whitespace `/`, `%20 %09 %0b %0c %1c %1d %1e %1f` to break the validator while the backend trims them; (3) change the HTTP method (GET/POST/PUT/DELETE/PATCH); (4) add an id param to an id-less request (`GET /api/card` → `GET /api/card?custom_id=<victim>`).
- Test: when an id-swap returns 401/invalid, don't give up — append trailing whitespace/special chars, pollute the param (HPP), change method, or inject the id into endpoints that don't normally take one.
- Q: "Did a 401 on id-swap stop me too early? Have I tried `%20`/special-char suffixes, HPP duplicate params, method changes, and injecting an id into id-less requests?"
