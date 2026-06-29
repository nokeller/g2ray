### [437] Travel portal — read any user's support chat: chat request has `customer_id` (13-char alnum) + `chat_id` (`FL-132756`, incremental); customer_id is unguessable but appears in the traveller-BLOG URLs → harvest customer_ids from many blogs, brute the chat_id → full chat history — Avinash Jain [NEW ★ source the "unguessable" id from a different feature (blog URLs); try many victims since not all have data]
- Where: support-chat request (`customer_id` + incremental `chat_id`); customer_id leaked in blog post URLs.
- Approach/how-found: chat needed a 13-char customer_id (not in login/profile); the travel blog section exposed customer_ids in URLs. He harvested several, brute-forced chat_id for each, and (after a few empty users) hit full chat histories.
- Test: when one feature needs an unguessable id, find a DIFFERENT feature (blogs, reviews, public profiles, share links) that exposes it; iterate over many harvested ids since only some users have the target data.
- Q: "Which other feature leaks this user/customer id (blogs, reviews, comments, share URLs)? Have I tried enough victims to find ones with data?"

### [439] New Relic — IDOR in the INTERNAL API (public REST API was safe): `/internal_api/v1/accounts/<num>/incidents` on `alerts`/`infrastructure` subdomains didn't bind the account number to the authenticated user; account numbers are sequential → enumerate every account's events/messages/violations/policies/settings — Jon Bottarini ($1,000) [NEW ★ the public API is locked down but the internal_api isn't; check all subdomains AND api versions]
- Where: `*.newrelic.com/internal_api/v1/accounts/<seq>/...` (alerts + infrastructure subdomains; only v1 vulnerable).
- Approach/how-found: swapping application_id on the public REST API failed; but the app also used `/internal_api/` (referenced in JS) across two product subdomains and multiple versions — only v1 on those subdomains skipped the account-ownership check → sequential account number → mass data.
- Test: enumerate INTERNAL APIs (`/internal_api/`, JS-referenced endpoints) separately from the public API; test EVERY subdomain and EVERY api version — authz often differs; sequential account numbers = full enumeration.
- Q: "Is there an internal API (in the JS) with weaker authz than the public one? Have I tested every subdomain and version? Are account numbers sequential?"

### [440] Facebook polls — delete any image ($10k): poll-create `poll_question_data[options][][associated_image_id]`; set it to a victim's image id → the poll shows their image; deleting the poll deletes the victim's image (cascade as a poll property) — Pouya Darabi [DUP-reinforce of the attach-foreign-id-then-delete cascade family (cf. [430]); high impact]
- Where: poll-create request `...[associated_image_id]`.
- Approach/how-found: the poll option referenced an uploaded image by id; swapping it embedded a victim's image; deleting the poll cascade-deleted the referenced image.
- Test: any feature that ATTACHES an image/file by id (poll, story, series, post) and treats it as an owned property → swap to a victim's id, then delete the container to destroy their asset.
- Q: "Does attaching a foreign media id and then deleting my container cascade-delete the victim's media? Which features (poll/story/series) reference media by id?"
