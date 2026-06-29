### [225] JWT account-number swap — payload `id` is the account number; pre-login email-existence check leaks the victim's id (`email=victim&id=123456`) → ATO — Filipe Azevedo ($3,000) [DUP reinforcement: id-in-JWT-payload + pre-login id leak]
- Where: session JWT whose payload `id` = account number; the "enter email → Next" pre-login step.
- Approach/how-found: the only difference between two accounts' JWTs was the payload `id` (= account number) → swapping it accessed any account (server trusted the payload id). Victim id source: the pre-login flow (email → Next) sent `email=victim@…&id=123456` when the email existed → harvest any user's id.
- Test: decode JWT payloads for an account id/number and test whether swapping it is honored (is the signature actually enforced/bound?). Pre-login email-existence / "next" steps frequently leak the user id in the request/response — harvest victim ids there.
- Q: "Does the JWT payload carry a swappable account id (is its signature truly enforced)? Does the pre-login email check leak the user's id?"

### [227] Facebook — remove-cover action keys only on `note_id`, ignoring the document's "no one may edit" setting → swap to victim's note_id to strip their cover (Documents & Notes) — Muhammad Sholikhin ($1,500) [NEW: sub-resource action ignores parent permission settings]
- Where: `POST /notes/composer/remove_cover_photo/`; `note_id` (Documents and Notes).
- Approach/how-found: a victim's document was set to disallow edits. He created his own document, captured the remove-cover request, and swapped `note_id` to the victim's → the cover was removed despite the no-edit setting (the action validated only the object id, not the parent's permissions).
- Test: remove/edit/delete-sub-resource actions that key only on the object id ignore the parent object's edit/permission flags → swap the id to modify objects the UI says you can't edit.
- Q: "Does a remove/edit-subresource action key only on the object id and ignore the parent's edit/permission settings? Can I swap the id to modify a 'non-editable' object?"

### [229] Facebook — `LiveProducerProviderRefetchQuery` (owner-only) keys on `videoID`; swap to another user's livestream → private broadcast data (blocked list, config, charity) — Geva-Kun [NEW: owner/producer config query keyed only on object id; crawl the graphql folder]
- Where: FB GraphQL `LiveProducerProviderRefetchQuery`; `videoID`.
- Approach/how-found: while using the livestream feature he intercepted requests; the producer-only refetch query took `videoID` → swapping it to another user's livestream returned their private producer data.
- Test: "producer/owner/admin config/refetch" GraphQL queries are owner-scoped by intent but often key only on the object id → swap it. Use Burp live-passive-crawl and inspect the sitemap `graphql` folder (and intercept on button clicks) for such queries.
- Q: "Is there an owner/producer/admin-only config/refetch query keyed on an object id I can swap? Have I crawled the graphql folder + intercepted button-click queries for suspicious ones?"

### [230] SSO — session cookie embeds a repeated sequential 5-digit user code (`…|47402|…`); decrement/increment it → log straight into other accounts (even a user in China) — Sankalpa Acharya ($500) [NEW ★ dissect the cookie field-by-field; sequential code = ATO]
- Where: `Set-Cookie: example_token=1|rand|47402|47402|rand|` (a repeated 5-digit user code).
- Approach/how-found: login returned no JWT, so identity lived in cookies. Swapping each cookie field between two accounts isolated the identifying token; inside it a 5-digit code (47402) repeated and differed by 1 from the second account (47403) → replacing it logged him into other accounts (47401 = a Chinese user's account).
- Test: dissect session cookies field-by-field (swap each between two accounts to find the identifier). A repeated numeric segment is likely the user id — test sequentiality (±1) → direct ATO.
- Q: "Does the session cookie embed a sequential user code (often repeated within the token)? Can I inc/dec it to log into other accounts?"

### [231] "Some ways to find more IDOR" (methodology) — `/…/self/…` → replace `self` with your user id → site-wide IDOR incl change-email → ATO; fuzz chars (`/`, `%20 %09 %0b %0c %1c-%1f`, %00→%ff) to break authz regex; don't drop GraphQL from scope — Thái Vũ [NEW ★ three reusable IDOR-discovery methods]
- Where: APIs like `/ngprofile/aggregate/self/fullProfile`; `/accounts/{id}`; `/api/applications/{id}`; `/graphql`.
- Approach/how-found: (1) "No ID, no worry" — APIs with a `/…/self/…` segment: replace `self` with your user id (from the JWT) → works; then swap to incremental user ids → read/modify/delete anyone, including a Change-Email API → chain forgot-password → ATO all accounts. (2) "Don't just replace ID" — when a swap returns "Invalid account number"/401, append a character: `/` (e.g. `/accounts/0001176361/`) or whitespace/control bytes (`%20 %09 %0b %0c %1c %1d %1e %1f`, fuzz %00→%ff) → breaks the server's regex/authz pattern → full data. (3) "Don't ignore GraphQL" — if Burp history looks empty, all traffic may be `/graphql`; add it to scope → found 2 IDORs by plain id replacement.
- Test: replace literal `self`/`me`/`current` path segments with your numeric id, then enumerate. When an id-swap is blocked, append `/` or whitespace/control chars and fuzz %00–%ff to defeat the authz regex. Never exclude `/graphql` from scope.
- Q: "Do any endpoints use a `self`/`me` segment I can replace with a raw user id? When a swap is rejected, did I fuzz trailing chars (`/`, %00–%ff) to break the regex? Did I keep GraphQL in scope?"

### [232] Instagram — media-by-`MEDIA_ID` GraphQL returns private/archived posts/stories/reels/IGTV (+regenerated CDN); when a second endpoint enforced a token, `access_token=null` bypassed it — Mayur Fartade ($30,000) [NEW ★ media-id brute + null-token bypass]
- Where: Instagram GraphQL `doc_id=…` with `query_params.id=[MEDIA_ID]`; an `access_token` param on a second endpoint.
- Approach/how-found: the media fetch keyed only on MEDIA_ID with no ownership check → private/archived media details + a fresh CDN URL (brute MEDIA_ID to harvest, then filter private/archived). A second endpoint returned `data:null` for others' media when a valid access_token was sent — but setting `access_token=null` returned the data (the null token skipped the ownership filter).
- Test: media-by-id GraphQL leaks private/archived content and regenerates CDN URLs → brute media ids. When a token gates it, try `access_token=null`/empty/removed — a null/absent token often bypasses the ownership check entirely.
- Q: "Does a media-by-id query return private/archived content and a fresh CDN URL? If a token blocks it, does setting the token to null/empty/removing it bypass the check?"

### [234] Facebook Leads Center — chain two GraphQL IDORs: `pageID` → any page's leads-form details (leaks `form_id`); `pageID`+`form_id` → total leads captured → spy competitors' winning lead ads — Amine Aboud [NEW ★ chain IDOR-1 leaks the id IDOR-2 needs]
- Where: FB Leads Center GraphQL `doc_id=3388026827877743` (`pageID`→form details incl. form_id) and `doc_id=3547538925278909` (`pageID`+`form_id`→lead counts).
- Approach/how-found: first IDOR returns the leads-form details (and form_id) for any `pageID`; feeding that form_id into the second IDOR returns the total leads captured → a competitor could copy profitable lead ads without spending a dollar.
- Test: chain IDORs where the first leaks the child id (form_id) the second requires. Ads/leads/business GraphQL keyed by `pageID`/business id usually skips ownership → swap it; then pivot to sibling queries needing the leaked child id.
- Q: "Can I chain a first IDOR that leaks a child id (form_id/campaign_id) into a second IDOR that needs it? Are ads/leads/business endpoints keyed by a swappable page/business id?"
