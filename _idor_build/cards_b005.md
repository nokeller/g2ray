### [26] Instagram IGTV — add a caption to others' caption-less posts via media-id swap; ignore the error, verify the effect — Sarmad (Meta $6,500) [NEW: state-gated write-IDOR + "error but applied"]
- Where: `POST /media/<mediaID>/edit/` with `caption=&publish_mode=igtv&title=`.
- Approach/how-found: edit your own IGTV, intercept, swap `mediaID` to a victim's **public post that lacks a caption** → server throws "Oops, an error occurred", but refreshing the victim's post shows the attacker's description applied. Works on photos/videos/IGTV; limited to public posts that are missing a description.
- Test: write-IDORs may only succeed on objects in a specific state (empty field/draft/pending). Never trust an error response — re-fetch the object to confirm the mutation actually landed.
- Q: "Does a write only apply to objects in a certain state (empty/blank field)? Did I verify by re-fetching even though the API returned an error?"

### [28] $15k mass breach — Wayback/dork-found order endpoint MINTS auth cookies that unlock ANY order — bxmbn [NEW ★ cookie-minting object endpoint + archive recon]
- Where: a forgotten orders subdomain (403) found via `site:program.com/webapp/` dork; Wayback revealed a per-order endpoint.
- Approach/how-found: requesting the order endpoint returned a blank 200 but **Set-Cookie: WC_AUTHENTICATION_/WC_PERSISTENT** (WebSphere Commerce auth cookies). Reusing those cookies granted access to that order — and the same flow worked for any other `orderId` found by dorking. The endpoint mints "order-scoped" auth cookies that actually authorize **all** orders → 3M users' PII (payment method, contract PDF, addresses, email, phone, names).
- Test: when an endpoint Set-Cookies on a blank/redirect response, capture and reuse them — they may be object-scoped tokens that over-authorize. Use Google dorks + Wayback to find forgotten order/account subdomains and ids.
- Q: "Does requesting an object endpoint hand me Set-Cookie auth tokens, and do they authorize other objects too? What forgotten endpoints/ids do dorks + Wayback reveal?"

### [29] Bank-offer IDOR — encoded access key has a plaintext `ridNumber` twin in the response; enumerate it — bxmbn ($5,000) [NEW: decoded twin of an encoded ref]
- Where: marketing offer opened via a URL access-key (`FD2t6...`, URL-encoded); the offer page shows your PII.
- Approach/how-found: the response body contained `ridNumber` as a **plain numeric** value (the decoded form of the encoded key). Submitting the decoded `ridNumber` directly was accepted → modifying the last digits returned other users' offers (`...243`, `...241`, `...255`) → full PII (names, address, email, phone, DOB). The "encryption" was cosmetic because the cleartext id is exposed and accepted.
- Test: inspect every response value — an opaque/encoded reference often has a plaintext numeric twin elsewhere; submit the plaintext to bypass the encoding and enumerate.
- Q: "Is there a plaintext/numeric twin of this encoded id in the response or a sibling endpoint? Will the server accept the decoded value directly so I can enumerate?"

### [32] Shodan `ssl:` dork → forgotten server → `PUT /offer` group-name leak, then a sibling host adds `personid` → session IDOR — Anas Hmaidy [NEW: replay the bug across sibling subdomains]
- Where: `z2007.redacted.com/agv/sampleAgent.html` test page; `PUT /offer` with `groupid` (→ leaks group name, $100). Then `video.redacted.com` accepts the same PUT with `groupid,isAnonymous,personid` → register/read any user's video-session data ($200 IDOR).
- Approach/how-found: all subdomains redirect to a generic login (DNS brute useless), so he pivoted to Shodan `ssl:redacted.com` → found old host `z2007`. He replayed the working request across other subdomains; one sibling (`video.`) exposed an extra `personid` param, escalating info-disclosure to a full session IDOR.
- Test: when subdomains redirect to login, pivot recon to certs/Shodan/CT to find forgotten hosts. Replay a working request across all sibling subdomains — the same endpoint may accept extra id params (`personid`/`userid`) on a different host.
- Q: "Did I find forgotten hosts via cert/Shodan when DNS brute fails? Does the same endpoint on a sibling subdomain accept extra id params that upgrade info-disclosure to a full IDOR?"
