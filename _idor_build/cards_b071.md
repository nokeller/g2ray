### [407] Edmodo — steal Google Drive access tokens of any user: endpoint #1 (is-linked check, `user_id`) Intruder'd → harvest user_ids who linked Drive (+timestamps); endpoint #2 (`provider`+`user_id`) returns the Drive access TOKEN, not validating the user → swap user_id → get any user's OAuth token — Aagam Shah [NEW ★ enumerate a "is-linked" oracle, then a token-mint endpoint by user_id → others' 3rd-party tokens]
- Where: link-check API (`user_id` → exists+timestamp); token API (`provider`,`user_id` → access_token).
- Approach/how-found: adding files from Drive triggered (1) a check of whether the user linked Drive — Intruder over `user_id` mapped all linked users; then (2) a token endpoint that, given `provider`+`user_id`, returned that user's Drive access token with no ownership check.
- Test: OAuth/3rd-party integration flows: find the "is X linked?" enumeration oracle, then the token/credential endpoint keyed on user_id — swap to mint/read other users' provider tokens.
- Q: "Is there an endpoint that returns a user's linked-service access token by user_id? Can I first enumerate which users linked the service, then pull their tokens?"

### [408] Crypto exchange — full ATO: `POST /api/reset_password` keyed on an INCREMENTAL `id` (swap → reset any account) chained with 2FA bypass (the verify response can be flipped to true / token `123456` accepted); admin email/id found via ticket-system IDOR — mabdullah22 [NEW ★ reset-by-incremental-id + client-side 2FA response tampering]
- Where: `POST /api/reset_password` (`id`, incremental); 2FA verify request (response-tamperable).
- Approach/how-found: the reset wasn't token-based — it carried a sequential user `id`; swapping it reset another account. Login then required 2FA, but intercepting the verify response and setting it true (or sending `123456`) bypassed it → full takeover. Their ticket system leaked the admin's id via IDOR.
- Test: password-reset that carries a user id (not an emailed token) is reset-IDOR; 2FA/OTP gates enforced on the CLIENT can be bypassed by editing the response (true/false) — always test response tampering.
- Q: "Does reset use a swappable user id instead of a bound token? Is 2FA verified server-side, or can I flip the verify response to true? Does the ticket/support system leak admin ids?"

### [409] Paytm — bill-pay PII IDOR: electricity-bill lookup takes `recharge_number` (account) + `recharge_number_2` (mobile) supposedly validated together, but changing the account number with ANY mobile returns the real user's bill/name/address; no throttling → Intruder thousands — Avinash Jain [DUP-reinforce: "two fields must match" but only one is actually checked; utility bill PII]
- Where: bill-fetch request (`recharge_number` + `recharge_number_2`).
- Approach/how-found: the request looked like it validated account+mobile as a pair, but only the account number mattered → arbitrary account number + random mobile returned that consumer's full bill/PII; sequential consumer numbers + no rate limit → mass harvest.
- Test: utility/bill/booking lookups that "require two matching fields" — vary each independently; one is usually the real key; enumerate it for mass PII (these third-party-data flows are often dismissed then re-accepted).
- Q: "Do both 'matching' fields actually get validated, or just one? Can I fix a random secondary value and enumerate the primary id for PII?"

### [410] Facebook "Top Fans" add-anyone (cross-posted mirror of [403]) — same `fan_id`-swap consent bypass, hosted on updatelap.com — Jafar Abo Nada [DUP of 403: same technique, different source]
- Where: same Top Fans join/badge request (`fan_id`).
- Note: identical finding to card [403]; recorded for per-index completeness. See [403] for the full test/question.
- Q: "(see [403]) Can I perform an opt-in action on behalf of another user by swapping their id?"
