### [47] GraphQL introspection → InQL → unauthenticated `deleteUser`/`updateUser` → admin takeover — Mahmuduzzaman Kamol [DUP reinforcement: introspection → dangerous mutations]
- Where: `/graphql` with introspection enabled.
- Approach/how-found: introspection query dumped the schema → InQL (Burp) listed mutations → `deleteUser`/`updateUser` lacked authz; used the `user(id)` query to find ids, deleted a user, then `updateUser` to reset the admin's password → login as admin.
- Test: always run introspection (or InQL / GraphQL Voyager); enumerate `delete*/update*/reset*` mutations and call them with ids from `user`/`users` queries — per-mutation authz is frequently missing.
- Q: "Is introspection on? Which `update*/delete*/reset*` mutations exist, and do they enforce per-object authz when I pass another user's id?"

### [50] Unguessable user id (u+10 random) defeated by a Spring-Data search endpoint that leaks creator ids → 40k PII — ferferof ($1,500) [NEW ★ leak the ids via a search/list endpoint]
- Where: `/main/api/v1/users/<userId>` discloses PII but `userId` = `u`+10 random chars (62^10, unbruteforceable). Leak source: `/main/companies/search/findByNameIgnoreCaseContaining?q=<term>&limit=20` returns each company's **creator user id**.
- Approach/how-found: enumerate companies by searching all 1/2/3-letter terms → harvest creator user ids → feed each to the user-info endpoint (multi-threaded Python) → 40k PII records in 10 minutes. (An earlier IDOR attempt surfaced a SQL error, but prepared statements blocked SQLi.)
- Test: when the id is unguessable, don't brute it — find a search/list/autocomplete/export endpoint that *returns* the ids. Spring Data REST `…/search/findBy…` endpoints leak fields and ids generously; sweep them with short query terms.
- Q: "Is there a search/list/autocomplete endpoint that returns the unguessable ids (esp. Spring `findBy…`)? Can I sweep it with short terms to harvest all ids, then hit the PII endpoint?"

### [51] LinkedIn — unpin any company's posts; the required per-page `versionTag` is itself fetchable — Omar Ahmed (LinkedIn H1) [NEW: defeat an anti-tamper token by fetching it per object]
- Where: unpin request takes a company id + a `versionTag`; companies are numerically ordered.
- Approach/how-found: the unpin failed without a valid `versionTag` (looked like protection). He realized the version tag is page-specific and *retrievable* from a page URL — fetch the target company's version tag, then unpin → 200. Because company ids are sequential, he could unpin any company's posts. Found by hunting *past* what the Autorize plugin auto-detects (chasing an odd response code).
- Test: when an action needs an anti-tamper token (version/etag/nonce) tied to the object, check whether you can simply fetch that token for the target object first — a fetchable "protection" is none. Investigate the weird/unique response codes the auto-tools skip.
- Q: "Does this action need a per-object token I can fetch for the victim object first? Am I only testing what Autorize auto-flags, or chasing the odd response codes too?"
