# Phase 2 — Unrecovered writeups (explicit ledger)

These pentester.land IDOR-tagged entries could NOT be read because the source no longer exists anywhere accessible. Documented here instead of fabricated. All other 465 entries (1..467 minus these two) have real per-article lesson cards built from the full article text.

## [65] "IDOR on bitdefender.com" — Vivek M (2023-03-05), program: Bitdefender
- URL: https://hopesamples.blogspot.com/2023/03/idor-on-bitdefendercom.html
- Status: UNRECOVERABLE. The entire blog `hopesamples.blogspot.com` was deleted by Google ("the blog ... has been removed").
- Recovery attempted (all failed): r.jina.ai (blogger JS shell), direct fetch (blog removed), Wayback CDX/id_ (only a 2025-05-31 capture of the "blog removed" 404; no post body; feeds/sitemap empty), Blogspot Atom/RSS feed (disabled), web_search (no mirror indexed), archive.is (zero snapshots for the URL and host-wide, captcha solved), Memento aggregator (down), penforce.me / awesome-google-vrp writeup indexes (metadata + dead link only). CUA confirmed deletion.
- Surviving metadata only: title, author (Vivek M), date, type IDOR, program Bitdefender. Body (endpoint/param/PoC) is gone.

## [88] "IDOR allows to assign deleted tasks to other members in Google Chat Space" — Vivek M (~Dec 2022), program: Google
- URL: https://hopesamples.blogspot.com/2022/12/idor-allows-to-assign-deleted-tasks-to.html
- Status: UNRECOVERABLE. Same deleted blog (`hopesamples.blogspot.com`).
- Recovery attempted (all failed): same set as [65] — jina, direct, Wayback (only 2025 "blog removed" 404), feeds/sitemap, web_search, archive.is (no snapshot, captcha solved), Memento, writeup indexes. CUA confirmed deletion.
- Surviving metadata only: title, author (Vivek M), ~Dec 2022, type IDOR, program Google (Chat Space). Body is gone.
- Title-level technique (NOT a substitute for the body): operating on a soft-deleted object — a "deleted" task could still be (re)assigned to other space members, i.e. deleted/archived objects remain actionable via the API. Treat as a lead, not a verified card.
