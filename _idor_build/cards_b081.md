### [444] Twitter — view any private account's tweets via the ADS subdomain: an Ad Groups settings request carries `userId`; swap it to a private account's id → the response returns their (private) tweets — Cj Legacion [NEW ★ a sibling/ads/business subdomain exposes main-product private data by userId swap]
- Where: ads.twitter.com Ad Groups settings request, `userId` parameter.
- Approach/how-found: while testing the ads subdomain's new Ad-Group settings, a request carried `userId`; creating a 2nd (private) test account and swapping its id into the request returned that private account's tweets.
- Test: marketing/ads/business subdomains often call back into the core product with a `userId`/`accountId` and skip the main app's privacy checks — swap to read private content (tweets, posts, profile) of protected accounts.
- Q: "Does an ads/business/partner subdomain expose core private data when I swap a userId? Do these secondary surfaces enforce the main product's privacy rules?"

### [448] Yahoo Luminate — app install statistics IDOR (emails of all installers): app-stats `GET ...?app_token=<token>` has no ownership check → returns who installed the app (admin emails/websites); source any app's `app_token` from the public install request URL (`...&app_token=...`) — Rojan Rijal [NEW ★ leaked token in an install URL unlocks a token-keyed stats IDOR]
- Where: stats `GET .../stats?app_token=<token>`; install `GET /admin/apps/live/settings/<app>?...&app_token=<token>...`.
- Approach/how-found: the stats endpoint trusted the `app_token` with no owner check (verified across two accounts). The remaining problem — getting another app's token — was solved because the app-store INSTALL request URL exposed `app_token` in the query string → grab it, feed it to stats → all installers' emails/sites.
- Test: when a stats/data endpoint is keyed on an app/integration token, hunt where that token leaks (install/settings/embed URLs, referer, JS); a "secret" token in a URL is harvestable.
- Q: "Is this stats/data endpoint keyed on a token with no owner check? Where does that token leak (install/embed URL, referer)? Can I read other apps' installer PII?"
