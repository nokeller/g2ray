### [153] Account-export download IDOR — download any user's full data export — Najam Ul Saqib [NEW: target data-export/download features]
- Where: an API that downloads "account exports" (full account info).
- Approach/how-found: testing API IDORs on root domains (no subdomain recon), he found the account-export download accepted another user's id/reference → download any user's full export. (Details NDA'd; single-line summary in the write-up.) Methodology: consistency over recon — stuck to root domains and hammered API id params daily.
- Test: hunt data-export / "download my data" / GDPR-export / report-download endpoints — they bundle an account's full info and are frequently keyed by a swappable id with weak authz. Root-domain APIs are full of IDORs.
- Q: "Is there an account-export / data-download / report endpoint keyed by a swappable id that returns another user's full data?"

### [154] TikTok SMB (WordPress) — profile-edit `u_id` IDOR → ATO; target found via an ad email — Ahmad A Abdulla ($1,000) [DUP reinforcement: WP theme `u_id` IDOR + ad-sourced asset]
- Where: `POST /wp-content/themes/tiktok/includes/user/user.php action=profile_edit` with `u_id=1504`.
- Approach/how-found: the asset (`tiktoksmbacademyeu.com`) came from a marketing email/ad. The profile-edit body has `u_id` (sequential); change 1504→1505 → set another account's email+name → ATO (also XSS + missing CSRF token). Two accounts ended with one email = IDOR confirmed.
- Test: WordPress custom-theme endpoints (`/wp-content/themes/.../user.php`) often carry a `u_id`/`user_id` with no authz; sequential → enumerate. Add assets seen in ads/marketing emails to scope.
- Q: "Does a WP theme/plugin endpoint carry a sequential `u_id`/`user_id` for profile edit (→ ATO)? Did I add ad/email-sourced domains to scope?"
