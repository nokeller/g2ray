### [52] School platform — full org takeover by chaining low-priv `getUsers` BAC + role mass-assignment privesc + admin-edit IDOR — Hacktus/DreyAnd [NEW ★ role-in-body privesc + admin BAC + PUT-user IDOR]
- Where: ASP.NET API `api.redacted.com`, Basic auth, school management SaaS.
- Approach/how-found:
  1. **BAC id-harvest:** `GET /v1/admin/<org>/customers/getUsers?=*` with a **low-priv** token leaked every user's `account_id`/email/IP/role (students→teachers→admins).
  2. **Vertical privesc #1:** low-priv can't create admins, but `POST /v1/<org>/users` with `"role":"Manager"` succeeded → manager.
  3. **Vertical privesc #2:** as manager, the same POST with `"role":"Administrator"` → admin (the `role` is **mass-assignable** from the request body).
  4. **IDOR ATO:** `PUT /v1/<org>/users/<adminId>` edits any admin's `email`+`password` → take over any admin.
  5. **Impact:** `DELETE /v1/<org>/users/<id>` → delete all other admins → own the org.
- Test: hit admin/reporting endpoints with a low-priv token (BAC for id harvest). On create/update-user, set `role`/`isAdmin`/`permissions` in the body (mass assignment). Then PUT other users (esp. admins) by id to change email/password.
- Q: "Can a low-priv token reach admin list/report endpoints to harvest ids? Is `role`/`isAdmin` honored from the create/update body? Can I PUT another (admin) user by id to change their email/password?"
