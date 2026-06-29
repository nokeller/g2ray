"""CORS misconfiguration scanner.

For each target URL we send an ``Origin`` header of an attacker-controlled
canary and inspect the response's ``Access-Control-Allow-Origin`` /
``-Allow-Credentials`` and whether the host sets a cookie. Severity reflects
real exploitability:

* arbitrary-origin reflection + credentials + a cookie-based session => high
  (a malicious page can read the victim's authenticated responses), UNLESS the
  response is an SSO/Zero-Trust login redirect (Cloudflare Access / Okta), in
  which case the app is gated and impact is downgraded.
* arbitrary-origin reflection + credentials but token (Authorization-header)
  auth, no cookie => low (browser won't auto-send the bearer token).
* ``null`` origin + credentials => high.
* wildcard ``*`` without credentials => info (only public data is readable).
"""
from __future__ import annotations

import concurrent.futures as cf
from typing import Callable

LogFn = Callable[[str, str], None]

EVIL_ORIGIN = "https://evil-g2recon.example.org"

# redirect Location substrings that mean the asset is gated behind SSO / Zero-Trust
_SSO_MARKERS = ("cloudflareaccess.com", "/cdn-cgi/access/", "okta.com",
                "login.microsoftonline.com", "auth0.com", "/oauth2/authorize",
                "accounts.google.com", "/saml", "/login")


def classify(acao: str, acac: bool, set_cookie: bool, *, evil: str = EVIL_ORIGIN,
             status: int = 0, location: str = "") -> tuple[str, str]:
    """Return (severity, note). Severity '' means not a finding."""
    acao = (acao or "").strip()
    gated = status in (301, 302, 303, 307, 308) and any(
        m in (location or "").lower() for m in _SSO_MARKERS)
    if acao == evil and acac and set_cookie:
        if gated:
            return ("low", "reflects origin+credentials but asset is behind SSO/Zero-Trust "
                           "(login redirect) — gated, not exploitable as-is")
        return ("high", "reflects arbitrary origin + credentials + cookie session "
                        "=> cross-origin theft of authenticated responses")
    if acao == "null" and acac:
        return ("high", "allows null origin with credentials")
    if acao == evil and acac:
        return ("low", "reflects arbitrary origin + credentials, but no cookie "
                       "(token/Authorization auth limits cross-origin impact)")
    if acao == "*" and acac:
        return ("medium", "wildcard origin with credentials (browsers reject this combo, "
                          "but indicates a misconfigured CORS layer)")
    if acao == evil:
        return ("low", "reflects arbitrary origin (no credentials)")
    if acao == "*":
        return ("info", "wildcard origin, no credentials (public data only)")
    return ("", "")


class CorsScanner:
    def __init__(self, client):
        self.client = client

    def _check(self, url: str) -> dict | None:
        try:
            r = self.client.get(url, allow_redirects=False,
                                 headers={"Origin": EVIL_ORIGIN},
                                 timeout=8, max_proxy_tries=1)
        except Exception:
            return None
        h = r.headers or {}
        acao = h.get("access-control-allow-origin") or h.get("Access-Control-Allow-Origin") or ""
        acac_raw = h.get("access-control-allow-credentials") or h.get("Access-Control-Allow-Credentials") or ""
        acac = str(acac_raw).lower() == "true"
        set_cookie = bool(h.get("set-cookie") or h.get("Set-Cookie"))
        location = h.get("location") or h.get("Location") or ""
        sev, note = classify(acao, acac, set_cookie, status=r.status, location=location)
        if not sev:
            return None
        from urllib.parse import urlsplit
        return {"url": url, "host": urlsplit(url).hostname or "",
                "origin_reflected": acao == EVIL_ORIGIN, "acao": acao[:200],
                "acac": acac, "set_cookie": set_cookie, "severity": sev,
                "note": note, "status_code": r.status}

    def run(self, urls: list[str], persist: Callable[[dict], None],
            log: LogFn, should_stop: Callable[[], bool], workers: int = 25) -> int:
        urls = list(dict.fromkeys(u for u in urls if u))
        log("info", f"cors: probing {len(urls)} targets with attacker Origin")
        count = 0
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self._check, u): u for u in urls}
            for fut in cf.as_completed(futs):
                if should_stop():
                    break
                try:
                    rec = fut.result()
                except Exception:
                    rec = None
                if rec:
                    persist(rec)
                    count += 1
                    if rec["severity"] in ("high", "medium"):
                        log("warn", f"cors: {rec['severity'].upper()} {rec['url']} "
                                    f"({rec['note']})")
        log("info", f"cors: {count} hosts with a CORS finding")
        return count
