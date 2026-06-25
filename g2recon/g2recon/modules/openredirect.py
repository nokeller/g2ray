"""Open-redirect detection.

For every URL that carries parameters we inject an off-site canary host into
redirect-prone params (and, as a second pass, all params) and follow no
redirects. If the Location header / meta-refresh / JS sink points at our canary
host, it is an open redirect.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlsplit, urlunparse, parse_qsl, urlencode

from .. import util
from ..config import SETTINGS
from ..http_client import HttpClient

LogFn = Callable[[str, str], None]

CANARY = "g2r-oob.example"   # we never visit it; we only look for it in sinks
REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "redirect_url", "redirecturl", "return",
    "returnurl", "return_url", "returnto", "return_to", "next", "dest",
    "destination", "continue", "goto", "go", "out", "view", "to", "target",
    "rurl", "u", "link", "callback", "redir", "forward", "from_url", "load_url",
    "image_url", "file", "page", "path",
}

PAYLOADS = [
    "https://{c}", "//{c}", "https:/{c}", "http://{c}",
    "https://{c}/%2f..", "/\\{c}", "https://localhost.{c}",
]


def _payloads():
    return [p.format(c=CANARY) for p in PAYLOADS]


def _candidate_params(url: str) -> list[str]:
    names = util.url_params(url)
    redir = [n for n in names if n.lower() in REDIRECT_PARAMS]
    return redir or names   # prefer obvious ones, else test all


class OpenRedirectScanner:
    def __init__(self, client: HttpClient):
        self.client = client

    def _test(self, url: str, param: str, payload: str):
        p = urlsplit(url if "://" in url else "http://" + url)
        q = dict(parse_qsl(p.query, keep_blank_values=True))
        q[param] = payload
        test_url = urlunparse((p.scheme, p.netloc, p.path, "", urlencode(q), ""))
        r = self.client.get(test_url, allow_redirects=False)
        loc = r.headers.get("location", "") or r.headers.get("Location", "")
        hit = False
        evidence = ""
        if loc and (CANARY in loc):
            hit, evidence = True, f"Location: {loc[:200]}"
        elif r.text:
            # meta refresh / JS location sinks
            if re.search(r"(?i)(http-equiv=['\"]?refresh|location\.(href|replace|assign)|window\.location)"
                         r"[^>]{0,80}" + re.escape(CANARY), r.text):
                hit, evidence = True, "client-side redirect sink to canary"
        if hit:
            return {"url": url, "param": param, "payload": payload,
                    "location": evidence, "status_code": r.status}
        return None

    def scan(self, urls: list[str], persist: Callable[[dict], None],
             log: LogFn, should_stop: Callable[[], bool],
             workers: int | None = None) -> int:
        workers = workers or SETTINGS.check_workers
        # dedup by signature to avoid retesting /x?u=a and /x?u=b
        seen: set[str] = set()
        jobs: list[tuple[str, str, str]] = []
        for u in urls:
            if not util.has_params(u):
                continue
            sig = util.param_signature(u)
            if sig in seen:
                continue
            seen.add(sig)
            for param in _candidate_params(u):
                for pl in _payloads():
                    jobs.append((u, param, pl))
        log("info", f"open-redirect: {len(jobs)} probes over {len(seen)} url signatures")
        count = 0
        found_sigs: set[str] = set()
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self._test, u, p, pl): (u, p) for (u, p, pl) in jobs}
            for fut in as_completed(futs):
                if should_stop():
                    break
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if res:
                    key = res["url"] + "|" + res["param"]
                    if key in found_sigs:
                        continue
                    found_sigs.add(key)
                    persist(res)
                    count += 1
        log("info", f"open-redirect: {count} findings")
        return count
