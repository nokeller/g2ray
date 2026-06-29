"""Live URL checker: status code, page title, content-type, length.

Used for every discovered path (JS links, juicy files, hosts) with curl_cffi
Chrome impersonation and proxy/WARP fallback on WAF blocks.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from .. import util
from ..config import SETTINGS
from ..http_client import HttpClient

LogFn = Callable[[str, str], None]
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def extract_title(body: str) -> str:
    m = _TITLE.search(body or "")
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:240]


class LiveChecker:
    def __init__(self, client: HttpClient):
        self.client = client

    def check_one(self, url: str) -> dict:
        r = self.client.get(url, allow_redirects=True)
        ctype = r.headers.get("content-type", "")
        clen = 0
        try:
            clen = int(r.headers.get("content-length") or len(r.content))
        except Exception:
            clen = len(r.content)
        title = extract_title(r.text) if "html" in ctype.lower() else ""
        return {
            "url": url, "status_code": r.status, "title": title,
            "content_type": ctype[:128], "content_length": clen,
            "via_proxy": r.via_proxy, "error": r.error,
        }

    def check_many(self, urls: list[str], persist: Callable[[dict], None],
                   log: LogFn, should_stop: Callable[[], bool],
                   workers: int | None = None) -> int:
        workers = workers or SETTINGS.check_workers
        urls = list(dict.fromkeys(urls))
        log("info", f"live-check: {len(urls)} urls")
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.check_one, u): u for u in urls}
            for fut in as_completed(futs):
                if should_stop():
                    break
                try:
                    res = fut.result()
                    if res["status_code"] or not res["error"]:
                        persist(res)
                except Exception as e:
                    log("warn", f"live-check error: {e}")
                done += 1
                if done % 100 == 0:
                    log("info", f"live-check {done}/{len(urls)}")
        return done
