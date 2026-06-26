"""curl_cffi content-discovery fuzzer (a ffuf-style engine using the shared
browser-like HTTP client and optional operator-provided proxies).

Behaviour:
* derives base directories from every discovered JS / juicy file
  (e.g. https://x/src/app.js  ->  https://x/src/)
* for each base dir, fuzzes `FUZZ.<ext>` for a wordlist of filenames and a list
  of juicy extensions
* soft-404 / baseline detection: probes a random name first; results matching
  the baseline (status + length) are discarded as false positives
* `-mc all` style: records every non-baseline, non-404 response
* on a 403-WAF signature the shared HttpClient records the block and can retry
  through configured proxies
"""
from __future__ import annotations

import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlsplit, urlunparse

from .. import util
from ..config import SETTINGS
from ..http_client import HttpClient

LogFn = Callable[[str, str], None]

DEFAULT_EXTS = ["js", "json", "map", "txt", "xml", "config", "cfg", "env",
                "bak", "old", "yml", "yaml"]
# bulk content-discovery probes use a short timeout: a flaky/slow host should
# fast-fail (and trip the client's per-host circuit breaker) rather than stall
# the sweep on the full 25s default for every dead filename.
FUZZ_TIMEOUT = 8
RECORD_STATUS = {200, 201, 202, 203, 204, 206, 301, 302, 307, 308,
                 401, 403, 405}


def base_dir_of(url: str) -> str:
    p = urlsplit(url if "://" in url else "http://" + url)
    path = p.path
    if not path.endswith("/"):
        path = path.rsplit("/", 1)[0] + "/"
    return urlunparse((p.scheme, p.netloc, path, "", "", ""))


def _rand(n=12):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class Fuzzer:
    def __init__(self, client: HttpClient, exts: list[str] | None = None,
                 max_base_dirs: int = 300):
        self.client = client
        self.exts = exts or DEFAULT_EXTS
        self.max_base_dirs = max_base_dirs

    def _baseline(self, base: str) -> dict[str, tuple[int, int]]:
        """Per-ext baseline {ext: (status, length)} from a random filename."""
        bl: dict[str, tuple[int, int]] = {}
        for ext in self.exts:
            u = f"{base}{_rand()}.{ext}"
            r = self.client.get(u, allow_redirects=False, timeout=FUZZ_TIMEOUT)
            bl[ext] = (r.status, len(r.content))
        return bl

    def _probe(self, base: str, word: str, ext: str,
               baseline: tuple[int, int]) -> dict | None:
        url = f"{base}{word}.{ext}"
        r = self.client.get(url, allow_redirects=False, timeout=FUZZ_TIMEOUT)
        if r.error:
            return None
        if r.status == 404 or r.status not in RECORD_STATUS:
            return None
        b_status, b_len = baseline
        # soft-404: same status and near-identical length as the random probe
        if r.status == b_status and abs(len(r.content) - b_len) <= 32:
            return None
        return {
            "base_url": base, "found_url": url, "status_code": r.status,
            "content_type": r.headers.get("content-type", "")[:128],
            "length": len(r.content), "via_proxy": r.via_proxy,
        }

    def fuzz(self, base_dirs: list[str], words: list[str],
             persist: Callable[[dict], None], log: LogFn,
             should_stop: Callable[[], bool], workers: int | None = None) -> int:
        workers = workers or SETTINGS.fuzz_workers
        base_dirs = list(dict.fromkeys(base_dirs))[: self.max_base_dirs]
        words = list(dict.fromkeys(words))
        log("info", f"fuzz: {len(base_dirs)} dirs x {len(words)} words "
                    f"x {len(self.exts)} exts")
        count = 0
        for base in base_dirs:
            if should_stop():
                break
            try:
                baseline = self._baseline(base)
            except Exception:
                baseline = {e: (0, 0) for e in self.exts}
            jobs = [(w, e) for w in words for e in self.exts]
            dir_hits: list[dict] = []
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(self._probe, base, w, e, baseline.get(e, (0, 0))): (w, e)
                        for (w, e) in jobs}
                for fut in as_completed(futs):
                    if should_stop():
                        break
                    try:
                        res = fut.result()
                    except Exception:
                        res = None
                    if res:
                        dir_hits.append(res)
            # drop systematic responses: a (status,length) returned for many
            # distinct filenames is a generic error/redirect/SPA page (e.g. a
            # 500 served via proxy), not real discovered content.
            from collections import Counter
            sig_count = Counter((h["status_code"], h["length"]) for h in dir_hits)
            for h in dir_hits:
                if sig_count[(h["status_code"], h["length"])] >= 5:
                    continue
                persist(h)
                count += 1
            log("info", f"fuzz {base}: {count} hits so far")
        log("info", f"fuzz: {count} total hits")
        return count
