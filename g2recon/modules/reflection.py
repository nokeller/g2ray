"""x8-style parameter reflection scanner (curl_cffi / Chrome impersonation).

Key behaviours requested:
* de-duplicate URLs by scheme+host+path+param-NAME-set, so
  `/search?q=a` and `/search?q=b` are tested once, but `/search?q=` and
  `/search?id=` are both tested.
* per-parameter unique canary so a single request can probe many params and we
  know exactly which reflected (this is how x8 batches efficiently).
* adaptive batch sizing: detect the max number of params the server accepts per
  request (shrinks on 400/414/431 or truncated responses).
* WAF/IP-block aware via the shared HttpClient (block detection and optional
  operator-provided proxy retry).
"""
from __future__ import annotations

import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable
from urllib.parse import urlsplit, urlunparse, urlencode, parse_qsl

from .. import util
from ..config import SETTINGS
from ..http_client import HttpClient

LogFn = Callable[[str, str], None]


def _canary(n: int = 6) -> str:
    return "g2r" + "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def dedup_targets(urls: list[str]) -> dict[str, dict]:
    """signature -> {url, base, known_params}."""
    out: dict[str, dict] = {}
    for u in urls:
        if not util.has_params(u):
            continue
        sig = util.param_signature(u)
        if sig in out:
            continue
        p = urlsplit(u if "://" in u else "http://" + u)
        known = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        base = urlunparse((p.scheme, p.netloc, p.path, "", "", ""))
        out[sig] = {"url": u, "base": base, "known_params": known}
    return out


def order_diverse(targets: dict[str, dict]) -> list[dict]:
    """Round-robin signatures across hosts so a capped scan covers MANY
    subdomains instead of just the busiest one. Without this, app.adjust.com
    (millions of tracking urls) would monopolise the first N signatures and the
    other subdomains would never be tested."""
    from collections import defaultdict, deque
    buckets: dict[str, deque] = defaultdict(deque)
    for it in targets.values():
        host = urlsplit(it["base"]).hostname or ""
        buckets[host].append(it)
    dqs = [dq for dq in buckets.values()]
    order: list[dict] = []
    while dqs:
        nxt = []
        for dq in dqs:
            if dq:
                order.append(dq.popleft())
            if dq:
                nxt.append(dq)
        dqs = nxt
    return order


def _build_url(base: str, markers: dict[str, str]) -> str:
    p = urlsplit(base)
    return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(markers), ""))


# Raw survival of any of these breakout chars next to the marker means the
# reflection is UNENCODED (a real XSS candidate). If they come back HTML/URL-
# encoded, the reflection is harmless — that was the dominant false positive
# (773/780 of the 8x8 "reflections" were encoded text echoes).
_BREAK = "\"'<>"


def _reflection_info(body: str, token: str) -> tuple[str, str]:
    """Return (contexts, raw_break) for a marker echoed in ``body``.

    raw_break = the subset of ``_BREAK`` chars that appear UNENCODED immediately
    after the marker. Empty => reflected but encoded => NOT exploitable.
    """
    ctx: set[str] = set()
    raw: set[str] = set()
    for m in re.finditer(re.escape(token), body):
        i = m.start()
        pre = body[max(0, i - 60): i]
        seg = body[i + len(token): i + len(token) + 12]
        low = pre.lower()
        if "<script" in low and "</script" not in low:
            ctx.add("js")
        elif re.search(r"=\s*[\"'][^\"'<>]*$", pre):
            ctx.add("attribute")
        elif ">" in pre and "<" not in pre.split(">")[-1]:
            ctx.add("html")
        else:
            ctx.add("text")
        for ch in _BREAK:
            if ch in seg:
                raw.add(ch)
    return ",".join(sorted(ctx)) or "body", "".join(c for c in _BREAK if c in raw)


class ReflectionScanner:
    def __init__(self, client: HttpClient, max_params_per_url: int = 1024,
                 start_batch: int = 64):
        self.client = client
        self.max_params_per_url = max_params_per_url
        self.start_batch = start_batch

    def _probe_batch(self, base: str, names: list[str]) -> tuple[dict, int, bool]:
        """Send one batch; return (reflected{name:{contexts,raw}}, status, shrink?).

        Each canary carries trailing breakout chars so we can tell an exploitable
        (raw) reflection from a harmless encoded echo."""
        markers = {name: _canary() for name in names}
        url = _build_url(base, {name: tok + _BREAK for name, tok in markers.items()})
        r = self.client.get(url, allow_redirects=True)
        if r.status in (400, 413, 414, 431) or r.error:
            return {}, r.status, True
        body = r.text or ""
        reflected: dict[str, dict] = {}
        for name, token in markers.items():
            if token in body:
                ctx, raw = _reflection_info(body, token)
                reflected[name] = {"contexts": ctx, "raw": raw}
        return reflected, r.status, False

    def _control_reflects(self, base: str) -> tuple[bool, str, str]:
        """x8-style guard: probe a RANDOM param name no endpoint expects. If its
        canary is echoed back, the page reflects ARBITRARY params (it prints the
        request URL / whole query string — e.g. a canonical link or a
        'page not found: <url>' message), so enumerating the wordlist would record
        hundreds of meaningless rows. Detect it with one probe and collapse to a
        single finding. Returns (reflects, contexts, raw_break)."""
        name = "g2rctl" + _canary(5)
        reflected, _status, _ = self._probe_batch(base, [name])
        info = reflected.get(name)
        if info:
            return True, info["contexts"], info["raw"]
        return False, "", ""

    @staticmethod
    def _ctx_label(contexts: str, raw: str) -> str:
        # make exploitability explicit in the stored contexts string so the UI /
        # report can filter real XSS candidates from harmless encoded echoes
        return contexts + (" UNENCODED:" + raw if raw else " (encoded)")

    def scan_url(self, base: str, candidate_params: list[str]) -> list[dict]:
        names = candidate_params[: self.max_params_per_url]
        # reflects-everything guard (see _control_reflects): one finding, not noise
        any_refl, any_ctx, any_raw = self._control_reflects(base)
        if any_refl:
            return [{
                "url": base,
                "param": "*any* (reflects arbitrary params)",
                "contexts": self._ctx_label(any_ctx or "body", any_raw),
                "payload": any_raw, "status_code": 200,
            }]
        results: list[dict] = []
        batch = self.start_batch
        i = 0
        while i < len(names):
            chunk = names[i: i + batch]
            reflected, status, shrink = self._probe_batch(base, chunk)
            if shrink and batch > 4:
                batch = max(4, batch // 2)   # adaptive max-param detection
                continue
            for name, info in reflected.items():
                results.append({
                    "url": util.with_params(base, {name: "FUZZ"}),
                    "param": name,
                    "contexts": self._ctx_label(info["contexts"], info["raw"]),
                    "payload": info["raw"], "status_code": status,
                })
            i += batch
        return results

    def scan(self, urls: list[str], wordlist: list[str], persist: Callable[[dict], None],
             log: LogFn, should_stop: Callable[[], bool],
             workers: int | None = None) -> int:
        workers = workers or SETTINGS.check_workers
        targets = dedup_targets(urls)
        log("info", f"reflection: {len(targets)} unique URL signatures "
                    f"(from {len(urls)} urls), wordlist={len(wordlist)}")
        count = 0

        def work(item):
            base = item["base"]
            cand = list(dict.fromkeys(item["known_params"] + wordlist))
            return self.scan_url(base, cand)

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(work, it): sig for sig, it in targets.items()}
            for fut in as_completed(futs):
                if should_stop():
                    break
                try:
                    for res in fut.result():
                        persist(res)
                        count += 1
                except Exception as e:
                    log("warn", f"reflection error: {e}")
        log("info", f"reflection: {count} reflected params")
        return count
