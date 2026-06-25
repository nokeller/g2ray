"""Wayback Machine (archive.org) CDX harvester.

* iterates per-subdomain, per-year (time-travel) from `from_year` to now
* paginates the CDX API in batches (default 5000) using resumeKey
* persists a resume cursor per (target, host, year) so a stopped job continues
* archive.org throttles aggressively -> the HttpClient detects 403/429/block
  signatures, can retry through configured proxies, and we add bounded backoff
"""
from __future__ import annotations

import datetime as dt
import json
import time
from typing import Callable, Iterable, Optional

from ..http_client import HttpClient

LogFn = Callable[[str, str], None]
CDX = "https://web.archive.org/cdx/search/cdx"


def archive_raw_url(ts: str, original: str) -> str:
    """Raw archived content (no Wayback rewriting) via the `id_` modifier."""
    return f"https://web.archive.org/web/{ts}id_/{original}"


def year_range(from_year: int, to_year: int) -> list[int]:
    now = dt.datetime.now(dt.timezone.utc).year
    if not from_year:
        from_year = 2010
    if not to_year:
        to_year = now
    return list(range(from_year, to_year + 1))


def _parse_cdx_json(text: str) -> tuple[list[dict], Optional[str]]:
    rows: list[dict] = []
    resume: Optional[str] = None
    try:
        data = json.loads(text)
    except Exception:
        return rows, None
    if not data:
        return rows, None
    header = data[0]
    idx = {name: i for i, name in enumerate(header)}
    for row in data[1:]:
        if not row:           # [] separator before resume key
            continue
        if len(row) == 1:     # resume key row
            resume = row[0]
            continue
        def g(name):
            i = idx.get(name)
            return row[i] if i is not None and i < len(row) else ""
        rows.append({
            "original": g("original"),
            "timestamp": g("timestamp"),
            "statuscode": g("statuscode"),
            "mimetype": g("mimetype"),
            "digest": g("digest"),
        })
    return rows, resume


def cdx_page(client: HttpClient, host: str, year: int, resume_key: Optional[str],
             batch: int) -> tuple[list[dict], Optional[str], object]:
    params = [
        f"url={host}", "matchType=host",
        "output=json", "fl=original,timestamp,statuscode,mimetype,digest",
        "collapse=urlkey", f"limit={batch}", "showResumeKey=true",
        f"from={year}0101000000", f"to={year}1231235959",
    ]
    if resume_key:
        from urllib.parse import quote
        params.append("resumeKey=" + quote(resume_key, safe=""))
    url = CDX + "?" + "&".join(params)

    last = None
    for attempt in range(4):
        r = client.get(url, timeout=90)
        last = r
        if r.ok and r.text.strip():
            rows, nxt = _parse_cdx_json(r.text)
            return rows, nxt, r.waf
        if r.ok and not r.text.strip():
            return [], None, r.waf      # legitimately empty year
        time.sleep(min(2 ** attempt, 8))
    return [], None, (last.waf if last else None)


def snapshots_for(client: HttpClient, url: str, log: LogFn,
                  limit: int = 500) -> list[dict]:
    """All capture timestamps for a single URL (for robots.txt-style time-travel)."""
    from urllib.parse import quote
    u = (f"{CDX}?url={quote(url, safe='')}&output=json"
         f"&fl=timestamp,original,statuscode,mimetype,digest&limit={limit}")
    r = client.get(u, timeout=60)
    if not r.ok:
        return []
    rows, _ = _parse_cdx_json(r.text)
    return rows


def harvest_host(client: HttpClient, host: str, *,
                 years: Iterable[int], batch: int,
                 on_rows: Callable[[list[dict]], None],
                 get_cursor: Callable[[str], Optional[str]],
                 set_cursor: Callable[[str, str], None],
                 log: LogFn,
                 should_stop: Callable[[], bool]) -> int:
    """Harvest every URL for one host. Returns count of rows emitted."""
    total = 0
    for year in years:
        if should_stop():
            return total
        done_key = f"y{year}:done"
        if get_cursor(done_key) == "1":
            continue
        resume = get_cursor(f"y{year}:resume") or None
        pages = 0
        while True:
            if should_stop():
                return total
            rows, nxt, verdict = cdx_page(client, host, year, resume, batch)
            if rows:
                on_rows(rows)
                total += len(rows)
            pages += 1
            if verdict is not None and getattr(verdict, "blocked", False):
                log("warn", f"{host} {year}: archive block ({verdict.reason}); "
                            f"cursor saved for resume")
                if resume:
                    set_cursor(f"y{year}:resume", resume)
                break
            if not nxt:
                set_cursor(done_key, "1")
                break
            resume = nxt
            set_cursor(f"y{year}:resume", resume)
            time.sleep(0.2)
        if pages:
            log("info", f"{host} {year}: {total} urls so far")
    return total
