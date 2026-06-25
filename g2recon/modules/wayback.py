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
import re
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


def unique_snapshots(client: HttpClient, url: str, *, max_caps: int = 25,
                     from_year: int = 0, to_year: int = 0,
                     log: LogFn | None = None) -> list[dict]:
    """Return time-travel captures of one URL, de-duplicated by content digest.

    archive.org often stores hundreds of identical captures of the same file;
    we only want each *unique content* once. Newest captures are preferred when
    capping. Returns rows with timestamp/digest/statuscode/mimetype.

    NOTE: this issues one CDX request per URL, which is slow at scale. For a
    whole target prefer :func:`juicy_capture_map` (one paginated stream).
    """
    from urllib.parse import quote
    params = [f"url={quote(url, safe='')}", "output=json",
              "fl=timestamp,original,statuscode,mimetype,digest",
              "collapse=digest", "limit=5000"]
    if from_year:
        params.append(f"from={from_year}0101000000")
    if to_year:
        params.append(f"to={to_year}1231235959")
    u = CDX + "?" + "&".join(params)
    r = client.get(u, timeout=60)
    if not r.ok or not r.text.strip():
        return []
    rows, _ = _parse_cdx_json(r.text)
    seen: set[str] = set()
    uniq: list[dict] = []
    for row in rows:
        dg = row.get("digest") or row.get("timestamp")
        if dg in seen:
            continue
        seen.add(dg)
        uniq.append(row)
    uniq.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    if max_caps and len(uniq) > max_caps:
        uniq = uniq[:max_caps]
    return uniq


def _cap_key(url: str) -> str:
    """Scheme/query-agnostic key (host + path) for grouping captures of a file."""
    from urllib.parse import urlsplit
    p = urlsplit(url if "://" in url else "http://" + url)
    return (p.hostname or "").lower() + (p.path or "/")


def juicy_capture_map(client: HttpClient, root: str, *, exts: list[str],
                      batch: int = 20000, max_caps_per_url: int = 25,
                      from_year: int = 0, to_year: int = 0,
                      max_rows: int = 3_000_000,
                      log: LogFn | None = None,
                      should_stop: Callable[[], bool] | None = None) -> dict[str, dict]:
    """Build {host+path: {"url": original, "caps": [timestamps...]}} for every
    juicy-file capture of a whole domain in ONE paginated CDX stream (efficient
    + archive-friendly via resumeKey, which datacenter IPs are *not* throttled
    on, unlike waymore's page-mode).

    Captures are de-duplicated per file by content digest and capped, newest
    first. A representative original URL is kept per file so the downloader can
    fetch files discovered here even if they never appeared as a standalone URL
    row. Far cheaper than one CDX query per URL.
    """
    from urllib.parse import quote
    should_stop = should_stop or (lambda: False)
    ext_re = "|".join(re.escape(e) for e in exts)
    cap_map: dict[str, dict] = {}
    seen_digest: dict[str, set[str]] = {}
    resume: Optional[str] = None
    total = 0
    pages = 0
    while True:
        if should_stop():
            break
        params = [
            f"url={root}", "matchType=domain", "output=json",
            "fl=original,timestamp,digest,statuscode,mimetype",
            f"filter=urlkey:.*[.](?:{ext_re})(?:[?].*)?$",
            f"limit={batch}", "showResumeKey=true",
        ]
        if from_year:
            params.append(f"from={from_year}0101000000")
        if to_year:
            params.append(f"to={to_year}1231235959")
        if resume:
            params.append("resumeKey=" + quote(resume, safe=""))
        url = CDX + "?" + "&".join(params)
        r = None
        for attempt in range(6):
            r = client.get(url, timeout=90, force_proxy=(attempt >= 1))
            if r.ok and r.text.strip():
                break
            if r.ok and not r.text.strip():
                break
            time.sleep(min(2 ** attempt, 12))
        if r is None or not r.ok:
            if log:
                log("warn", f"juicy-cdx: page failed ({getattr(r,'status',0)} "
                            f"{getattr(getattr(r,'waf',None),'reason','')}) — "
                            f"keeping {len(cap_map)} files mapped so far")
            break
        rows, nxt = _parse_cdx_json(r.text)
        for row in rows:
            o = row.get("original")
            ts = row.get("timestamp")
            dg = row.get("digest") or ts
            if not o or not ts:
                continue
            key = _cap_key(o)
            ds = seen_digest.setdefault(key, set())
            if dg in ds:
                continue
            ds.add(dg)
            ent = cap_map.get(key)
            if ent is None:
                ent = {"url": o, "caps": []}
                cap_map[key] = ent
            # prefer an https original for the representative URL
            if o.startswith("https://") and not ent["url"].startswith("https://"):
                ent["url"] = o
            ent["caps"].append(ts)
            total += 1
        pages += 1
        if log and pages % 5 == 0:
            log("info", f"juicy-cdx: {pages} pages, {len(cap_map)} files, {total} captures")
        if not nxt or total >= max_rows:
            break
        resume = nxt
        time.sleep(0.2)
    # newest-first + cap per file
    for key, ent in cap_map.items():
        ent["caps"].sort(reverse=True)
        if max_caps_per_url and len(ent["caps"]) > max_caps_per_url:
            ent["caps"] = ent["caps"][:max_caps_per_url]
    if log:
        log("info", f"juicy-cdx: {len(cap_map)} files mapped, {total} unique captures")
    return cap_map


def harvest_domain(client: HttpClient, root: str, *,
                   on_rows: Callable[[list[dict]], None],
                   get_cursor: Callable[[str], Optional[str]],
                   set_cursor: Callable[[str, str], None],
                   log: LogFn,
                   should_stop: Callable[[], bool],
                   from_year: int = 0, to_year: int = 0,
                   batch: int = 50000, max_rows: int = 0) -> int:
    """Domain-wide CDX harvest of EVERY url, iterated PER YEAR (newest first)
    via resumeKey pagination.

    Why per-year: a single domain-wide resumeKey stream works great until a very
    deep offset (~1M+ rows), where archive.org stalls datacenter IPs (accepts
    the connection then hangs). Slicing by year keeps every result set shallow,
    matches the "resume per year" design, and still yields every URL once
    (in-memory dedup collapses the same URL seen across multiple years).
    ``matchType=domain`` covers all subdomains; HttpClient escalates blocked/
    stalled pages to proxies; a per-year cursor lets a killed job resume.
    """
    from urllib.parse import quote
    import datetime as _dt
    now_year = _dt.datetime.now(_dt.timezone.utc).year
    fy = from_year or 1996          # wayback machine inception
    ty = to_year or now_year
    seen_urls: set[str] = set()
    total = 0
    for year in range(ty, fy - 1, -1):     # newest first = most relevant
        if should_stop():
            break
        if get_cursor(f"dom:y{year}:done") == "1":
            continue
        resume = get_cursor(f"dom:y{year}:resume") or None
        year_total = 0
        ypages = 0
        while not should_stop():
            params = [
                f"url={root}", "matchType=domain", "output=json",
                "fl=original,timestamp,statuscode,mimetype,digest",
                "collapse=urlkey", f"limit={batch}", "showResumeKey=true",
                f"from={year}0101000000", f"to={year}1231235959",
            ]
            if resume:
                params.append("resumeKey=" + quote(resume, safe=""))
            url = CDX + "?" + "&".join(params)
            r = None
            for attempt in range(6):
                if should_stop():
                    return total
                # escalate to proxy fast: archive.org stalls deep pages from
                # datacenter IPs, so don't burn a long direct timeout each retry.
                r = client.get(url, timeout=60, force_proxy=(attempt >= 1))
                if r.ok and r.text.strip():
                    break
                if r.ok and not r.text.strip():
                    break
                time.sleep(min(2 ** attempt, 12))
            if r is None or not r.ok:
                log("warn", f"cdx-domain {year}: page failed "
                            f"status={getattr(r,'status',0)} "
                            f"{getattr(getattr(r,'waf',None),'reason','')}; "
                            f"cursor saved, resumable")
                if resume:
                    set_cursor(f"dom:y{year}:resume", resume)
                break
            rows, nxt = _parse_cdx_json(r.text)
            new_rows = []
            for row in rows:
                u = row.get("original")
                if not u or u in seen_urls:
                    continue
                seen_urls.add(u)
                new_rows.append(row)
            if new_rows:
                on_rows(new_rows)
                total += len(new_rows)
                year_total += len(new_rows)
            ypages += 1
            if ypages % 3 == 0:
                log("info", f"cdx-domain {year}: page {ypages}, "
                            f"+{year_total} new (grand {total})")
            if not nxt:
                set_cursor(f"dom:y{year}:done", "1")
                set_cursor(f"dom:y{year}:resume", "")
                break
            resume = nxt
            set_cursor(f"dom:y{year}:resume", resume)
            if max_rows and total >= max_rows:
                log("warn", f"cdx-domain: reached max_rows cap {max_rows}; cursor saved")
                return total
            time.sleep(0.15)
        if year_total or ypages:
            log("info", f"cdx-domain {year}: +{year_total} new urls "
                        f"(grand total {total})")
    return total


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
