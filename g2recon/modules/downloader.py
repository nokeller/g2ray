"""Download archived + live copies of JS / JSON / juicy files.

Each stored file keeps its source URL and the *parent* URL it was discovered
from, so recursively-found JS can be traced back to where to look for it.
"""
from __future__ import annotations

import hashlib
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

from .. import util
from ..config import SETTINGS
from ..http_client import HttpClient
from .wayback import archive_raw_url

LogFn = Callable[[str, str], None]


def _safe_name(url: str) -> str:
    p = urlsplit(url)
    name = (p.path.rsplit("/", 1)[-1] or "index")
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)[:80]
    h = hashlib.sha1((p.path + "?" + p.query).encode()).hexdigest()[:10]
    if "." not in name:
        name += ".bin"
    return f"{name}.{h}"


class Downloader:
    def __init__(self, base_dir: Path, client: HttpClient):
        self.base = Path(base_dir)
        self.client = client

    def _dest(self, host: str, url: str, variant: str) -> Path:
        host = re.sub(r"[^A-Za-z0-9._-]", "_", host or "unknown")
        d = self.base / "downloads" / variant / host
        d.mkdir(parents=True, exist_ok=True)
        return d / _safe_name(url)

    def download_one(self, item: dict) -> Optional[dict]:
        url = item["url"]
        variant = item.get("variant", "live")
        ts = item.get("archive_ts", "")
        host = util.host_of(url)
        fetch_url = archive_raw_url(ts, url) if (variant == "archived" and ts) else url
        r = self.client.get(fetch_url, allow_redirects=True)
        if r.error or not r.content:
            return {
                "url": url, "variant": variant, "archive_ts": ts,
                "parent_url": item.get("parent_url", ""),
                "kind": item.get("kind") or util.kind_for_url(url),
                "depth": item.get("depth", 0),
                "status_code": r.status, "content_type": r.headers.get("content-type", ""),
                "path": "", "size": 0, "sha256": "", "ok": False,
                "text": "", "via_proxy": r.via_proxy,
            }
        dest = self._dest(host, url, variant)
        try:
            dest.write_bytes(r.content)
        except Exception as e:
            return None
        digest = hashlib.sha256(r.content).hexdigest()
        text = ""
        kind = item.get("kind") or util.kind_for_url(url)
        if kind in ("js", "json", "config", "map") or len(r.content) < 2_000_000:
            try:
                text = r.content.decode("utf-8", "replace")
            except Exception:
                text = ""
        ok = 200 <= r.status < 400
        return {
            "url": url, "variant": variant, "archive_ts": ts,
            "parent_url": item.get("parent_url", ""),
            "kind": kind, "depth": item.get("depth", 0),
            "status_code": r.status,
            "content_type": r.headers.get("content-type", ""),
            "path": str(dest), "size": len(r.content), "sha256": digest,
            "ok": ok, "text": text if ok else "", "via_proxy": r.via_proxy,
        }

    def download_many(self, items: list[dict], persist: Callable[[dict], None],
                      log: LogFn, should_stop: Callable[[], bool],
                      workers: int | None = None) -> int:
        workers = workers or SETTINGS.download_workers
        done = 0
        total = len(items)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.download_one, it): it for it in items}
            for fut in as_completed(futs):
                if should_stop():
                    break
                try:
                    res = fut.result()
                except Exception as e:
                    res = None
                if res:
                    persist(res)
                done += 1
                if done % 50 == 0 or done == total:
                    log("info", f"downloaded {done}/{total}")
        return done
