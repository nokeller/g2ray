"""Pipeline orchestrator: runs the recon steps for one target.

Steps (each can be excluded from the UI):
  subdomains -> wayback -> files -> params -> reflection -> openredirect
  -> livecheck -> fuzz

* resumable: wayback keeps per-host/per-year cursors; every other step is
  idempotent (DB unique constraints dedup re-runs).
* stoppable: a threading.Event aborts between/within steps.
* thread-safe: module workers persist through a single write lock.
"""
from __future__ import annotations

import datetime as dt
import threading
import traceback
from pathlib import Path
from urllib.parse import urljoin

from sqlalchemy import select

from . import store, util
from .config import SETTINGS, WORDLIST_DIR
from .db import get_session, Target, Subdomain, Url, FileRecord, JsLink, Reflection, OpenRedirect, Endpoint
from .http_client import get_client
from .modules import (subdomains as m_sub, wayback as m_wb, downloader as m_dl,
                      jsanalyze, params as m_params, reflection as m_refl,
                      openredirect as m_or, livecheck as m_live, fuzz as m_fuzz,
                      waymore_runner as m_waymore, endpoints as m_ep)

STEP_ORDER = ["subdomains", "wayback", "files", "endpoints", "params",
              "reflection", "openredirect", "livecheck", "fuzz"]


def _is_html_shell(rec: dict) -> bool:
    """True when a non-HTML data file (js/json/xml/map/config) actually returned
    an HTML page — a SPA/soft-404 shell served for a dead path. Analyzing it
    would mine the shell's inline secrets/links and misattribute them to the
    requested file (a real source of false positives, e.g. one inline
    accessToken showing up under hundreds of dead .xml/.json paths)."""
    ct = (rec.get("content_type") or "").lower()
    if "text/html" in ct or "application/xhtml" in ct:
        return True
    head = (rec.get("text") or "")[:300].lstrip().lower()
    return head.startswith("<!doctype html") or head.startswith("<html") \
        or "<head" in head[:60]


class PipelineRunner:
    def __init__(self, target_id: int, job_id: int, options: dict,
                 stop_event: threading.Event):
        self.target_id = target_id
        self.job_id = job_id
        self.options = options or {}
        self.stop_event = stop_event
        self.session = get_session()
        self._lock = threading.Lock()
        self.client = get_client(refresh=True)
        self.target = self.session.get(Target, target_id)
        self.root = self.target.name
        self.slug = self.target.slug
        self.dir = Path(SETTINGS.data_dir) / "targets" / self.slug
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "downloads").mkdir(exist_ok=True)
        excl = set(self.options.get("excluded_steps") or [])
        self.steps = [s for s in STEP_ORDER if s not in excl]

    # -- helpers -----------------------------------------------------------
    def should_stop(self) -> bool:
        return self.stop_event.is_set()

    def log(self, level: str, step: str, msg: str):
        with self._lock:
            store.log(self.session, self.job_id, self.target_id, level, step, msg)

    def _cursor_get(self, key): return store.cursor_get(self.session, key)
    def _cursor_set(self, key, val):
        with self._lock:
            store.cursor_set(self.session, key, val)

    def _in_scope_hosts(self) -> list[str]:
        rows = self.session.execute(
            select(Subdomain.host).where(Subdomain.target_id == self.target_id)).all()
        return [r[0] for r in rows]

    def _all_urls(self, only_params=False, only_juicy=False) -> list[str]:
        q = select(Url.url).where(Url.target_id == self.target_id)
        if only_params:
            q = q.where(Url.has_params == True)  # noqa: E712
        if only_juicy:
            q = q.where(Url.is_juicy == True)    # noqa: E712
        return [r[0] for r in self.session.execute(q).all()]

    # -- run ---------------------------------------------------------------
    def run(self):
        store.update_job(self.session, self.job_id, status="running")
        self.target.status = "running"
        self.session.commit()
        total = len(self.steps)
        try:
            for idx, step in enumerate(self.steps):
                if self.should_stop():
                    self.log("warn", step, "stop requested")
                    store.update_job(self.session, self.job_id, status="stopped")
                    self.target.status = "stopped"; self.session.commit()
                    return
                store.update_job(self.session, self.job_id, current_step=step,
                                 progress=int(idx / total * 100))
                self.log("info", step, f"=== step {idx+1}/{total}: {step} ===")
                try:
                    getattr(self, f"_step_{step}")()
                except Exception as e:
                    self.log("error", step, f"{e}\n{traceback.format_exc()[:1500]}")
            store.update_job(self.session, self.job_id, status="done", progress=100,
                             current_step="done")
            self.target.status = "done"; self.session.commit()
            self.log("info", "done", "pipeline complete")
        except Exception as e:
            store.update_job(self.session, self.job_id, status="error",
                             detail=str(e)[:500])
            self.target.status = "error"; self.session.commit()
            self.log("error", "pipeline", f"fatal: {e}")
        finally:
            self.session.close()

    # -- steps -------------------------------------------------------------
    def _step_subdomains(self):
        sources = self.options.get("subdomain_sources")
        paste = self.options.get("paste_subdomains", "")
        subindex = self.options.get("subindex_output", "")
        res = m_sub.gather(self.root, self.client,
                           lambda lvl, m: self.log(lvl, "subdomains", m),
                           sources=sources, paste_text=paste, subindex_text=subindex)
        items = [(h, src) for src, hosts in res.items() for h in hosts]
        with self._lock:
            n = store.add_subdomains(self.session, self.target_id, items)
        hosts = sorted({h for hs in res.values() for h in hs})
        (self.dir / f"{self.slug}_subdomains.txt").write_text("\n".join(hosts) + "\n")
        self.log("info", "subdomains", f"{len(hosts)} unique subdomains (+{n} new in db)")

    def _step_wayback(self):
        """Archive harvesting.

        The dependable backbone is a domain-wide CDX *resumeKey* harvest: it
        works from datacenter IPs at ~50k urls/page, whereas waymore's page-mode
        wayback 503s on the same IP (that was the real cause of the tiny URL
        counts). waymore then ADDS the non-wayback passive sources (Common
        Crawl, OTX, URLScan, VirusTotal, IntelX); Common Crawl is routed through
        the operator proxy because the VPS direct IP cannot reach it.

        engine: both (default) = CDX + waymore extras; cdx = CDX only;
        waymore = CDX backbone + waymore extras."""
        engine = (self.options.get("archive_engine") or SETTINGS.archive_engine).lower()
        fy_opt = self.options.get("wayback_from_year")
        from_year = int(fy_opt if fy_opt is not None else SETTINGS.wayback_from_year)
        to_year = int(self.options.get("wayback_to_year") or SETTINGS.wayback_to_year) or 0

        # 1) CDX domain-wide resumeKey harvest — reliable, gets every url
        self._run_cdx_domain(from_year, to_year)

        # 2) waymore for the other passive sources (its own wayback excluded)
        if engine in ("waymore", "both"):
            if m_waymore.have_waymore():
                self._run_waymore(from_year, to_year)
            else:
                self.log("warn", "wayback", "waymore not installed; CDX-only archive")

        self._backfill_subdomains()
        n = self._write_urls_file()
        self.log("info", "wayback", f"{n} total urls collected")

    def _run_waymore(self, from_year: int, to_year: int) -> int:
        cfg = m_waymore.write_config(
            self.dir / "waymore_config.yml",
            urlscan_key=SETTINGS.urlscan_api_key,
            vt_key=SETTINGS.virustotal_api_key,
            intelx_key=SETTINGS.intelx_api_key,
            filter_code=str(self.options.get("archive_filter_code", "404")))
        out = self.dir / "waymore_urls.txt"
        from_date = f"{from_year}0101000000" if from_year else ""
        to_date = f"{to_year}1231235959" if to_year else ""
        kw = self.options.get("waymore_keywords_only") or None
        # route waymore through a proxy so Common Crawl (unreachable from the VPS
        # direct IP) resolves; exclude wayback (covered by the CDX harvester).
        from .http_client import normalize_proxy
        proxy = None
        use_proxy = self.options.get("waymore_use_proxy")
        use_proxy = True if use_proxy is None else bool(use_proxy)
        if use_proxy and SETTINGS.proxies:
            proxy = normalize_proxy(SETTINGS.proxies[0])
        run_to = int(self.options.get("waymore_run_timeout")
                     if self.options.get("waymore_run_timeout") is not None
                     else SETTINGS.waymore_run_timeout) or 2400
        urls = m_waymore.run(
            self.root, out, cfg,
            log=lambda lvl, m: self.log(lvl, "wayback", m),
            should_stop=self.should_stop,
            from_date=from_date, to_date=to_date, keywords_only=kw,
            run_timeout=run_to,
            limit_requests=int(self.options.get("waymore_limit_requests")
                               or SETTINGS.waymore_limit_requests),
            processes=int(self.options.get("waymore_processes")
                          or SETTINGS.waymore_processes),
            exclude_providers=["wayback"], proxy=proxy)
        payload = [{
            "url": u, "host": util.host_of(u), "source": "waymore",
            "mime": "", "archive_ts": "",
            "is_juicy": util.is_juicy_url(u), "has_params": util.has_params(u),
        } for u in urls if u]
        # store in chunks to keep the write lock short
        for i in range(0, len(payload), 2000):
            if self.should_stop():
                break
            with self._lock:
                store.add_urls(self.session, self.target_id, payload[i:i + 2000])
        self.log("info", "wayback", f"waymore stored {len(payload)} urls")
        return len(payload)

    def _run_cdx_domain(self, from_year: int, to_year: int):
        batch = int(self.options.get("wayback_batch_size") or SETTINGS.wayback_batch_size or 50000)
        if batch < 1000:
            batch = 50000
        max_rows = int(self.options.get("wayback_max_urls") or 0)
        self.log("info", "wayback", f"cdx-domain: harvesting *.{self.root} "
                 f"(years {from_year or 'all'}..{to_year or 'now'}, batch={batch}, "
                 f"max_rows={max_rows or 'all'})")
        pfx = f"wb:{self.target_id}:"

        def on_rows(rows):
            payload = []
            for r in rows:
                u = r.get("original")
                if not u:
                    continue
                payload.append({
                    "url": u, "host": util.host_of(u), "source": "wayback",
                    "mime": r.get("mimetype", ""), "archive_ts": r.get("timestamp", ""),
                    "is_juicy": util.is_juicy_url(u), "has_params": util.has_params(u),
                })
            for i in range(0, len(payload), 5000):
                if self.should_stop():
                    break
                with self._lock:
                    store.add_urls(self.session, self.target_id, payload[i:i + 5000])

        total = m_wb.harvest_domain(
            self.client, self.root, on_rows=on_rows,
            get_cursor=lambda k: self._cursor_get(pfx + k),
            set_cursor=lambda k, v: self._cursor_set(pfx + k, v),
            log=lambda lvl, m: self.log(lvl, "wayback", m),
            should_stop=self.should_stop,
            from_year=from_year, to_year=to_year, batch=batch, max_rows=max_rows)
        self.log("info", "wayback", f"cdx-domain: {total} url rows streamed")

    def _write_urls_file(self) -> int:
        out = self.dir / f"{self.slug}_urls.txt"
        seen: set[str] = set()
        n = 0
        with out.open("w") as fh:
            for (u,) in self.session.execute(
                    select(Url.url).where(Url.target_id == self.target_id)
                    ).yield_per(20000):
                if u and u not in seen:
                    seen.add(u)
                    fh.write(u + "\n")
                    n += 1
        return n

    def _backfill_subdomains(self):
        """Add in-scope hosts discovered in archive URLs to the subdomain table."""
        hosts: set[str] = set()
        for (h,) in self.session.execute(
                select(Url.host).where(Url.target_id == self.target_id,
                                       Url.host != "").distinct()).all():
            if h and util.in_scope(h, self.root):
                hosts.add(h)
        if hosts:
            with self._lock:
                n = store.add_subdomains(self.session, self.target_id,
                                         [(h, "archive") for h in hosts])
            self.log("info", "wayback", f"backfilled subdomains from archive hosts "
                                        f"({len(hosts)} in-scope hosts seen)")

    def _step_files(self):
        max_depth = int(self.options.get("max_recursion_depth", 3))
        max_files = int(self.options.get("max_files") or SETTINGS.max_files_per_target or 0)
        variants = self.options.get("download_variants") or ["live", "archived"]
        timetravel = bool(self.options.get("archive_timetravel", SETTINGS.archive_timetravel))
        max_caps = int(self.options.get("max_snapshots_per_url")
                       if self.options.get("max_snapshots_per_url") is not None
                       else SETTINGS.max_snapshots_per_url)
        from_year = int(self.options.get("wayback_from_year") or 0)
        to_year = int(self.options.get("wayback_to_year") or 0)
        dl_batch = int(self.options.get("download_batch") or 2000)

        # 1) bulk archive capture map for EVERY juicy file of the whole domain
        #    (one resumeKey CDX stream, digest-deduped) ->
        #    {host+path: {"url": original, "caps": [ts...]}}
        cap_map: dict[str, dict] = {}
        if "archived" in variants:
            exts = ["js", "mjs", "cjs", "json", "map", "xml", "yml", "yaml", "env",
                    "config", "cfg", "conf", "ini", "txt", "bak", "old", "csv",
                    "wsdl", "wadl", "properties", "toml"]
            self.log("info", "files", "building archive capture map (bulk CDX)…")
            jpfx = f"files:{self.target_id}:"
            cap_map = m_wb.juicy_capture_map(
                self.client, self.root, exts=exts,
                max_caps_per_url=(max_caps or 0) if timetravel else 1,
                from_year=from_year, to_year=to_year,
                time_budget=int(self.options.get("cap_map_budget_sec", 240)),
                log=lambda lvl, m: self.log(lvl, "files", m),
                should_stop=self.should_stop,
                get_cursor=lambda k: self._cursor_get(jpfx + k),
                set_cursor=lambda k, v: self._cursor_set(jpfx + k, v))

        # 2) download universe = juicy urls in the DB  UNION  cap_map files.
        #    (previous bug: cap_map was built but never used as a download
        #    target, so only DB juicy urls were fetched — which was ~1 when the
        #    archive harvest had failed. Now every archived juicy file is fetched
        #    even if it never appeared as a standalone collapsed URL row.)
        targets: dict[str, dict] = {}        # cap_key -> {"url":..., "parent":...}
        db_caps: dict[str, set] = {}         # cap_key -> {archive_ts,...} from harvest
        # the CDX harvest already stored an archive_ts per juicy url, so archived
        # time-travel downloads do NOT depend on the (rate-limit-prone) cap_map.
        for (u, ts) in self.session.execute(
                select(Url.url, Url.archive_ts).where(
                    Url.target_id == self.target_id,
                    Url.is_juicy == True)):  # noqa: E712
            k = m_wb._cap_key(u)
            ent = targets.get(k)
            if ent is None:
                targets[k] = {"url": u, "parent": ""}
            elif u.startswith("https://") and not ent["url"].startswith("https://"):
                ent["url"] = u
            if ts:
                db_caps.setdefault(k, set()).add(ts)
        for k, ent in cap_map.items():
            targets.setdefault(k, {"url": ent["url"], "parent": "archive"})
            db_caps.setdefault(k, set()).update(ent.get("caps") or [])

        target_entries = list(targets.values())
        if max_files:
            target_entries = target_entries[:max_files]
        self.log("info", "files", f"{len(target_entries)} unique juicy files to fetch "
                 f"(db-juicy ∪ archive-cdx; variants={variants}, depth={max_depth}, "
                 f"timetravel={timetravel}, max_caps={max_caps})")

        # 3) resume: skip (url,variant,ts) already downloaded ok in a prior run
        already: set[tuple] = set()
        for (u, v, ts) in self.session.execute(
                select(FileRecord.url, FileRecord.variant, FileRecord.archive_ts)
                .where(FileRecord.target_id == self.target_id,
                       FileRecord.size > 0)):
            already.add((u, v, ts or ""))

        dl = m_dl.Downloader(self.dir, self.client)
        seen_keys: set[str] = set()
        new_parent: dict[str, str] = {}

        def on_file(rec):
            analysis = None
            analyzable = rec.get("kind") in ("js", "json", "config", "map")
            # soft-404: a dead .js/.json/.xml path that returns the SPA HTML
            # shell must NOT be mined (false secrets/links misattributed to it).
            if analyzable and _is_html_shell(rec):
                analyzable = False
            if rec.get("ok") and rec.get("text") and analyzable:
                analysis = jsanalyze.analyze(rec["text"], rec["url"], self.root)
            rec["analyzed"] = analysis is not None
            with self._lock:
                store.add_file(self.session, self.target_id, rec)
                if analysis:
                    store.add_jslinks(self.session, self.target_id,
                                      [(l, k, rec["url"]) for (l, k) in analysis["links"]])
                    store.add_secrets(self.session, self.target_id,
                                      [{**s, "source_file": rec["url"]} for s in analysis["secrets"]])
                    if analysis["subdomains"]:
                        store.add_subdomains(self.session, self.target_id,
                                             [(h, "js") for h in analysis["subdomains"]])
                    for nf in analysis["new_files"]:
                        new_parent.setdefault(nf, rec["url"])

        def make_items(entries, depth):
            items = []
            for ent in entries:
                u = ent["url"]
                parent = ent.get("parent", "")
                kind = util.kind_for_url(u)
                if "live" in variants and (u, "live", "") not in already:
                    items.append({"url": u, "variant": "live",
                                  "parent_url": parent or util.host_of(u),
                                  "kind": kind, "depth": depth})
                if "archived" in variants:
                    caps = sorted(db_caps.get(m_wb._cap_key(u), ()), reverse=True)
                    if timetravel:
                        caps = caps[:max_caps] if max_caps else caps
                    else:
                        caps = caps[:1]
                    for ts in caps:
                        if (u, "archived", ts) in already:
                            continue
                        items.append({"url": u, "variant": "archived", "archive_ts": ts,
                                      "parent_url": parent or "archive",
                                      "kind": kind, "depth": depth})
            return items

        entries = target_entries
        depth = 0
        total_dl = 0
        while entries and depth <= max_depth:
            if self.should_stop():
                return
            items = make_items(entries, depth)
            self.log("info", "files", f"depth {depth}: {len(items)} downloads "
                                      f"queued from {len(entries)} files")
            for i in range(0, len(items), dl_batch):
                if self.should_stop():
                    return
                chunk = items[i:i + dl_batch]
                dl.download_many(chunk, on_file,
                                 lambda lvl, m: self.log(lvl, "files", m), self.should_stop)
                total_dl += len(chunk)
                if len(items) > dl_batch:
                    self.log("info", "files",
                             f"depth {depth}: {min(i + dl_batch, len(items))}/{len(items)}")
            for ent in entries:
                seen_keys.add(m_wb._cap_key(ent["url"]))
            # recursion: newly-discovered in-scope juicy files
            new_entries = []
            for nf, par in list(new_parent.items()):
                k = m_wb._cap_key(nf)
                if k not in seen_keys:
                    new_entries.append({"url": nf, "parent": par})
                    seen_keys.add(k)
            new_parent.clear()
            if max_files and len(seen_keys) >= max_files:
                break
            depth += 1
            entries = new_entries

        # --- recursion safety-net (DB-derived) -------------------------------
        # The in-memory recursion above only sees files freshly downloaded THIS
        # run; on a resumed run (a huge depth-0 archive set spread across
        # restarts) already-downloaded files are skipped and not re-analysed, so
        # their JS-referenced children can be missed. Re-derive missing in-scope
        # juicy files from the PERSISTED JsLinks and fetch+analyse them, iterating
        # to max_depth (each pass picks up children of the previous pass via the
        # links on_file just stored). Guarantees no referenced file is left out
        # regardless of how the run was interrupted/resumed.
        if "live" in variants:
            try:
                swept = 0
                for sweep_depth in range(1, max_depth + 1):
                    if self.should_stop():
                        break
                    downloaded = {u for (u,) in self.session.execute(
                        select(FileRecord.url).where(
                            FileRecord.target_id == self.target_id,
                            FileRecord.size > 0))}
                    missing: dict[str, str] = {}
                    for (link, src) in self.session.execute(
                            select(JsLink.link, JsLink.source_file).where(
                                JsLink.target_id == self.target_id,
                                JsLink.kind == "file")).yield_per(20000):
                        if not src or "://" not in src:
                            continue
                        try:
                            absu = ("https:" + link) if link.startswith("//") else urljoin(src, link)
                        except Exception:
                            continue
                        absu = absu.split("#", 1)[0]
                        h = util.host_of(absu)
                        if (util.in_scope(h, self.root)
                                and util.ext_of(absu) in util.JUICY_EXT
                                and absu not in downloaded
                                and m_wb._cap_key(absu) not in seen_keys):
                            missing.setdefault(absu, src)
                    if not missing:
                        break
                    for u in missing:
                        seen_keys.add(m_wb._cap_key(u))
                    items = [{"url": u, "variant": "live", "parent_url": p,
                              "kind": util.kind_for_url(u), "depth": sweep_depth}
                             for u, p in missing.items()]
                    self.log("info", "files", f"recursion sweep depth {sweep_depth}: "
                             f"{len(items)} JS-referenced files not yet downloaded -> fetching")
                    for i in range(0, len(items), dl_batch):
                        if self.should_stop():
                            break
                        dl.download_many(items[i:i + dl_batch], on_file,
                                         lambda lvl, m: self.log(lvl, "files", m),
                                         self.should_stop)
                    swept += len(items)
                    if max_files and len(seen_keys) >= max_files:
                        break
                if swept:
                    self.log("info", "files", f"recursion sweep fetched {swept} "
                             f"previously-missed JS-referenced files")
            except Exception as e:
                self.log("warn", "files", f"recursion sweep skipped: {e}")

        self.log("info", "files", f"downloaded/analyzed {len(seen_keys)} unique files "
                                  f"({total_dl} fetch ops incl. time-travel)")

    def _step_endpoints(self):
        """Intelligent API/endpoint discovery + multi-method probing.

        Uses the JS-extracted links (and, optionally, a re-scan of downloaded JS
        for fetch/axios method-hinted api calls), infers the target's API hosts,
        builds absolute in-scope candidate URLs (parent origin + inferred API
        hosts, route-templates expanded), and probes each with GET/OPTIONS then
        the configured write verbs — recording every non-404, non-WAF result
        with its parent JS file + inferred-host flag."""
        methods = self.options.get("endpoint_methods") or m_ep.DEFAULT_METHODS
        if isinstance(methods, str):
            methods = [m.strip() for m in methods.split(",") if m.strip()]
        max_paths = int(self.options.get("endpoint_max_paths")
                        if self.options.get("endpoint_max_paths") is not None else 30000)
        max_inferred = int(self.options.get("endpoint_inferred_hosts")
                           if self.options.get("endpoint_inferred_hosts") is not None else 3)
        scan_files = bool(self.options.get("endpoint_scan_files", True))
        scan_max = int(self.options.get("endpoint_scan_max_files")
                       if self.options.get("endpoint_scan_max_files") is not None else 20000)

        hosts = self._in_scope_hosts()
        # hosts that actually served API-looking paths = strong API-host signal
        api_origin_hosts: set[str] = set()
        for (link, kind) in self.session.execute(
                select(JsLink.link, JsLink.kind)
                .where(JsLink.target_id == self.target_id, JsLink.kind == "url")):
            if not link:
                continue
            absu = ("https:" + link) if link.startswith("//") else link
            h = util.host_of(absu)
            if h and util.in_scope(h, self.root) and m_ep.is_api_path(absu):
                api_origin_hosts.add(h)
        api_hosts = m_ep.rank_api_hosts(list(hosts) + list(api_origin_hosts), self.root,
                                        api_origin_hosts=api_origin_hosts, top=8)
        self.log("info", "endpoints", f"inferred API hosts: "
                 f"{', '.join(api_hosts) or '(none — parent origins only)'}")

        # 1) candidate (path, kind, source_file) from JS links
        items: list[tuple[str, str, str]] = []
        for (link, kind, src) in self.session.execute(
                select(JsLink.link, JsLink.kind, JsLink.source_file)
                .where(JsLink.target_id == self.target_id)).yield_per(20000):
            items.append((link, kind, src or ""))
        n_jslinks = len(items)

        # 2) optional re-scan of downloaded JS for fetch/axios api-calls the
        #    LinkFinder regex missed (template-literal endpoints, method hints)
        if scan_files:
            seen_sha: set[str] = set()
            scanned = 0
            for (furl, fpath, sha) in self.session.execute(
                    select(FileRecord.url, FileRecord.path, FileRecord.sha256)
                    .where(FileRecord.target_id == self.target_id,
                           FileRecord.kind == "js", FileRecord.size > 0)):
                if scanned >= scan_max or self.should_stop():
                    break
                if sha and sha in seen_sha:
                    continue
                if sha:
                    seen_sha.add(sha)
                try:
                    text = Path(fpath).read_text("utf-8", "replace") if fpath else ""
                except Exception:
                    continue
                if not text:
                    continue
                for (_meth, path) in jsanalyze.extract_api_calls(text[:5_000_000]):
                    items.append((path, "api", furl))
                scanned += 1
            self.log("info", "endpoints", f"re-scanned {scanned} JS files for api-calls "
                     f"(+{len(items) - n_jslinks} raw api-call paths)")

        cands, n_paths = m_ep.select_and_build(
            items, self.root, api_hosts, max_paths=max_paths, max_inferred=max_inferred)
        self.log("info", "endpoints", f"{n_paths} unique endpoint paths "
                 f"(from {len(items)} raw); built {len(cands)} candidate urls "
                 f"(cap={max_paths or 'none'})")
        if not cands:
            self.log("info", "endpoints", "no candidate endpoints to probe")
            return

        prober = m_ep.EndpointProber(self.client, methods=methods)
        workers = int(self.options.get("endpoint_workers") or SETTINGS.check_workers)

        def persist(rec):
            with self._lock:
                store.add_endpoint(self.session, self.target_id, rec)
        prober.run(cands, persist,
                   lambda lvl, m: self.log(lvl, "endpoints", m), self.should_stop,
                   workers=workers)
        self._write_endpoints_file()

    def _write_endpoints_file(self):
        rows = self.session.execute(
            select(Endpoint.method, Endpoint.status_code, Endpoint.url,
                   Endpoint.content_type, Endpoint.source_file)
            .where(Endpoint.target_id == self.target_id)
            .order_by(Endpoint.status_code, Endpoint.url)).all()
        lines = [f"{st}\t{meth}\t{u}\t{ct}\t<- {sf}"
                 for (meth, st, u, ct, sf) in rows]
        (self.dir / f"{self.slug}_endpoints.txt").write_text("\n".join(lines) + "\n")

    def _step_params(self):
        urls = self._all_urls(only_params=True)
        collected = m_params.collect_from_urls(urls)
        # params hidden inside js links with query strings
        jl = self.session.execute(
            select(JsLink.link).where(JsLink.target_id == self.target_id)).all()
        collected |= m_params.collect_from_urls([r[0] for r in jl if "?" in (r[0] or "")])

        base_path = self.options.get("base_params_path") or str(WORDLIST_DIR / "params.txt")
        base = m_params.load_base(base_path)

        with self._lock:
            store.add_params(self.session, self.target_id, [(n, "archive") for n in collected])
            store.add_params(self.session, self.target_id, [(n, "base") for n in base])
        allnames = collected | base
        out = self.dir / f"{self.slug}_parameters.txt"
        m_params.write_params_file(out, allnames)
        self.log("info", "params", f"{len(collected)} from archive + {len(base)} base "
                                   f"= {len(allnames)} -> {out.name}")

    def _step_reflection(self):
        urls = self._all_urls(only_params=True)
        if not urls:
            self.log("info", "reflection", "no parametrised urls")
            return
        max_urls = int(self.options.get("reflection_max_urls", 400))
        # dedup happens in scanner; cap raw input for safety
        from .db import Param
        words = [r[0] for r in self.session.execute(
            select(Param.name).where(Param.target_id == self.target_id)).all()]
        max_params = int(self.options.get("reflection_max_params", 1024))
        scanner = m_refl.ReflectionScanner(self.client, max_params_per_url=max_params)
        # bound by signatures, spread across hosts (not just app.adjust.com)
        sigs = m_refl.order_diverse(m_refl.dedup_targets(urls))[:max_urls]
        urls_capped = [s["url"] for s in sigs]

        def persist(rec):
            with self._lock:
                store.add_reflection(self.session, self.target_id, rec)
        scanner.scan(urls_capped, words, persist,
                     lambda lvl, m: self.log(lvl, "reflection", m), self.should_stop)
        self._write_reflection_file()

    def _write_reflection_file(self):
        rows = self.session.execute(
            select(Reflection.url, Reflection.param, Reflection.contexts)
            .where(Reflection.target_id == self.target_id)).all()
        lines = [f"{u}\t{p}\t{c}" for (u, p, c) in rows]
        (self.dir / f"{self.slug}_reflected.txt").write_text("\n".join(lines) + "\n")

    def _step_openredirect(self):
        urls = self._all_urls(only_params=True)
        if not urls:
            self.log("info", "openredirect", "no parametrised urls")
            return
        # bound by unique signatures so 130k param-urls don't explode into probes
        max_urls = int(self.options.get("openredirect_max_urls")
                       if self.options.get("openredirect_max_urls") is not None else 1500)
        sigs = m_refl.order_diverse(m_refl.dedup_targets(urls))
        if max_urls and len(sigs) > max_urls:
            self.log("warn", "openredirect", f"capping {len(sigs)} -> {max_urls} url signatures")
            sigs = sigs[:max_urls]
        urls_capped = [s["url"] for s in sigs]
        scanner = m_or.OpenRedirectScanner(self.client)

        def persist(rec):
            with self._lock:
                store.add_openredirect(self.session, self.target_id, rec)
        scanner.scan(urls_capped, persist,
                     lambda lvl, m: self.log(lvl, "openredirect", m), self.should_stop)
        rows = self.session.execute(
            select(OpenRedirect.url, OpenRedirect.param, OpenRedirect.payload, OpenRedirect.location)
            .where(OpenRedirect.target_id == self.target_id)).all()
        lines = [f"{u}\t{p}\t{pl}\t{loc}" for (u, p, pl, loc) in rows]
        (self.dir / f"{self.slug}_openredirect.txt").write_text("\n".join(lines) + "\n")

    def _step_livecheck(self):
        targets: set[str] = set()
        for h in self._in_scope_hosts():
            targets.add(f"https://{h}/")
        # resolve js links to absolute in-scope urls
        for link, kind, src in self.session.execute(
                select(JsLink.link, JsLink.kind, JsLink.source_file)
                .where(JsLink.target_id == self.target_id)).all():
            try:
                absu = urljoin(src or f"https://{self.root}/", link)
            except Exception:
                continue
            if util.in_scope(util.host_of(absu), self.root) and absu.startswith("http"):
                targets.add(absu.split("#")[0])
        # juicy urls
        for u in self._all_urls(only_juicy=True):
            targets.add(u)
        target_list = list(targets)
        cap = int(self.options.get("livecheck_max_urls")
                  if self.options.get("livecheck_max_urls") is not None else 8000)
        if cap and len(target_list) > cap:
            self.log("warn", "livecheck", f"capping {len(target_list)} -> {cap} urls "
                                          "(raise livecheck_max_urls to check more)")
            target_list = target_list[:cap]
        checker = m_live.LiveChecker(self.client)

        def persist(rec):
            with self._lock:
                store.add_liveresult(self.session, self.target_id, rec)
        checker.check_many(target_list, persist,
                           lambda lvl, m: self.log(lvl, "livecheck", m), self.should_stop)

    def _step_fuzz(self):
        base_dirs: set[str] = set()
        for (u,) in self.session.execute(
                select(FileRecord.url).where(FileRecord.target_id == self.target_id)).all():
            if util.in_scope(util.host_of(u), self.root):
                base_dirs.add(m_fuzz.base_dir_of(u))
        for u in self._all_urls(only_juicy=True):
            base_dirs.add(m_fuzz.base_dir_of(u))
        wl_path = self.options.get("fuzz_wordlist_path") or str(WORDLIST_DIR / "js_words.txt")
        words = m_params.load_wordlist(wl_path) if Path(wl_path).exists() else []
        if not words:
            words = ["app", "main", "index", "config", "settings", "admin", "api",
                     "bundle", "vendor", "runtime", "chunk", "auth", "login", "user"]
        max_words = int(self.options.get("fuzz_max_words") or 0)
        if max_words and len(words) > max_words:
            words = words[:max_words]
        max_dirs = int(self.options.get("fuzz_max_base_dirs")
                       if self.options.get("fuzz_max_base_dirs") is not None else 300)
        exts = self.options.get("fuzz_exts") or None
        fuzzer = m_fuzz.Fuzzer(self.client, exts=exts, max_base_dirs=max_dirs)

        def persist(rec):
            with self._lock:
                store.add_fuzzresult(self.session, self.target_id, rec)
        fuzzer.fuzz(list(base_dirs), list(words), persist,
                    lambda lvl, m: self.log(lvl, "fuzz", m), self.should_stop)
