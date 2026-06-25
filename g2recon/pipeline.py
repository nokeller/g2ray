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

import threading
import traceback
from pathlib import Path
from urllib.parse import urljoin

from sqlalchemy import select

from . import store, util
from .config import SETTINGS, WORDLIST_DIR
from .db import get_session, Target, Subdomain, Url, FileRecord, JsLink, Reflection, OpenRedirect
from .http_client import get_client
from .modules import (subdomains as m_sub, wayback as m_wb, downloader as m_dl,
                      jsanalyze, params as m_params, reflection as m_refl,
                      openredirect as m_or, livecheck as m_live, fuzz as m_fuzz)

STEP_ORDER = ["subdomains", "wayback", "files", "params",
              "reflection", "openredirect", "livecheck", "fuzz"]


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
        hosts = self._in_scope_hosts()
        from_year = int(self.options.get("wayback_from_year") or SETTINGS.wayback_from_year)
        to_year = int(self.options.get("wayback_to_year") or SETTINGS.wayback_to_year)
        years = m_wb.year_range(from_year, to_year)
        batch = int(self.options.get("wayback_batch_size") or SETTINGS.wayback_batch_size)
        self.log("info", "wayback", f"{len(hosts)} hosts x years {years[0]}..{years[-1]} "
                                    f"batch={batch}")

        def on_rows(rows):
            payload = []
            for r in rows:
                u = r["original"]
                if not u:
                    continue
                payload.append({
                    "url": u, "host": util.host_of(u), "source": "wayback",
                    "mime": r.get("mimetype", ""), "archive_ts": r.get("timestamp", ""),
                    "is_juicy": util.is_juicy_url(u), "has_params": util.has_params(u),
                })
            with self._lock:
                store.add_urls(self.session, self.target_id, payload)

        import concurrent.futures as cf
        workers = int(self.options.get("wayback_workers") or 3)

        def do_host(host):
            pfx = f"wb:{self.target_id}:{host}:"
            return m_wb.harvest_host(
                self.client, host, years=years, batch=batch, on_rows=on_rows,
                get_cursor=lambda k: self._cursor_get(pfx + k),
                set_cursor=lambda k, v: self._cursor_set(pfx + k, v),
                log=lambda lvl, m: self.log(lvl, "wayback", m),
                should_stop=self.should_stop)

        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(do_host, hosts))

        urls = self._all_urls()
        (self.dir / f"{self.slug}_urls.txt").write_text("\n".join(sorted(set(urls))) + "\n")
        self.log("info", "wayback", f"{len(urls)} urls collected")

    def _step_files(self):
        max_depth = int(self.options.get("max_recursion_depth", 3))
        max_files = int(self.options.get("max_files") or SETTINGS.max_files_per_target or 0)
        variants = self.options.get("download_variants") or ["live", "archived"]

        # Keep each archived timestamp. Live downloads are deduped by URL, archived
        # downloads are per URL+timestamp so time-travel captures are preserved.
        rows = self.session.execute(
            select(Url.url, Url.archive_ts).where(
                Url.target_id == self.target_id, Url.is_juicy == True)).all()  # noqa: E712
        juicy = [(u, ts) for (u, ts) in rows]
        if max_files:
            juicy = juicy[:max_files]
        self.log("info", "files", f"{len(juicy)} juicy urls to download "
                                  f"(variants={variants}, depth={max_depth})")

        items = []
        live_seen: set[str] = set()
        for u, ts in juicy:
            kind = util.kind_for_url(u)
            if "live" in variants and u not in live_seen:
                live_seen.add(u)
                items.append({"url": u, "variant": "live", "parent_url": util.host_of(u),
                              "kind": kind, "depth": 0})
            if "archived" in variants and ts:
                items.append({"url": u, "variant": "archived", "archive_ts": ts,
                              "parent_url": util.host_of(u), "kind": kind, "depth": 0})

        dl = m_dl.Downloader(self.dir, self.client)
        seen_urls: set[str] = set()
        new_parent: dict[str, str] = {}

        def on_file(rec):
            analysis = None
            if rec.get("ok") and rec.get("text") and rec.get("kind") in ("js", "json", "config", "map"):
                analysis = jsanalyze.analyze(rec["text"], rec["url"], self.root)
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

        depth = 0
        while items and depth <= max_depth:
            if self.should_stop():
                return
            self.log("info", "files", f"depth {depth}: downloading {len(items)} items")
            dl.download_many(items, on_file,
                             lambda lvl, m: self.log(lvl, "files", m), self.should_stop)
            for it in items:
                seen_urls.add(it["url"])
            # next depth = newly discovered in-scope files not yet seen
            new_urls = [u for u in new_parent.keys() if u not in seen_urls]
            new_parent_local = dict(new_parent)
            new_parent.clear()
            items = [{"url": u, "variant": "live", "parent_url": new_parent_local.get(u, ""),
                      "kind": util.kind_for_url(u), "depth": depth + 1}
                     for u in new_urls]
            if max_files and len(seen_urls) >= max_files:
                break
            depth += 1
        self.log("info", "files", f"downloaded/analyzed {len(seen_urls)} files")

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
        # bound by signatures
        sigs = list(m_refl.dedup_targets(urls).values())[:max_urls]
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
        scanner = m_or.OpenRedirectScanner(self.client)

        def persist(rec):
            with self._lock:
                store.add_openredirect(self.session, self.target_id, rec)
        scanner.scan(urls, persist,
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
        checker = m_live.LiveChecker(self.client)

        def persist(rec):
            with self._lock:
                store.add_liveresult(self.session, self.target_id, rec)
        checker.check_many(list(targets), persist,
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
        words = m_params.load_base(wl_path) if Path(wl_path).exists() else set()
        if not words:
            words = {"app", "main", "index", "config", "settings", "admin", "api",
                     "bundle", "vendor", "runtime", "chunk", "auth", "login", "user"}
        fuzzer = m_fuzz.Fuzzer(self.client)

        def persist(rec):
            with self._lock:
                store.add_fuzzresult(self.session, self.target_id, rec)
        fuzzer.fuzz(list(base_dirs), list(words), persist,
                    lambda lvl, m: self.log(lvl, "fuzz", m), self.should_stop)
