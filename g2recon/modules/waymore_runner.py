"""waymore integration (xnl-h4ck3r/waymore) for the archive step.

waymore pulls URLs for a domain from many sources at once — Wayback Machine,
Common Crawl, AlienVault OTX, URLScan, VirusTotal and Intelligence X — and is
much faster / more complete than iterating archive.org CDX per host.

Per the tool's own guidance we pass the *root domain only* (it returns every
subdomain automatically); passing a list of subdomains is slower and misses
results.

This module:
  * writes a waymore ``config.yml`` from g2recon settings (API keys + filters),
  * runs waymore as a cancellable subprocess with an overall wall-clock cap,
  * streams progress to the job log (with secrets stripped),
  * parses the resulting URL file.
"""
from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..config import SETTINGS

LogFn = Callable[[str, str], None]

_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# MIME types we never care about for recon (images / fonts / media / archives of
# binary assets). waymore filters these out of the URL list unless -f is passed.
_FILTER_MIME = (
    "text/css,image/jpeg,image/jpg,image/png,image/svg+xml,image/gif,"
    "image/tiff,image/webp,image/bmp,image/vnd,image/x-icon,"
    "image/vnd.microsoft.icon,font/ttf,font/woff,font/woff2,font/x-woff2,"
    "font/x-woff,font/otf,audio/mpeg,audio/wav,audio/webm,audio/aac,audio/ogg,"
    "video/mp4,video/mpeg,video/webm,video/ogg,video/mp2t,video/x-msvideo,"
    "video/x-flv,application/font-woff,application/font-woff2,"
    "application/vnd.ms-fontobject,binary/octet-stream,"
    "application/octet-stream,image/avif"
)
_FILTER_URL = (
    r"\.(?:css|jpe?g|png|svg|gif|tiff|webp|bmp|ico|ttf|woff2?|otf|eot|mp3|mp4|"
    r"mpe?g|webm|ogg|avi|flv|wmv|wma|aac|wav|m4a|mov)(?:\?|$)"
)


def have_waymore() -> bool:
    if shutil.which("waymore"):
        return True
    try:
        import waymore  # noqa: F401
        return True
    except Exception:
        return False


def _waymore_cmd() -> list[str]:
    """Resolve how to invoke waymore, PATH-independently.

    Prefer the console-script that sits next to the *running* interpreter
    (``<venv>/bin/waymore``) so it works under systemd regardless of PATH, then
    a PATH lookup. ``python -m waymore`` is NOT a valid fallback: this waymore
    package has no ``__main__`` module, so ``-m`` errors out — only use it as a
    last resort if no console script exists at all."""
    cand = Path(sys.executable).resolve().parent / "waymore"
    if cand.exists():
        return [str(cand)]
    exe = shutil.which("waymore")
    if exe:
        return [exe]
    return [sys.executable, "-m", "waymore"]


def write_config(path: Path, *, urlscan_key: str = "", vt_key: str = "",
                 intelx_key: str = "", filter_code: str = "404") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    cfg = (
        f"FILTER_CODE: {filter_code}\n"
        f"FILTER_MIME: {_FILTER_MIME}\n"
        f"FILTER_URL: {_FILTER_URL}\n"
        "FILTER_KEYWORDS: admin,login,api,config,backup,debug,db,git,swagger,"
        "upload,redirect,internal,token,secret,key,graphql,gql,.js,.json,.xml,"
        ".yml,.yaml,.env,.bak\n"
        f"URLSCAN_API_KEY: {urlscan_key}\n"
        f"VIRUSTOTAL_API_KEY: {vt_key}\n"
        "CONTINUE_RESPONSES_IF_PIPED: True\n"
        "WEBHOOK_DISCORD: YOUR_WEBHOOK\n"
        "TELEGRAM_BOT_TOKEN: YOUR_TOKEN\n"
        "TELEGRAM_CHAT_ID: YOUR_CHAT_ID\n"
        "DEFAULT_OUTPUT_DIR:\n"
        f"INTELX_API_KEY: {intelx_key}\n"
        "SOURCE_IP:\n"
    )
    path.write_text(cfg)
    return path


def _sanitize(line: str, secrets: Iterable[str]) -> str:
    line = _ANSI.sub("", line).rstrip()
    for sec in secrets:
        if sec:
            line = line.replace(sec, "****")
    return line


_EXCLUDE_FLAG = {
    "wayback": "-xwm", "commoncrawl": "-xcc", "otx": "-xav", "alienvault": "-xav",
    "urlscan": "-xus", "virustotal": "-xvt", "intelx": "-xix", "ghostarchive": "-xga",
}


def run(root: str, out_file: Path, config_path: Path, *,
        log: LogFn, should_stop: Callable[[], bool],
        mode: str = "U",
        processes: Optional[int] = None,
        req_timeout: Optional[int] = None,
        run_timeout: Optional[int] = None,
        limit_requests: Optional[int] = None,
        include_subs: Optional[bool] = None,
        keywords_only: Optional[str] = None,
        from_date: str = "", to_date: str = "",
        providers: Optional[list[str]] = None,
        exclude_providers: Optional[list[str]] = None,
        proxy: Optional[str] = None,
        retries: int = 2,
        extra_args: Optional[list[str]] = None) -> list[str]:
    """Run waymore (mode U) and return the harvested URL list.

    Cancellable via ``should_stop`` and bounded by ``run_timeout`` seconds
    (0 == no cap). Partial output is still returned/parsed.

    ``exclude_providers`` maps to waymore's -x* flags (we exclude ``wayback`` by
    default because archive.org page-mode 503s datacenter IPs; the reliable CDX
    resumeKey harvester covers Wayback instead). ``proxy`` (scheme://user:pass@
    host:port) is exported as HTTP(S)_PROXY so providers unreachable from the
    VPS direct IP — notably Common Crawl — succeed through the operator proxy.
    """
    out_file = Path(out_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    processes = processes if processes is not None else SETTINGS.waymore_processes
    req_timeout = req_timeout if req_timeout is not None else SETTINGS.waymore_req_timeout
    run_timeout = run_timeout if run_timeout is not None else SETTINGS.waymore_run_timeout
    limit_requests = (limit_requests if limit_requests is not None
                      else SETTINGS.waymore_limit_requests)
    include_subs = (include_subs if include_subs is not None
                    else SETTINGS.waymore_include_subs)

    procs = min(5, max(1, processes))
    cmd = _waymore_cmd() + [
        "-i", root, "-mode", mode, "-c", str(config_path),
        "-oU", str(out_file), "-ow",
        "-p", str(procs), "-t", str(max(5, req_timeout)),
        "-r", str(max(1, retries)),
    ]
    if not include_subs:
        cmd.append("-n")
    if limit_requests and limit_requests > 0:
        cmd += ["-l", str(limit_requests)]
    if keywords_only:
        cmd += ["-ko", keywords_only]
    if from_date:
        cmd += ["-from", from_date]
    if to_date:
        cmd += ["-to", to_date]
    if providers:
        cmd += ["--providers", ",".join(providers)]
    else:
        for p in (exclude_providers or []):
            flag = _EXCLUDE_FLAG.get(p.lower())
            if flag and flag not in cmd:
                cmd.append(flag)
    if extra_args:
        cmd += list(extra_args)

    secrets = [SETTINGS.urlscan_api_key, SETTINGS.virustotal_api_key,
               SETTINGS.intelx_api_key]
    log("info", f"waymore: harvesting {root} (mode {mode}, p={procs}"
                f"{', via proxy' if proxy else ''})")

    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    if proxy:
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            env[var] = proxy
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, bufsize=1, env=env,
            start_new_session=True,
        )
    except FileNotFoundError:
        log("error", "waymore binary not found")
        return []

    # Hard watchdog: enforce the wall-clock cap and cancellation even if waymore
    # blocks silently (e.g. Common Crawl / rate-limit sleeps produce no output,
    # so the readline loop alone can't time out).
    import threading
    stop_flag = {"kill": False, "reason": ""}

    def _terminate():
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                time.sleep(2)
                if proc.poll() is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def _watchdog():
        start_w = time.time()
        while proc.poll() is None:
            if run_timeout and (time.time() - start_w) > run_timeout:
                stop_flag["kill"] = True
                stop_flag["reason"] = f"run timeout {run_timeout}s"
                _terminate()
                return
            if should_stop():
                stop_flag["kill"] = True
                stop_flag["reason"] = "stop requested"
                _terminate()
                return
            time.sleep(1)

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()

    start = time.time()
    last_emit = 0.0
    try:
        for line in iter(proc.stdout.readline, ""):
            clean = _sanitize(line, secrets)
            if clean:
                now = time.time()
                lo = clean.lower()
                # surface meaningful lines; rate-limit the chatty ones
                if any(k in lo for k in ("error", "rate limit", "429",
                                         "blocked", "found", "total",
                                         "added", "links", "responses")):
                    if now - last_emit > 1.0 or "error" in lo or "rate" in lo:
                        log("info", f"waymore: {clean[:300]}")
                        last_emit = now
            if stop_flag["kill"]:
                break
    finally:
        try:
            proc.wait(timeout=10)
        except Exception:
            _terminate()
        if stop_flag["kill"] and stop_flag["reason"]:
            log("warn", f"waymore: {stop_flag['reason']}; using partial results")

    urls = parse_output(out_file)
    log("info", f"waymore: {len(urls)} urls parsed from output")
    return urls


def parse_output(out_file: Path) -> list[str]:
    p = Path(out_file)
    if not p.exists():
        return []
    seen: set[str] = set()
    out: list[str] = []
    for line in p.read_text(errors="ignore").splitlines():
        u = line.strip()
        if not u or not u.lower().startswith(("http://", "https://")):
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out
