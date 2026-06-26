"""Standalone waymore merge: run waymore via the app's own runner from a valid
import context (placed in repo root so `import g2recon` resolves like the
systemd service `python -m g2recon`). Captures real returned URL count, merges
net-new rows as source='waymore', backfills any genuinely-new in-scope hosts.
"""
import sys, traceback
from pathlib import Path

try:
    from g2recon.config import SETTINGS
    from g2recon import store, util
    from g2recon.db import get_session, Url, Subdomain
    from g2recon.modules import waymore_runner as w
    from sqlalchemy import select, func
except Exception:
    print("IMPORT_FAIL", flush=True)
    traceback.print_exc()
    sys.exit(2)

# proxy normalizer is optional; fall back to raw string
try:
    from g2recon.http_client import normalize_proxy
except Exception:
    def normalize_proxy(p):
        return p

TARGET_ID = 1
ROOT = "adjust.com"
TDIR = Path("data/targets/adjust.com")
TDIR.mkdir(parents=True, exist_ok=True)


def log(level, msg):
    print(f"[{level}] {str(msg)[:160]}", flush=True)


def main():
    s = get_session()
    b_wm = s.execute(select(func.count()).select_from(Url).where(
        Url.target_id == TARGET_ID, Url.source == "waymore")).scalar()
    b_tot = s.execute(select(func.count()).select_from(Url).where(
        Url.target_id == TARGET_ID)).scalar()
    print(f"BEFORE waymore_rows={b_wm} total_urls={b_tot}", flush=True)

    print("WAYMORE_CMD", w._waymore_cmd(), flush=True)
    print("HAVE_WAYMORE", w.have_waymore(), flush=True)

    cfg = w.write_config(
        TDIR / "waymore_config.yml",
        urlscan_key=getattr(SETTINGS, "urlscan_api_key", "") or "",
        vt_key=getattr(SETTINGS, "virustotal_api_key", "") or "",
        intelx_key=getattr(SETTINGS, "intelx_api_key", "") or "",
        filter_code="404",
    )
    proxies = getattr(SETTINGS, "proxies", None) or []
    proxy = normalize_proxy(proxies[0]) if proxies else None
    print(f"PROXY={'set' if proxy else 'none'}", flush=True)

    urls = w.run(
        ROOT,
        TDIR / "waymore_urls.txt",
        cfg,
        log=log,
        should_stop=lambda: False,
        run_timeout=1200,
        limit_requests=5000,
        processes=3,
        exclude_providers=["wayback"],  # CDX harvester already covers Wayback
        proxy=proxy,
    )
    urls = [u for u in (urls or []) if u]
    print(f"WAYMORE_RETURNED {len(urls)}", flush=True)

    payload = [{
        "url": u,
        "host": util.host_of(u),
        "source": "waymore",
        "mime": "",
        "archive_ts": "",
        "is_juicy": util.is_juicy_url(u),
        "has_params": util.has_params(u),
    } for u in urls]
    inserted = 0
    for i in range(0, len(payload), 2000):
        inserted += store.add_urls(s, TARGET_ID, payload[i:i + 2000])

    a_wm = s.execute(select(func.count()).select_from(Url).where(
        Url.target_id == TARGET_ID, Url.source == "waymore")).scalar()
    a_tot = s.execute(select(func.count()).select_from(Url).where(
        Url.target_id == TARGET_ID)).scalar()

    wm_hosts = {util.host_of(u) for u in urls
                if util.in_scope(util.host_of(u), ROOT)}
    known = {r[0] for r in s.execute(
        select(Subdomain.host).where(Subdomain.target_id == TARGET_ID)).all()}
    newh = sorted(wm_hosts - known)
    if newh:
        store.add_subdomains(s, TARGET_ID, [(h, "waymore") for h in newh])

    print(f"RESULT waymore_rows {b_wm}->{a_wm} | total {b_tot}->{a_tot} "
          f"(+{a_tot - b_tot}) | add_urls_inserted~{inserted} | "
          f"new_inscope_hosts {len(newh)}", flush=True)
    if newh:
        print("NEW_HOSTS", ", ".join(newh[:40]), flush=True)
    s.close()
    print("DONE", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("RUN_FAIL", flush=True)
        traceback.print_exc()
        sys.exit(1)
