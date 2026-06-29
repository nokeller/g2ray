# g2recon

A self-hosted **bug-bounty reconnaissance platform** with a web console. One
target → subdomains → Wayback URL harvesting → JS/juicy-file download &
analysis → parameter mining → reflection / open-redirect testing → live probing
→ content fuzzing. Every HTTP request uses a real **Chrome (curl_cffi
impersonate) TLS fingerprint** and falls back to **proxies / WARP on WAF / 403 /
rate-limit** blocks.

> ⚠️ **Authorized use only.** Only run g2recon against assets you own or are
> explicitly authorized to test (e.g. an active bug-bounty scope). You are
> responsible for staying within program rules, rate limits and the law.

---

## Quick start

```bash
cd g2recon
./install.sh                 # venv + deps (+ subfinder if go is present)
# it prints / saves an admin password (data/INITIAL_PASSWORD.txt)
./run.sh                     # or:  G2RECON_PORT=64521 .venv/bin/python -m g2recon
# open http://localhost:64521  (default port)
```

Server install (systemd, auto-restart):

```bash
sudo ./install.sh --service --port 64521 --user admin --password 'choose-a-strong-one'
systemctl status g2recon
```

The UI listens on a **high custom port (default 64521) with login auth**. Put it
behind an SSH tunnel or TLS reverse-proxy — do **not** expose plain HTTP auth to
the internet:

```bash
ssh -L 64521:127.0.0.1:64521 dev@your-server   # then browse localhost:64521
```

---

## How it works (pipeline steps — each can be excluded in the UI)

| # | Step | What it does |
|---|------|--------------|
| 1 | **subdomains** | paste list / import `subindex` output / crt.sh / subfinder / Wayback / OTX / HackerTarget / RapidDNS, scope-filtered |
| 2 | **wayback** | per-host, per-year CDX harvest in resumable batches (default 5000) with proxy/WARP fallback; classifies juicy files & URLs-with-params |
| 3 | **files** | downloads **archived + live** copies of JS/JSON/config/map/juicy files; records each file's **parent URL**; recursively discovers & fetches new JS referenced inside |
| 4 | **params** | merges your `params.txt` with every parameter mined from archives → `TARGET_parameters.txt` |
| 5 | **reflection** | x8-style reflection scanner: dedups by path+param-set, unique per-param canaries, adaptive max-param batch detection |
| 6 | **openredirect** | injects an off-site canary into redirect-prone params, detects header & client-side redirect sinks |
| 7 | **livecheck** | curl_cffi probe of every discovered path → status / title / content-type / length |
| 8 | **fuzz** | curl_cffi content discovery (`FUZZ.<ext>`) per discovered directory, with soft-404 baselining and proxy-on-403 |

JS/juicy analysis also runs **secret detection** (AWS, GCP, Google, GitHub,
Slack, Stripe, JWT, private keys, generic api-key assignments, …) and harvests
**in-scope subdomains leaked in file contents**.

---

## Where each requested feature lives

- subindex import / paste subs → `modules/subdomains.py` (`from_subindex_import`, `from_paste`)
- crt.sh + subfinder + more → `modules/subdomains.py`
- archive.org per-subdomain, time-travel, year batches + resume → `modules/wayback.py`
- 403 / WAF / IP-block detection + proxy + WARP fallback → `waf.py`, `http_client.py`
- curl_cffi Chrome-124 impersonation everywhere → `http_client.py`
- JS link/endpoint extraction (LinkFinder-style) + recursive new-JS discovery → `modules/jsanalyze.py`
- parent-URL mapping for every file → `db.py:FileRecord.parent_url`, `jslinks.source_file`
- secret scanning → `modules/jsanalyze.py:find_secrets`
- subdomain harvest from JS → `modules/jsanalyze.py` (`hosts_in_text`)
- `TARGET_parameters.txt` from base + archive params → `modules/params.py`, `pipeline.py:_step_params`
- reflection (x8-like, dedup, batch detection) → `modules/reflection.py`
- open redirect → `modules/openredirect.py`
- ffuf replacement (curl_cffi fuzzer, proxy-on-403, `-mc all` style) → `modules/fuzz.py`
- live path check (status/title/type) → `modules/livecheck.py`
- panel + auth on high port + target management + exports → `server.py`, `web/`

> **Note on ffuf:** ffuf is written in Go and cannot literally embed the Python
> `curl_cffi` library, so g2recon ships an **equivalent fuzzer built directly on
> the curl_cffi Chrome-impersonation engine** (`modules/fuzz.py`). It gives the
> behavior you wanted (real Chrome fingerprint, proxy auto-switch on 403-WAF,
> soft-404 detection, `-mc all`) without a brittle Go recompile.

---

## Proxies & IP rotation

Add proxies in **Settings** (UI), one per line. Both formats work:

```
host:port:user:pass
scheme://user:pass@host:port
```

Default behavior: **proxyless first**, switch to proxies only when a WAF /
403 / 429 signature is detected. Optionally set a **WARP/VPN rotation command**
in Settings (e.g. `warp-cli disconnect && warp-cli connect`) — g2recon only ever
runs that exact command, so it will not touch your SSH session.

Proxy credentials are stored **only** in `data/config.json` on your server and
are masked in the API/UI. They are never committed to the repo.

---

## Data & exports

Per-target data lives under `data/targets/<target>/`:

```
<target>_subdomains.txt   <target>_urls.txt   <target>_parameters.txt
<target>_reflected.txt    <target>_openredirect.txt
downloads/<live|archived>/<host>/<file>
```

In the UI every tab has search, paging, **CSV export**, secure **raw file
download**, and per-target **ZIP export** (all behind login).

---

## subfinder / subindex

- **subfinder** is optional; the installer fetches it if Go is available.
  Without it, the other passive sources still run.
- **subindex** runs on your own machine; export its output and paste it into the
  run dialog (or tick only the sources you want and paste your own subdomain
  list to skip remote enumeration entirely).

## Configuration

Env overrides: `G2RECON_PORT`, `G2RECON_HOST`, `G2RECON_ADMIN_USER`,
`G2RECON_ADMIN_PASSWORD`, `G2RECON_DATA_DIR`. Everything else is editable from
the Settings panel (workers, batch sizes, request delay, proxies, WARP, password).

## Stack

FastAPI · curl_cffi · SQLAlchemy/SQLite (WAL) · vanilla-JS SPA. No Node build
step. Python 3.10+.
