# g2recon

Self-hosted bug-bounty reconnaissance console for authorized targets. One target
flows through scope-filtered subdomains, **waymore** archive harvesting, JS/JSON/
config download + recursive analysis, parameter mining, reflection/open-redirect
checks, live probing, content discovery, exports, and an authenticated UI on
port `64521`.

> Authorized use only. Keep scans inside assets you own or are explicitly allowed
> to test, and respect program rules, robots, rate limits, and local law.

## Quick start

```bash
./install.sh --port 64521
./run.sh
# open http://localhost:64521
```

Server/systemd install:

```bash
sudo ./install.sh --service --port 64521 --user admin \
  --password 'choose-a-strong-password' \
  --urlscan-key 'YOUR_URLSCAN_KEY' --otx-key 'YOUR_OTX_KEY' \
  --proxies 'host:port:user:pass,host2:port2:user2:pass2'
```

Prefer an SSH tunnel or TLS reverse proxy instead of exposing plain HTTP:

```bash
ssh -L 64521:127.0.0.1:64521 dev@your-server
```

API keys and proxies can also be set any time from the UI ⚙ Settings (stored
only in `data/config.json`, masked in the API/UI). waymore uses the URLScan key;
the OTX key is used for AlienVault passive DNS.

## Pipeline

Each step can be excluded from the run dialog.

1. **subdomains** — paste/import `subindex` output, paste arbitrary subdomains,
   and optionally query crt.sh, subfinder, Wayback hostnames, OTX, HackerTarget,
   and RapidDNS.
2. **wayback (archive)** — **waymore** is the primary engine: it pulls URLs for
   the *root domain* (gets every subdomain automatically) from Wayback Machine,
   Common Crawl, OTX, URLScan, VirusTotal and Intelligence X. A per-host/per-year
   archive.org CDX harvester (resume cursors, 5000-row batches) is the fallback
   (`archive_engine` = `waymore` | `both` | `cdx`). Hosts found in archive URLs
   are back-filled into the subdomain inventory.
3. **files** — downloads live and archived copies of JS/JSON/config/map/juicy
   files, records each parent URL, analyzes contents, and recursively fetches
   newly-discovered in-scope files. Archive **time-travel** uses one bulk,
   digest-deduplicated CDX stream so every *unique* capture of a file is fetched
   without one slow query per URL.
4. **params** — merges `params.txt` with query parameters mined from archive and
   JS links into `TARGET_parameters.txt` (UUID/hash/numeric value-tokens are
   filtered out so only real parameter names remain).
5. **reflection** — x8-style batching: dedup by `scheme://host/path?param-set`,
   unique canaries per parameter, and adaptive batch shrink on request-size
   failures.
6. **openredirect** — probes redirect-prone parameters with a canary URL and
   records Location/meta-refresh/client-side redirect evidence.
7. **livecheck** — records status, title, content type, length, and proxy use for
   discovered paths.
8. **fuzz** — ffuf-style extension-aware content discovery using the same HTTP
   client, soft-404 baselining, and `-mc all` style recording of non-baseline
   responses.

## HTTP client and proxies

All outbound requests use `curl_cffi` with browser-like impersonation when the
installed version supports it. g2recon detects common WAF/rate-limit/block
responses and records them. The strategy is **direct first, proxy on block**:
when the direct IP is WAF/rate-limit blocked for a host, requests automatically
retry through operator-provided proxies; that host is marked blocked for
`block_cooldown_sec` so it routes via proxy without hammering the direct IP, then
the direct IP is automatically re-probed when the cooldown elapses (auto-recovers
when a temporary ban lifts). Plain `403`s are kept as a real recon signal, not
treated as blocks. Proxy credentials are stored only in `data/config.json` and
masked in the API/UI.

Supported proxy formats:

```text
host:port:user:pass
scheme://user:pass@host:port
```

## Exports

Per-target data is under `data/targets/<target>/`:

```text
<target>_subdomains.txt
<target>_urls.txt
<target>_parameters.txt
<target>_reflected.txt
<target>_openredirect.txt
downloads/<live|archived>/<host>/<file>
```

Every UI tab supports search, paging, CSV export, authenticated raw file download,
and a per-target ZIP export.

## Useful commands

```bash
python -m pytest
python -m g2recon              # serve UI/API
G2RECON_DATA_DIR=/tmp/g2data python -m g2recon
```

Runtime env overrides: `G2RECON_PORT`, `G2RECON_HOST`,
`G2RECON_ADMIN_USER`, `G2RECON_ADMIN_PASSWORD`, `G2RECON_DATA_DIR`,
`G2RECON_URLSCAN_KEY`, `G2RECON_OTX_KEY`, `G2RECON_VIRUSTOTAL_KEY`,
`G2RECON_INTELX_KEY`.
