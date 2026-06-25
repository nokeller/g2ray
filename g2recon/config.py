"""Central configuration for g2recon.

Settings are layered:  built-in defaults  <-  data/config.json  <-  environment.
Secrets (admin password, proxy credentials) are NEVER stored in the repo; they
live only in the runtime data directory or in environment variables.
"""
from __future__ import annotations

import json
import os
import secrets
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

# --- paths -----------------------------------------------------------------
PKG_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PKG_DIR.parent
DEFAULT_DATA_DIR = Path(os.environ.get("G2RECON_DATA_DIR", PROJECT_DIR / "data"))
WORDLIST_DIR = PROJECT_DIR / "wordlists"


def _pbkdf2(password: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + dk.hex()


def hash_password(password: str) -> str:
    return _pbkdf2(password, secrets.token_bytes(16))


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, _ = stored.split("$", 1)
        return secrets.compare_digest(_pbkdf2(password, bytes.fromhex(salt_hex)), stored)
    except Exception:
        return False


@dataclass
class Settings:
    host: str = "0.0.0.0"
    port: int = 64521
    admin_user: str = "admin"
    admin_password_hash: str = ""
    secret_key: str = ""
    data_dir: str = str(DEFAULT_DATA_DIR)

    # HTTP
    impersonate: str = "chrome124"
    request_timeout: int = 25
    max_retries: int = 3
    # list of "host:port:user:pass" or "scheme://user:pass@host:port"
    proxies: list[str] = field(default_factory=list)
    use_proxy_only_on_block: bool = True   # proxyless first, operator-provided proxy on block/rate-limit
    # once a host blocks the direct IP, route it through proxies for this long
    # before re-testing the direct IP again (auto-recovers when the ban lifts)
    block_cooldown_sec: int = 180

    # api keys (passive sources / waymore). NEVER committed; live in data/config.json
    urlscan_api_key: str = ""
    otx_api_key: str = ""
    virustotal_api_key: str = ""
    intelx_api_key: str = ""

    # archive harvesting
    archive_engine: str = "both"           # both | cdx | waymore
    waymore_processes: int = 5             # waymore -p (must be 1..5)
    waymore_req_timeout: int = 15          # waymore -t (per request)
    waymore_run_timeout: int = 0           # overall wall-clock cap (0 == 2400s default)
    waymore_limit_requests: int = 0        # waymore -l (0 == no limit)
    waymore_include_subs: bool = True      # pass root only (gets all subs); False adds -n
    waymore_use_proxy: bool = True         # route waymore via proxy (Common Crawl needs it)
    archive_timetravel: bool = True        # download every unique-digest archived capture
    max_snapshots_per_url: int = 25        # cap captures/file (0 == all unique digests)

    # wayback (domain-wide CDX resumeKey harvest = the reliable archive backbone)
    wayback_batch_size: int = 50000        # urls per CDX page (resumeKey paginated)
    wayback_from_year: int = 0             # 0 == all time (max coverage)
    wayback_to_year: int = 0               # 0 == current year
    wayback_max_urls: int = 0              # 0 == harvest every url (no cap)
    download_batch: int = 2000             # file downloads per scheduling batch

    # concurrency
    download_workers: int = 8
    check_workers: int = 12
    fuzz_workers: int = 15
    max_concurrent_jobs: int = 2

    # safety
    request_delay_ms: int = 0
    max_files_per_target: int = 0          # 0 == unlimited

    def public_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("admin_password_hash", None)
        d.pop("secret_key", None)
        # never leak full proxy creds to the UI; show masked
        d["proxies"] = [mask_proxy(p) for p in self.proxies]
        d["proxy_count"] = len(self.proxies)
        # never leak api keys; only report whether they are set (+ a short hint)
        for key in ("urlscan_api_key", "otx_api_key", "virustotal_api_key",
                    "intelx_api_key"):
            val = d.pop(key, "") or ""
            d[key + "_set"] = bool(val)
            d[key + "_hint"] = (val[:4] + "…" + val[-2:]) if len(val) > 8 else ""
        return d


def mask_proxy(p: str) -> str:
    """Mask credentials inside a proxy string for display."""
    try:
        body = p.split("://", 1)[-1]
        if "@" in body:  # scheme://user:pass@host:port
            creds, hostport = body.split("@", 1)
            user = creds.split(":", 1)[0]
            return f"{user}:****@{hostport}"
        parts = body.split(":")
        if len(parts) >= 4:  # host:port:user:pass
            return f"{parts[0]}:{parts[1]}:{parts[2]}:****"
        return body
    except Exception:
        return "****"


def _config_path(data_dir: Path) -> Path:
    return data_dir / "config.json"


def load_settings() -> Settings:
    data_dir = DEFAULT_DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = _config_path(data_dir)

    s = Settings()
    if cfg_path.exists():
        try:
            raw = json.loads(cfg_path.read_text())
            for k, v in raw.items():
                if hasattr(s, k):
                    setattr(s, k, v)
        except Exception:
            pass

    changed = False

    # environment overrides
    if os.environ.get("G2RECON_PORT"):
        s.port = int(os.environ["G2RECON_PORT"])
    if os.environ.get("G2RECON_HOST"):
        s.host = os.environ["G2RECON_HOST"]
    if os.environ.get("G2RECON_ADMIN_USER"):
        s.admin_user = os.environ["G2RECON_ADMIN_USER"]
    if os.environ.get("G2RECON_ADMIN_PASSWORD"):
        s.admin_password_hash = hash_password(os.environ["G2RECON_ADMIN_PASSWORD"])
        changed = True
    # api keys via env (optional)
    for env, attr in (("G2RECON_URLSCAN_KEY", "urlscan_api_key"),
                      ("G2RECON_OTX_KEY", "otx_api_key"),
                      ("G2RECON_VIRUSTOTAL_KEY", "virustotal_api_key"),
                      ("G2RECON_INTELX_KEY", "intelx_api_key")):
        if os.environ.get(env):
            setattr(s, attr, os.environ[env])
            changed = True

    # first-run secret key
    if not s.secret_key:
        s.secret_key = secrets.token_hex(32)
        changed = True
    # first-run password: generate a strong one and surface it once
    if not s.admin_password_hash:
        generated = secrets.token_urlsafe(12)
        s.admin_password_hash = hash_password(generated)
        changed = True
        try:
            (data_dir / "INITIAL_PASSWORD.txt").write_text(
                f"user: {s.admin_user}\npassword: {generated}\n"
                "Delete this file after you log in and change the password.\n"
            )
        except Exception:
            pass
        print(f"[g2recon] Generated admin password: {generated} "
              f"(also saved to {data_dir/'INITIAL_PASSWORD.txt'})")

    s.data_dir = str(data_dir)
    if changed:
        save_settings(s)
    return s


def save_settings(s: Settings) -> None:
    data_dir = Path(s.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    _config_path(data_dir).write_text(json.dumps(asdict(s), indent=2))


SETTINGS = load_settings()
