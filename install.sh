#!/usr/bin/env bash
# g2recon installer — venv + deps (incl. waymore), admin password, optional
# API keys / proxies, and an optional systemd service on a custom high port.
# Safe to re-run. Authorized-use recon console.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PORT="${G2RECON_PORT:-64521}"
ADMIN_USER="${G2RECON_ADMIN_USER:-admin}"
ADMIN_PASS="${G2RECON_ADMIN_PASSWORD:-}"
URLSCAN_KEY="${G2RECON_URLSCAN_KEY:-}"
OTX_KEY="${G2RECON_OTX_KEY:-}"
VT_KEY="${G2RECON_VIRUSTOTAL_KEY:-}"
INTELX_KEY="${G2RECON_INTELX_KEY:-}"
PROXIES_CSV="${G2RECON_PROXIES:-}"     # comma-separated host:port:user:pass
WANT_SERVICE=0
WANT_SUBFINDER=1
PYBIN="${PYBIN:-python3}"

usage(){ cat <<EOF
g2recon installer
  --port N            UI port (default 64521)
  --user NAME         admin username (default admin)
  --password PASS     admin password (default: prompt, else random)
  --urlscan-key K     URLScan API key (for waymore)
  --otx-key K         AlienVault OTX API key
  --virustotal-key K  VirusTotal API key (optional)
  --intelx-key K      Intelligence X API key (optional)
  --proxies CSV       comma-separated proxies host:port:user:pass
  --service           install + start a systemd service (needs root)
  --no-subfinder      skip installing subfinder
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --user) ADMIN_USER="$2"; shift 2;;
    --password) ADMIN_PASS="$2"; shift 2;;
    --urlscan-key) URLSCAN_KEY="$2"; shift 2;;
    --otx-key) OTX_KEY="$2"; shift 2;;
    --virustotal-key) VT_KEY="$2"; shift 2;;
    --intelx-key) INTELX_KEY="$2"; shift 2;;
    --proxies) PROXIES_CSV="$2"; shift 2;;
    --service) WANT_SERVICE=1; shift;;
    --no-subfinder) WANT_SUBFINDER=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "unknown option: $1"; usage; exit 1;;
  esac
done

echo "==> g2recon install (port=$PORT, user=$ADMIN_USER)"
command -v "$PYBIN" >/dev/null || { echo "python3 not found"; exit 1; }

echo "==> creating virtualenv (.venv)"
"$PYBIN" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip wheel >/dev/null
echo "==> installing python dependencies (fastapi, curl_cffi, waymore, …)"
pip install -r requirements.txt
echo "==> waymore: $(waymore --version 2>/dev/null | head -1 || echo 'installed')"

# optional: subfinder for extra passive subdomains
if [[ "$WANT_SUBFINDER" == "1" ]] && ! command -v subfinder >/dev/null; then
  echo "==> installing subfinder"
  SF_OK=0
  # prefer the prebuilt release binary (no Go toolchain needed, fast)
  if command -v curl >/dev/null && command -v unzip >/dev/null; then
    SF_V="$(curl -fsSL https://api.github.com/repos/projectdiscovery/subfinder/releases/latest 2>/dev/null | grep -oP 'tag_name"\s*:\s*"v\K[0-9.]+' | head -1 || true)"
    if [[ -n "$SF_V" ]]; then
      ARCH="$(uname -m)"; case "$ARCH" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; esac
      if curl -fsSL -o /tmp/_sf.zip "https://github.com/projectdiscovery/subfinder/releases/download/v${SF_V}/subfinder_${SF_V}_linux_${ARCH}.zip" 2>/dev/null \
         && unzip -o /tmp/_sf.zip subfinder -d /tmp >/dev/null 2>&1; then
        if [[ "$(id -u)" == "0" ]]; then install -m755 /tmp/subfinder /usr/local/bin/subfinder
        else mkdir -p "$HOME/.local/bin" && install -m755 /tmp/subfinder "$HOME/.local/bin/subfinder" && export PATH="$PATH:$HOME/.local/bin"; fi
        rm -f /tmp/_sf.zip /tmp/subfinder; SF_OK=1; echo "    subfinder v$SF_V installed (prebuilt)"
      fi
    fi
  fi
  # fall back to `go install` if no prebuilt binary could be fetched
  if [[ "$SF_OK" == "0" ]]; then
    if command -v go >/dev/null; then
      echo "    (prebuilt unavailable — building with go)"
      GOBIN="$HOME/go/bin" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
      export PATH="$PATH:$HOME/go/bin"
    else
      echo "    (could not install subfinder — the other passive sources still work)"
    fi
  fi
fi

# password: prompt if interactive and not provided, else generate
if [[ -z "$ADMIN_PASS" ]]; then
  if [[ -t 0 ]]; then
    read -rsp "Set admin password (blank = generate random): " ADMIN_PASS; echo
  fi
fi

echo "==> initialising config (data/config.json)"
mkdir -p data wordlists
env G2RECON_ADMIN_USER="$ADMIN_USER" \
    ${ADMIN_PASS:+G2RECON_ADMIN_PASSWORD="$ADMIN_PASS"} \
    ${URLSCAN_KEY:+G2RECON_URLSCAN_KEY="$URLSCAN_KEY"} \
    ${OTX_KEY:+G2RECON_OTX_KEY="$OTX_KEY"} \
    ${VT_KEY:+G2RECON_VIRUSTOTAL_KEY="$VT_KEY"} \
    ${INTELX_KEY:+G2RECON_INTELX_KEY="$INTELX_KEY"} \
    python -c "import g2recon.config" >/dev/null
if [[ -z "$ADMIN_PASS" ]]; then
  echo "    random password written to data/INITIAL_PASSWORD.txt"
else
  echo "    admin password set."
fi

# proxies (host:port:user:pass, comma-separated) -> data/config.json
if [[ -n "$PROXIES_CSV" ]]; then
  echo "==> storing proxies in data/config.json"
  G2RECON_PROXIES="$PROXIES_CSV" python - <<'PY'
import json, os
from pathlib import Path
p = Path("data/config.json")
cfg = json.loads(p.read_text()) if p.exists() else {}
cfg["proxies"] = [x.strip() for x in os.environ["G2RECON_PROXIES"].split(",") if x.strip()]
p.write_text(json.dumps(cfg, indent=2))
print("    %d proxies stored" % len(cfg["proxies"]))
PY
fi

if [[ "$WANT_SERVICE" == "1" ]]; then
  if [[ "$(id -u)" != "0" ]]; then echo "--service needs root (sudo)"; exit 1; fi
  SVC=/etc/systemd/system/g2recon.service
  echo "==> writing $SVC"
  cat > "$SVC" <<EOF
[Unit]
Description=g2recon recon console
After=network.target

[Service]
Type=simple
WorkingDirectory=$HERE
Environment=G2RECON_PORT=$PORT
Environment=PATH=$HERE/.venv/bin:$HOME/go/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=$HERE/.venv/bin/python -m g2recon
Restart=on-failure
RestartSec=3
User=${SUDO_USER:-root}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now g2recon
  sleep 2
  systemctl --no-pager --full status g2recon | head -8 || true
  echo "==> UI: http://<server-ip>:$PORT   (protect with SSH tunnel or TLS!)"
else
  echo
  echo "==> install complete. Start with:"
  echo "    cd $HERE && G2RECON_PORT=$PORT .venv/bin/python -m g2recon"
  echo "==> then open http://localhost:$PORT"
fi
