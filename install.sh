#!/usr/bin/env bash
# g2recon installer - sets up a venv, installs deps, persists an admin password,
# and (optionally) installs a systemd service. Safe to re-run.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

PORT="${G2RECON_PORT:-64521}"
ADMIN_USER="${G2RECON_ADMIN_USER:-admin}"
ADMIN_PASS="${G2RECON_ADMIN_PASSWORD:-}"
WANT_SERVICE=0
WANT_SUBFINDER=1
PYBIN="${PYBIN:-python3}"

usage(){ cat <<EOF
g2recon installer
  --port N            UI port (default 64521)
  --user NAME         admin username (default admin)
  --password PASS     admin password (default: prompt, else random)
  --service           install + start a systemd service (needs root)
  --no-subfinder      skip installing subfinder
EOF
}
while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="$2"; shift 2;;
    --user) ADMIN_USER="$2"; shift 2;;
    --password) ADMIN_PASS="$2"; shift 2;;
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
echo "==> installing python dependencies"
pip install -r requirements.txt

# optional: subfinder for extra passive subdomains
if [[ "$WANT_SUBFINDER" == "1" ]] && ! command -v subfinder >/dev/null; then
  if command -v go >/dev/null; then
    echo "==> installing subfinder (go)"
    GOBIN="$HOME/go/bin" go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
    export PATH="$PATH:$HOME/go/bin"
  else
    echo "    (go not found - skipping subfinder; the other passive sources still work)"
  fi
fi

# password: prompt if interactive and not provided, else generate
if [[ -z "$ADMIN_PASS" ]]; then
  if [[ -t 0 ]]; then
    read -rsp "Set admin password (blank = generate random): " ADMIN_PASS; echo
  fi
fi

echo "==> initialising config (data/config.json)"
if [[ -n "$ADMIN_PASS" ]]; then
  G2RECON_ADMIN_USER="$ADMIN_USER" G2RECON_ADMIN_PASSWORD="$ADMIN_PASS" \
    python -c "import g2recon.config" >/dev/null
  echo "    admin password set."
else
  G2RECON_ADMIN_USER="$ADMIN_USER" python -c "import g2recon.config"
  echo "    random password written to data/INITIAL_PASSWORD.txt"
fi

mkdir -p data wordlists

if [[ "$WANT_SERVICE" == "1" ]]; then
  if [[ "$(id -u)" != "0" ]]; then echo "--service needs root"; exit 1; fi
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
User=${SUDO_USER:-root}

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now g2recon
  echo "==> service started:  systemctl status g2recon"
  echo "==> UI: http://<server-ip>:$PORT   (protect with SSH tunnel or TLS!)"
else
  echo
  echo "==> install complete. Start with:"
  echo "    cd $HERE && G2RECON_PORT=$PORT .venv/bin/python -m g2recon"
  echo "==> then open http://localhost:$PORT"
fi
