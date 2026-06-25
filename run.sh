#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; cd "$HERE"
[[ -d .venv ]] || { echo "run ./install.sh first"; exit 1; }
exec env G2RECON_PORT="${G2RECON_PORT:-64521}" .venv/bin/python -m g2recon
