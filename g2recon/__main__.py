"""Run the g2recon server:  python -m g2recon"""
from __future__ import annotations

import uvicorn
from .config import SETTINGS


def main():
    print(f"[g2recon] starting on http://{SETTINGS.host}:{SETTINGS.port}  "
          f"(user: {SETTINGS.admin_user})")
    uvicorn.run("g2recon.server:app", host=SETTINGS.host, port=SETTINGS.port,
                log_level="info", workers=1)


if __name__ == "__main__":
    main()
