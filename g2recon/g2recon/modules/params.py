"""Parameter inventory: base params.txt + params mined from archived URLs."""
from __future__ import annotations

import re
from pathlib import Path

from .. import util

_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,64}$")


def collect_from_urls(urls) -> set[str]:
    out: set[str] = set()
    for u in urls:
        for name in util.url_params(u):
            if _PARAM_NAME.match(name):
                out.add(name)
    return out


def load_base(path: str | Path) -> set[str]:
    out: set[str] = set()
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and _PARAM_NAME.match(line):
            out.add(line)
    return out


def write_params_file(path: str | Path, names) -> int:
    names = sorted(set(names))
    Path(path).write_text("\n".join(names) + ("\n" if names else ""))
    return len(names)
