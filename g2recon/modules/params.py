"""Parameter inventory: base params.txt + params mined from archived URLs."""
from __future__ import annotations

import re
from pathlib import Path

from .. import util

_PARAM_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,48}$")
_HAS_LETTER = re.compile(r"[A-Za-z]")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LONG_HEX = re.compile(r"^[0-9a-f]{24,}$", re.I)


def is_param_name(name: str) -> bool:
    """A usable parameter *name* (not a value/token/hash).

    Rejects archive noise: pure numbers, UUIDs, long hex digests, and tokens
    with no letters. Real param names (q, id, redirect_uri, utm_source…) always
    contain a letter and are short.
    """
    if not name or not _PARAM_NAME.match(name):
        return False
    if not _HAS_LETTER.search(name):     # pure numeric / symbols
        return False
    if _UUID.match(name) or _LONG_HEX.match(name):
        return False
    return True


def collect_from_urls(urls) -> set[str]:
    out: set[str] = set()
    for u in urls:
        for name in util.url_params(u):
            if is_param_name(name):
                out.add(name)
    return out


def load_base(path: str | Path) -> set[str]:
    out: set[str] = set()
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and is_param_name(line):
            out.add(line)
    return out


_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def load_wordlist(path: str | Path) -> list[str]:
    """Permissive loader for fuzz wordlists (filenames, incl. numeric webpack
    chunk names like ``0``/``1``). Unlike load_base this keeps numeric tokens."""
    out: list[str] = []
    seen: set[str] = set()
    p = Path(path)
    if not p.exists():
        return out
    for line in p.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # allow a bare extension to be split off; keep the stem
        if _WORD.match(line) and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def write_params_file(path: str | Path, names) -> int:
    names = sorted(set(names))
    Path(path).write_text("\n".join(names) + ("\n" if names else ""))
    return len(names)
