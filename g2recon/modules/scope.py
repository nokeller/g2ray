"""Program-scope helpers: explicit out-of-scope exclusion on top of ``util.in_scope``.

A bug-bounty program's wildcard scope (``*.target``) still excludes specific
assets (e.g. ``www.target``, ``*.msteams.target``, third-party hosts). The active
modules (livecheck / fuzz / reflection / openredirect / endpoints / takeover /
cors) must never touch those. Patterns accepted:

    www.8x8.com            exact host
    *.msteams.8x8.com      wildcard suffix (also matches msteams.8x8.com)
    jitsi.org              bare domain (matches it and any subdomain)
"""
from __future__ import annotations


def parse_patterns(text: str) -> list[str]:
    """Parse a newline/comma separated out-of-scope list into normalised hosts."""
    out: list[str] = []
    for chunk in (text or "").replace(",", "\n").splitlines():
        p = chunk.strip().lower()
        if not p or p.startswith("#"):
            continue
        # strip scheme / path / leading wildcard so '*.foo.bar', 'https://foo.bar/x'
        # and 'foo.bar' all normalise to 'foo.bar'
        if "://" in p:
            p = p.split("://", 1)[1]
        p = p.split("/", 1)[0].lstrip("*").strip(".")
        if p:
            out.append(p)
    return out


def host_excluded(host: str, patterns: list[str]) -> bool:
    h = (host or "").lower().strip(".")
    if not h:
        return False
    for p in patterns:
        if h == p or h.endswith("." + p):
            return True
    return False
