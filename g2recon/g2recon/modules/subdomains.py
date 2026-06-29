"""Subdomain enumeration.

Sources (all keyless / free):
  * paste            - subdomains the user pastes directly
  * subindex_import  - output of the user's local `subindex` tool (a plain list)
  * crtsh            - crt.sh certificate transparency
  * subfinder        - projectdiscovery subfinder (if the binary is installed)
  * wayback          - hostnames seen in the Wayback CDX index
  * otx              - AlienVault OTX passive DNS
  * hackertarget     - hackertarget hostsearch
  * rapiddns         - rapiddns.io
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from typing import Callable

from .. import util
from ..http_client import HttpClient

LogFn = Callable[[str, str], None]


def _hosts_from_lines(text: str, root: str) -> set[str]:
    out: set[str] = set()
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        h = util.host_of(line) or line.lower()
        h = h.strip().strip(".")
        if util.in_scope(h, root):
            out.add(h)
    return out


def from_paste(text: str, root: str) -> set[str]:
    return _hosts_from_lines(text, root)


def from_subindex_import(text: str, root: str) -> set[str]:
    return _hosts_from_lines(text, root)


def from_crtsh(root: str, client: HttpClient, log: LogFn) -> set[str]:
    out: set[str] = set()
    url = f"https://crt.sh/?q=%25.{root}&output=json"
    r = client.get(url, timeout=40)
    if not r.ok or not r.text:
        log("warn", f"crt.sh returned status={r.status} {r.waf.reason}")
        return out
    data = None
    try:
        data = json.loads(r.text)
    except Exception:
        # crt.sh occasionally emits concatenated objects
        try:
            data = json.loads("[" + r.text.replace("}{", "},{") + "]")
        except Exception:
            for m in re.finditer(r'"name_value":"([^"]+)"', r.text):
                for h in m.group(1).split("\\n"):
                    h = h.strip().lstrip("*.").lower()
                    if util.in_scope(h, root):
                        out.add(h)
            return out
    for row in data or []:
        for field in ("name_value", "common_name"):
            val = (row.get(field) or "")
            for h in re.split(r"[\n,]", val):
                h = h.strip().lstrip("*.").lower()
                if util.in_scope(h, root):
                    out.add(h)
    return out


def from_subfinder(root: str, log: LogFn) -> set[str]:
    if not shutil.which("subfinder"):
        log("info", "subfinder not installed - skipping")
        return set()
    try:
        p = subprocess.run(
            ["subfinder", "-d", root, "-silent", "-all"],
            capture_output=True, text=True, timeout=600,
        )
        return _hosts_from_lines(p.stdout, root)
    except Exception as e:
        log("warn", f"subfinder failed: {e}")
        return set()


def from_wayback(root: str, client: HttpClient, log: LogFn) -> set[str]:
    out: set[str] = set()
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{root}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=200000")
    r = client.get(url, timeout=60)
    if not r.ok:
        log("warn", f"wayback host pull status={r.status} {r.waf.reason}")
        return out
    for line in r.text.splitlines():
        h = util.host_of(line.strip())
        if util.in_scope(h, root):
            out.add(h)
    return out


def from_otx(root: str, client: HttpClient, log: LogFn) -> set[str]:
    out: set[str] = set()
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{root}/passive_dns"
    r = client.get(url, timeout=40)
    if not r.ok:
        return out
    try:
        data = json.loads(r.text)
        for row in data.get("passive_dns", []):
            h = (row.get("hostname") or "").lower().strip(".")
            if util.in_scope(h, root):
                out.add(h)
    except Exception:
        pass
    return out


def from_hackertarget(root: str, client: HttpClient, log: LogFn) -> set[str]:
    out: set[str] = set()
    r = client.get(f"https://api.hackertarget.com/hostsearch/?q={root}", timeout=40)
    if not r.ok or "API count exceeded" in r.text:
        return out
    for line in r.text.splitlines():
        h = line.split(",")[0].strip().lower()
        if util.in_scope(h, root):
            out.add(h)
    return out


def from_rapiddns(root: str, client: HttpClient, log: LogFn) -> set[str]:
    out: set[str] = set()
    r = client.get(f"https://rapiddns.io/subdomain/{root}?full=1", timeout=40)
    if not r.ok:
        return out
    for m in re.finditer(r"<td>([a-z0-9_.-]+\." + re.escape(root) + r")</td>", r.text, re.I):
        h = m.group(1).lower().strip(".")
        if util.in_scope(h, root):
            out.add(h)
    return out


SOURCES = {
    "crtsh": from_crtsh,
    "subfinder": lambda root, client, log: from_subfinder(root, log),
    "wayback": from_wayback,
    "otx": from_otx,
    "hackertarget": from_hackertarget,
    "rapiddns": from_rapiddns,
}


def gather(root: str, client: HttpClient, log: LogFn, *,
           sources: list[str] | None = None,
           paste_text: str = "", subindex_text: str = "") -> dict[str, set[str]]:
    """Return {source: {hosts}}. Always includes the root domain itself."""
    result: dict[str, set[str]] = {}
    if paste_text:
        result["paste"] = from_paste(paste_text, root)
    if subindex_text:
        result["subindex"] = from_subindex_import(subindex_text, root)

    active = sources if sources is not None else list(SOURCES.keys())
    for name in active:
        fn = SOURCES.get(name)
        if not fn:
            continue
        try:
            found = fn(root, client, log)
            result[name] = found
            log("info", f"{name}: {len(found)} subdomains")
        except Exception as e:
            log("warn", f"{name} error: {e}")
            result[name] = set()

    result.setdefault("root", set()).add(root)
    return result
