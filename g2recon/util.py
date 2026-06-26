"""Shared helpers: scope, URL classification, parameter handling."""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlsplit, parse_qsl, urlencode, urlunparse

JS_EXT = {"js", "mjs", "jsx", "cjs"}
JSON_EXT = {"json"}
MAP_EXT = {"map"}
CONFIG_EXT = {"cfg", "conf", "config", "ini", "env", "yml", "yaml",
              "properties", "toml", "xml"}
JUICY_EXT = JS_EXT | JSON_EXT | MAP_EXT | CONFIG_EXT | {
    "txt", "bak", "old", "backup", "swp", "sql", "log", "zip", "tar", "gz",
    "tgz", "rar", "7z", "wadl", "wsdl", "asmx", "csv", "pem", "key", "p12",
    "pfx", "crt", "har", "db", "sqlite",
}

JUICY_NAMES = {
    "robots.txt", "sitemap.xml", ".env", ".git/config", "web.config",
    "appsettings.json", "package.json", "composer.json", "swagger.json",
    "openapi.json", "config.json", "settings.json", "credentials",
    ".npmrc", ".dockercfg", "docker-compose.yml", "firebase.json",
    "manifest.json", ".htpasswd", "phpinfo.php",
}

_DOMAIN_RE = re.compile(r"^(?:https?://)?([a-z0-9_.-]+\.[a-z]{2,})", re.I)
_HOST_IN_TEXT = re.compile(r"\b((?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,})\b", re.I)


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9.-]+", "-", name.strip().lower()).strip("-.")
    return s or "target"


def root_domain(value: str) -> str:
    value = value.strip().lower()
    m = _DOMAIN_RE.match(value)
    host = m.group(1) if m else value
    return host.strip(".")


def host_of(url: str) -> str:
    try:
        h = urlsplit(url if "://" in url else "http://" + url).hostname or ""
        return h.lower()
    except Exception:
        return ""


def in_scope(host: str, root: str) -> bool:
    host = (host or "").lower().strip(".")
    root = (root or "").lower().strip(".")
    if not host or not root:
        return False
    if not is_valid_host(host):
        return False
    return host == root or host.endswith("." + root)


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def is_valid_host(host: str) -> bool:
    """Reject archive/CDX artifacts like ``__extcc_www.adjust.com`` or hosts
    with empty/invalid DNS labels. A real hostname is dot-separated labels of
    [a-z0-9-] (not starting/ending with '-')."""
    host = (host or "").strip().strip(".").lower()
    if not host or ".." in host or len(host) > 253:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    return all(_LABEL_RE.match(lbl) for lbl in labels)


def ext_of(url: str) -> str:
    path = urlsplit(url).path
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        return last.rsplit(".", 1)[-1].lower()
    return ""


def kind_for_url(url: str) -> str:
    e = ext_of(url)
    if e in JS_EXT:
        return "js"
    if e in JSON_EXT:
        return "json"
    if e in MAP_EXT:
        return "map"
    if e in CONFIG_EXT:
        return "config"
    return "other"


def is_juicy_url(url: str) -> bool:
    e = ext_of(url)
    if e in JUICY_EXT:
        return True
    low = url.lower()
    return any(n in low for n in JUICY_NAMES)


def url_params(url: str) -> list[str]:
    try:
        q = urlsplit(url).query
        return [k for k, _ in parse_qsl(q, keep_blank_values=True)]
    except Exception:
        return []


def has_params(url: str) -> bool:
    return "?" in url and bool(url_params(url))


def param_signature(url: str) -> str:
    """Collapse URLs that share scheme+host+path+param-NAME-set.

    abc.com/search?q=a  and  abc.com/search?q=b  -> same signature
    abc.com/search?q=a  and  abc.com/search?id=b -> different signatures
    """
    p = urlsplit(url if "://" in url else "http://" + url)
    names = sorted({k.lower() for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    base = f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")
    return base + "?" + ",".join(names)


def with_params(url: str, params: dict[str, str]) -> str:
    p = urlsplit(url if "://" in url else "http://" + url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q.update(params)
    return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(q), ""))


def set_all_params(url: str, value: str) -> tuple[str, list[str]]:
    """Return url with every existing param set to *value* and the param list."""
    p = urlsplit(url if "://" in url else "http://" + url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    names = [k for k, _ in pairs]
    newq = urlencode({k: value for k in names})
    return urlunparse((p.scheme, p.netloc, p.path, "", newq, "")), names


def hosts_in_text(text: str, root: str) -> set[str]:
    out: set[str] = set()
    for m in _HOST_IN_TEXT.finditer(text or ""):
        h = m.group(1).lower().strip(".")
        if in_scope(h, root):
            out.add(h)
    return out
