"""JS / juicy-file analysis:

* endpoint & path extraction (LinkFinder-style regex)
* secret / credential detection (2026-grade rule set)
* in-scope subdomain harvesting from file contents
* recursive discovery of *new* JS / juicy files to fetch and re-analyse
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from .. import util

# --- LinkFinder endpoint regex (GerbenJavado/LinkFinder) -------------------
_LINK_RE = re.compile(r"""
  (?:"|'|`)
  (
    ((?:[a-zA-Z][a-zA-Z0-9+.-]{1,9}://|//)[^"'`/]{1,}\.[a-zA-Z]{2,}[^"'`]{0,})   # absolute url
    |
    ((?:/|\.\./|\./)[^"'`><,;|*()%$^/\\\[\]][^"'`><,;|()]{1,})                    # rel path
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"'`]{0,}|)) # path w/ ext
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"'`]{0,}|))               # path
    |
    ([a-zA-Z0-9_\-]{1,}\.(?:php|aspx?|jsp|json|action|html?|js|txt|xml|yml|yaml|env|config|bak)(?:[\?|#][^"'`]{0,}|)) # file
  )
  (?:"|'|`)
""", re.VERBOSE)

# --- secret detection rules -------------------------------------------------
# (name, regex, severity)
_SECRET_RULES: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key_id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("aws_secret_access_key",
     re.compile(r"(?i)aws.{0,24}?['\"]([0-9a-zA-Z/+]{40})['\"]"), "high"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("google_oauth_token", re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"), "high"),
    ("gcp_service_account", re.compile(r'"type"\s*:\s*"service_account"'), "high"),
    ("firebase_cloud_messaging",
     re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"), "high"),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "high"),
    ("slack_webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"), "high"),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,251}\b"), "high"),
    ("github_pat_fine", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{82}\b"), "high"),
    ("gitlab_pat", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b"), "high"),
    ("stripe_secret", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b"), "high"),
    ("stripe_pub", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "medium"),
    ("twilio_sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "medium"),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("sendgrid_key", re.compile(r"\bSG\.[\w-]{20,}\.[\w-]{30,}\b"), "high"),
    ("mailgun_key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high"),
    ("mailchimp_key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), "medium"),
    ("square_token", re.compile(r"\b(sq0atp-[0-9A-Za-z\-_]{22}|sq0csp-[0-9A-Za-z\-_]{43})\b"), "high"),
    ("paypal_braintree",
     re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"), "high"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    ("private_key",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high"),
    ("cloudinary_url", re.compile(r"\bcloudinary://[0-9]+:[A-Za-z0-9\-_]+@[A-Za-z0-9\-_]+"), "high"),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.\-]{1,9}://[A-Za-z0-9._~%+\-]{2,}:[A-Za-z0-9._~%+\-]{2,}@[a-z0-9.\-]+\.[a-z]{2,}\b"), "high"),
    ("s3_bucket", re.compile(r"\b[a-z0-9.-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\b"), "low"),
    ("firebase_db", re.compile(r"\bhttps://[a-z0-9-]+\.firebaseio\.com\b"), "low"),
    ("authorization_bearer", re.compile(r"(?i)\bbearer\s+[a-z0-9\-_.=]{20,}"), "medium"),
    ("generic_secret",
     re.compile(r"""(?i)\b(api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|
        secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|pwd|
        private[_-]?key|x-api-key)\b['"]?\s*[:=]\s*['"]([^'"\s]{8,80})['"]""",
        re.VERBOSE), "medium"),
]

_NEW_FILE_EXT = util.JUICY_EXT  # what we recurse into

# Endpoint extraction noise: XML/RDF namespaces and bare MIME-type tokens that
# the LinkFinder regex picks up from RSS/Atom feeds, SVG and CSS but which are
# not real endpoints.
_NOISE_HOSTS = {
    "www.w3.org", "w3.org", "purl.org", "schema.org", "ns.adobe.com",
    "gmpg.org", "ogp.me", "creativecommons.org", "xmlns.com", "www.iso.org",
    "relaxng.org", "docbook.org", "www.gnu.org", "json-schema.org",
    "www.inkscape.org", "sodipodi.sourceforge.net", "validator.w3.org",
}
_MIME_TOKEN_RE = re.compile(
    r"^(?:text|image|audio|video|application|font|multipart|message|model|chemical)"
    r"/[a-z0-9][a-z0-9.+-]*$", re.I)


def _is_noise_link(link: str) -> bool:
    l = (link or "").strip().strip("'\"`")
    if not l:
        return True
    if _MIME_TOKEN_RE.match(l):                 # text/css, application/json …
        return True
    if l.startswith(("http://", "https://", "//")):
        h = util.host_of(l).lower()
        if h in _NOISE_HOSTS:
            return True
    return False


def extract_links(content: str) -> set[str]:
    out: set[str] = set()
    for m in _LINK_RE.finditer(content or ""):
        link = m.group(1)
        if link and not _is_noise_link(link):
            out.add(link.strip())
    return out


def find_secrets(content: str) -> list[dict]:
    content = content or ""
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for name, rx, sev in _SECRET_RULES:
        for m in rx.finditer(content):
            raw = m.group(0)
            key = (name, raw[:120])
            if key in seen:
                continue
            seen.add(key)
            i = m.start()
            ctx = content[max(0, i - 40): i + len(raw) + 40].replace("\n", " ").strip()
            out.append({
                "rule": name,
                "match": raw[:200],
                "severity": sev,
                "context": ctx[:240],
            })
            if len(out) > 500:
                return out
    return out


def link_kind(link: str) -> str:
    if link.startswith(("http://", "https://", "//")):
        return "url"
    if util.ext_of(link):
        return "file"
    return "path"


def analyze(content: str, source_url: str, root: str) -> dict:
    """Return links, secrets, subdomains and recursive new-file URLs."""
    links = extract_links(content)
    secrets = find_secrets(content)
    subdomains = util.hosts_in_text(content, root)

    classified: list[tuple[str, str]] = []
    new_files: set[str] = set()
    base = source_url
    for link in links:
        kind = link_kind(link)
        classified.append((link, kind))
        # resolve to absolute for recursion / live checking
        try:
            absu = urljoin(base, link) if not link.startswith("//") else "https:" + link
        except Exception:
            continue
        host = util.host_of(absu)
        if not util.in_scope(host, root):
            # still capture leaked subdomains
            if host:
                subdomains.add(host) if util.in_scope(host, root) else None
            continue
        if util.ext_of(absu) in _NEW_FILE_EXT:
            new_files.add(absu.split("#")[0])

    return {
        "links": classified,         # [(link, kind)]
        "secrets": secrets,          # [dict]
        "subdomains": subdomains,    # set
        "new_files": new_files,      # set of absolute in-scope juicy urls
    }
