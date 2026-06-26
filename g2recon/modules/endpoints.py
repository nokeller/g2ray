"""Intelligent API / endpoint discovery + multi-method probing.

This is the headline recon engine: it turns the raw paths/URLs extracted from JS
(and juicy files) into *tested* endpoints.

Pipeline:
  1. Collect candidate (path/url, parent_file, method-hint) from JsLinks +
     (optionally) a re-scan of downloaded JS for ``fetch``/``axios`` method hints
     and api-paths the LinkFinder regex missed.
  2. Infer the target's API hosts from the subdomain inventory + the hosts that
     actually served API-looking paths (e.g. ``api.adjust.com``,
     ``tracker-api.kube.adjust.com``, ``dash.adjust.com``).
  3. For every endpoint, build candidate ABSOLUTE in-scope URLs:
       * the parent JS file's own origin (highest confidence),
       * for API-looking paths, the top inferred API hosts (host_inferred=True),
       * absolute in-scope URLs found in JS are tested as-is.
     Route templates (``/api/apps/:token``, ``{id}``, ``${x}``, ``<id>``) are
     expanded to a static-prefix probe + a canary-substituted probe.
  4. Probe each candidate with GET + OPTIONS first (existence + Allow header),
     then the configured write methods (POST/PUT/PATCH/…) only for endpoints
     that actually exist — minimising calls to dead paths.
  5. Per-host soft-404 baselining + WAF/proxy handling: record everything that
     is NOT a 404 and NOT a WAF/IP block (200/401/403-real/405/422/500/3xx…),
     keyed by (url, method), with the parent JS file + inferred-host flag.

All HTTP goes through the shared curl_cffi Chrome-impersonation client, which
retries through operator proxies on a WAF/rate-limit block and re-probes the
direct IP after a cooldown.
"""
from __future__ import annotations

import random
import re
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional
from urllib.parse import urlsplit, urlunparse

from .. import util
from ..config import SETTINGS
from ..http_client import HttpClient

LogFn = Callable[[str, str], None]

# ----------------------------------------------------------------------------
# path / template handling
# ----------------------------------------------------------------------------
# route-template tokens:  :id   {id}   ${id}   <id>   [id]   *   (.*)
_TEMPLATE_TOKEN = re.compile(
    r"(:[A-Za-z_][\w]*|\{[^}/]{1,60}\}|\$\{[^}/]{1,80}\}|<[^>/]{1,60}>|\[[^\]/]{1,60}\]|\*+)")
_CANARY_SEG = "1"   # neutral substitution for a template segment when probing


def has_template(path: str) -> bool:
    return bool(_TEMPLATE_TOKEN.search(path or ""))


def static_prefix(path: str) -> str:
    """Longest leading portion of a route template with no template token.

    ``/api/apps/:token/settings`` -> ``/api/apps/``  (so we can probe the real
    collection endpoint even when we can't fill the id)."""
    m = _TEMPLATE_TOKEN.search(path or "")
    if not m:
        return path
    cut = path[: m.start()]
    if "/" in cut:
        cut = cut[: cut.rfind("/") + 1]
    return cut or "/"


def substitute_template(path: str) -> str:
    """Replace every template token with a neutral canary segment."""
    return _TEMPLATE_TOKEN.sub(_CANARY_SEG, path or "")


def clean_path(path: str) -> str:
    """Strip a fragment, trailing junk and JS string artifacts from a raw path."""
    p = (path or "").strip().strip("'\"`").split("#", 1)[0]
    # drop a dangling query that is empty or template-only ("?","?x=${y}")
    if "?" in p:
        head, q = p.split("?", 1)
        if not q or has_template(q) or "=" not in q:
            p = head
    return p


# API-ish path detector (decides whether we bother inferring API hosts for it)
_API_HINT = re.compile(
    r"(?:^|/)(?:api|v[0-9]{1,2}|graphql|gql|rest|rpc|internal|oauth|auth|token|"
    r"session|account|accounts|user|users|admin|webhook|callback|export|import|"
    r"upload|download|search|query|report|reporting|settings|config|partner|"
    r"partners|tracker|trackers|s2s|sdk|measure|event|events|attribution)\b",
    re.I)


def is_api_path(path: str) -> bool:
    return bool(_API_HINT.search(path or ""))


def origin_of(url: str) -> str:
    p = urlsplit(url if "://" in url else "https://" + url)
    if not p.hostname:
        return ""
    scheme = p.scheme or "https"
    return f"{scheme}://{p.netloc}"


# ----------------------------------------------------------------------------
# API-host inference
# ----------------------------------------------------------------------------
_API_HOST_STRONG = re.compile(r"(?:^|[.-])(api|apis|graphql|gql)(?:$|[.-])", re.I)
_API_HOST_MED = re.compile(
    r"(?:^|[.-])(gateway|gw|apigw|backend|bff|rest|rpc|edge|service|services|"
    r"svc|tracker|s2s|partner|internal)(?:$|[.-])", re.I)
_APP_HOST = re.compile(
    r"(?:^|[.-])(dash|dashboard|app|admin|portal|console|account|accounts|my|"
    r"secure|auth|login|suite|manage|automate|insights)(?:$|[.-])", re.I)
_STATIC_HOST = re.compile(
    r"(?:^|[.-])(www|cdn|static|assets|asset|media|img|images|fonts|css|js|"
    r"download|downloads|help|docs|doc|blog|support|status|careers|jobs|press|"
    r"email|mail|go|track|click|link|links|s|t)(?:$|[.-])", re.I)


_APEX_API_LABELS = {"api", "apis", "graphql", "gql", "gateway", "gw", "rest", "rpc"}
_INFRA_TOKEN = re.compile(
    r"(?:^|[.-])(kube|k8s|esh|cluster|node|svc|internal|infra|ingress)(?:$|[.-])", re.I)


def host_score(host: str, *, api_origin_hosts: set[str]) -> int:
    h = (host or "").lower()
    labels = h.split(".")
    score = 0
    # leftmost label is exactly an API token (api.adjust.com) = canonical API host
    if labels and labels[0] in _APEX_API_LABELS:
        score += 14
    elif _API_HOST_STRONG.search(h):           # api appears elsewhere (tracker-api…)
        score += 8
    if _API_HOST_MED.search(h):
        score += 4
    if _APP_HOST.search(h):
        score += 3
    if h in api_origin_hosts:                   # actually served API paths in JS
        score += 5
    if _STATIC_HOST.search(h):
        score -= 6
    if _INFRA_TOKEN.search(h):                  # internal infra hosts rank below prod
        score -= 3
    # prefer prod over staging/qa/demo a little (still kept, just ranked lower)
    if re.search(r"(?:^|[.-])(staging|stage|qa|demo|test|dev|regress|preview|"
                 r"sandbox)(?:$|[.-])", h):
        score -= 2
    # closer to the apex (fewer labels) is usually the canonical host
    score -= max(0, len(labels) - 3)
    return score


def rank_api_hosts(hosts: list[str], root: str, *, api_origin_hosts: set[str],
                   top: int = 6) -> list[str]:
    """Return the most likely API hosts (in scope), best first."""
    scored = []
    for h in set(hosts):
        if not util.in_scope(h, root):
            continue
        sc = host_score(h, api_origin_hosts=api_origin_hosts)
        if sc > 0:
            scored.append((sc, h))
    # stable, useful ordering: score desc, then shorter host (closer to apex)
    scored.sort(key=lambda x: (-x[0], len(x[1]), x[1]))
    return [h for _, h in scored[:top]]


# ----------------------------------------------------------------------------
# candidate URL building
# ----------------------------------------------------------------------------
def _norm_url(scheme_host: str, path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    # collapse accidental double slashes in the path (but not the scheme)
    path = re.sub(r"/{2,}", "/", path)
    return scheme_host.rstrip("/") + path


def build_candidates(link: str, kind: str, source_file: str, root: str,
                     api_hosts: list[str], *, max_inferred: int = 3) -> list[dict]:
    """Return candidate probe dicts: {url, path, source_file, host_inferred}."""
    raw = clean_path(link)
    if not raw:
        return []
    out: list[dict] = []
    seen: set[str] = set()

    def emit(url: str, host_inferred: bool):
        u = url.split("#", 1)[0]
        p = urlsplit(u)
        if not p.hostname or not util.in_scope(p.hostname, root):
            return
        if u in seen:
            return
        seen.add(u)
        out.append({"url": u, "path": raw, "source_file": source_file or "",
                    "host_inferred": host_inferred})

    # path forms to probe (template-aware)
    if has_template(raw):
        forms = []
        sp = static_prefix(raw)
        if sp and sp not in ("/",):
            forms.append(sp)
        forms.append(substitute_template(raw))
    else:
        forms = [raw]

    # absolute URL found in JS -> test as-is (only the host it names)
    if raw.startswith(("http://", "https://", "//")):
        absu = ("https:" + raw) if raw.startswith("//") else raw
        # strip template tokens from absolute urls too
        for f in ([substitute_template(absu), static_prefix(absu)]
                  if has_template(absu) else [absu]):
            emit(f, host_inferred=False)
        return out

    # relative path -> parent origin first (highest confidence)
    parent_origin = origin_of(source_file) if source_file and "://" in source_file else ""
    origins: list[tuple[str, bool]] = []
    if parent_origin:
        origins.append((parent_origin, False))
    # API-looking paths also get the top inferred API hosts
    if is_api_path(raw):
        for h in api_hosts[:max_inferred]:
            o = f"https://{h}"
            if o != parent_origin:
                origins.append((o, True))
    # if we had no parent origin at all, fall back to root + www
    if not parent_origin:
        for h in (root, "www." + root):
            origins.append((f"https://{h}", h != root))

    for origin, inferred in origins:
        for f in forms:
            emit(_norm_url(origin, f), host_inferred=inferred)
    return out


# ----------------------------------------------------------------------------
# selection / prioritisation (cap the probe budget intelligently)
# ----------------------------------------------------------------------------
_ID_SEG = re.compile(
    r"/(?:\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f-]{8,}|me|self|current)(?=/|$)", re.I)
_STATIC_ASSET = re.compile(
    r"\.(?:css|png|jpe?g|gif|svg|webp|bmp|ico|tiff?|woff2?|ttf|otf|eot|mp4|webm|"
    r"mp3|wav|ogg|avi|mov|flv|wmv|pdf|zip|gz|tgz|rar|7z|dmg|exe|apk|ipa)(?:$|[?#])",
    re.I)


def collapse_ids(path: str) -> str:
    return _ID_SEG.sub("/{id}", path or "")


def is_static_asset(path: str) -> bool:
    return bool(_STATIC_ASSET.search(path or ""))


def _round_robin(buckets: dict) -> list:
    from collections import deque
    dqs = [dq for dq in buckets.values() if dq]
    order: list = []
    while dqs:
        nxt = []
        for dq in dqs:
            if dq:
                order.append(dq.popleft())
            if dq:
                nxt.append(dq)
        dqs = nxt
    return order


def select_and_build(items, root: str, api_hosts: list[str], *,
                     max_paths: int = 8000, max_inferred: int = 3):
    """De-dup raw (link, kind, source_file) by host+collapsed-path signature,
    prioritise API-looking paths and spread across hosts, cap to ``max_paths``
    distinct endpoints, then build the absolute candidate URLs to probe.

    Returns ``(candidates, n_unique_paths)``."""
    from collections import defaultdict, deque
    reps: dict[str, tuple] = {}
    for (link, kind, src) in items:
        raw = clean_path(link)
        if not raw or is_static_asset(raw):
            continue
        if raw.startswith(("http://", "https://", "//")):
            absu = ("https:" + raw) if raw.startswith("//") else raw
            host = util.host_of(absu)
            if not util.in_scope(host, root):
                continue
        else:
            if not raw.startswith("/"):
                # bare relative tokens like "foo/bar" are noisy; require a
                # leading slash OR an api hint to be worth probing
                if not is_api_path(raw):
                    continue
            host = util.host_of(src) if src and "://" in src else root
            if not util.in_scope(host, root):
                host = root
        path_part = raw.split("?", 1)[0]
        sig = host + "|" + collapse_ids(path_part).lower()
        if sig not in reps:
            reps[sig] = (raw, kind, src, host, is_api_path(raw))
    buckets_api: dict[str, deque] = defaultdict(deque)
    buckets_other: dict[str, deque] = defaultdict(deque)
    for (raw, kind, src, host, isapi) in reps.values():
        (buckets_api if isapi else buckets_other)[host].append((raw, kind, src))
    ordered = _round_robin(buckets_api) + _round_robin(buckets_other)
    if max_paths and len(ordered) > max_paths:
        ordered = ordered[:max_paths]
    cands: list[dict] = []
    for (raw, kind, src) in ordered:
        cands.extend(build_candidates(raw, kind, src, root, api_hosts,
                                      max_inferred=max_inferred))
    return cands, len(reps)


# ----------------------------------------------------------------------------
# prober
# ----------------------------------------------------------------------------
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
DEFAULT_METHODS = ["GET", "OPTIONS", "POST", "PUT", "PATCH"]
# statuses that mean "this endpoint exists / is interesting" (never 404).
# 3xx are intentionally excluded: a redirect on a discovered path is almost
# always canonicalisation (trailing slash / http→https / →login / →www) noise —
# general redirect liveness is covered by the livecheck step instead.
_INTERESTING = {200, 201, 202, 203, 204, 206, 207, 226,
                400, 401, 402, 403, 405, 406, 409, 410, 415, 418, 422, 423,
                428, 429, 431, 451, 500, 501, 502, 503}
# STRONG api markers => record even when the body is html (real API surface)
_STRONG_API = re.compile(
    r"(?:^|/)(?:api|v[0-9]{1,2}|graphql|gql|rest|rpc|internal|oauth|jsonrpc|"
    r"webhook|s2s|odata|wp-json|graphiql)(?:/|$|\.|\?)", re.I)


def is_strong_api(url: str) -> bool:
    return bool(_STRONG_API.search(url or ""))


def _rand(n=10):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _snippet(text: str, ctype: str) -> str:
    if not text:
        return ""
    if "html" in ctype.lower():
        m = _TITLE.search(text)
        if m:
            return re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    s = re.sub(r"\s+", " ", text.strip())
    return s[:200]


def _len_of(r) -> int:
    try:
        return int(r.headers.get("content-length") or len(r.content))
    except Exception:
        return len(r.content or b"")


def _loc_sig(r) -> str:
    """Normalise a redirect Location to host+path (ignore query) so that a
    catch-all ``/login?return=<path>`` redirect collapses to one baseline."""
    loc = (r.headers.get("location") or r.headers.get("Location") or "")
    if not loc:
        return ""
    p = urlsplit(loc if "://" in loc else "//" + loc.lstrip("/"))
    return ((p.hostname or "") + (p.path or "")).lower()[:160]


_STRUCTURED_CT = ("json", "xml", "javascript", "x-www-form", "grpc", "protobuf",
                  "csv", "yaml", "graphql", "octet-stream", "text/plain")


def _worth_recording(url: str, status: int, ctype: str) -> bool:
    """Keep the endpoints view high-signal: a structured/auth-gated response, or
    a strong-API URL, is always recorded. A bare HTML page that merely exists or
    errors (a 200/405/5xx marketing page on a non-API path — often a uniform
    proxy/CDN error shell) is general liveness, not an endpoint finding.

    Note: keeping 5xx ONLY for strong-API/structured is deliberate — it also
    prevents a host that returns a uniform 5xx for every verb (when its soft-404
    baseline could not be established because the direct IP was rate-limited)
    from cascading a GET-5xx into write-method probes."""
    if is_strong_api(url):
        return True
    ct = (ctype or "").lower()
    if any(t in ct for t in _STRUCTURED_CT):
        return True
    if status in (401, 402, 403, 409, 422, 423):
        return True
    return False


class EndpointProber:
    def __init__(self, client: HttpClient, *, methods: Optional[list[str]] = None,
                 write_methods: Optional[list[str]] = None):
        self.client = client
        methods = methods or DEFAULT_METHODS
        self.methods = [m.upper() for m in methods]
        # GET/OPTIONS are the cheap existence probes; the rest are "write" probes
        self.write_methods = [m for m in self.methods if m not in ("GET", "HEAD", "OPTIONS")]
        self._baselines: dict[str, list[tuple]] = {}
        self._bl_lock = threading.Lock()

    # -- per-(host, method) soft-404 baseline -----------------------------
    # A nonsense path probed with the SAME verb reveals the host's generic
    # answer for that verb (SPA 200 shell, catch-all 301→login, blanket
    # OPTIONS-200 CORS preflight, generic 404/401…). Anything that matches it
    # is NOT a real endpoint. Baselining per-method is essential: e.g. some API
    # hosts answer OPTIONS 200 for every path but 404 GET — only a verb-specific
    # baseline tells the two apart.
    def _baseline(self, host_origin: str, method: str) -> list[tuple]:
        key = (host_origin, method)
        with self._bl_lock:
            if key in self._baselines:
                return self._baselines[key]
        probes = [f"{host_origin}/{_rand()}"]
        if method in ("GET", "HEAD"):
            probes.append(f"{host_origin}/api/{_rand()}/{_rand()}")
        sigs: list[tuple] = []
        for p in probes:
            try:
                r = self.client.request(method, p, allow_redirects=False, timeout=18,
                                        max_proxy_tries=1,
                                        **({"data": b""} if method in ("POST", "PUT", "PATCH") else {}))
            except Exception:
                continue
            if r.error or r.waf.blocked:
                continue
            sigs.append((r.status, _len_of(r), _loc_sig(r)))
        with self._bl_lock:
            self._baselines[key] = sigs
        return sigs

    def _is_baseline(self, host_origin: str, method: str, status: int,
                     length: int, loc: str) -> bool:
        for (bs, bl, bloc) in self._baselines.get((host_origin, method), []):
            if status != bs:
                continue
            if status in (301, 302, 303, 307, 308):
                if loc == bloc:                 # same catch-all redirect target
                    return True
                continue
            if abs(length - bl) <= max(48, int(bl * 0.05)):
                return True
        return False

    # -- single method probe ----------------------------------------------
    def _probe_method(self, url: str, method: str) -> Optional[dict]:
        host_origin = origin_of(url)
        self._baseline(host_origin, method)     # warm (cached per host+method)
        kw = {}
        if method in ("POST", "PUT", "PATCH"):
            kw["data"] = b""        # benign empty body
        try:
            r = self.client.request(method, url, allow_redirects=False,
                                    timeout=20, max_proxy_tries=1, **kw)
        except Exception:
            return None
        if r.error:
            return None
        if r.waf.blocked:           # WAF / IP block (even after proxy) -> not a signal
            return None
        if r.status == 404 or r.status not in _INTERESTING:
            return None
        length = _len_of(r)
        loc = _loc_sig(r)
        if self._is_baseline(host_origin, method, r.status, length, loc):
            return None
        ctype = r.headers.get("content-type", "")[:160]
        if not _worth_recording(url, r.status, ctype):
            return None
        loc_raw = (r.headers.get("location") or r.headers.get("Location") or "")
        allow = (r.headers.get("allow") or r.headers.get("Allow")
                 or r.headers.get("access-control-allow-methods") or "")[:160]
        snippet = _snippet(r.text, ctype)
        if loc_raw and not snippet:
            snippet = f"-> {loc_raw[:160]}"
        return {
            "url": url, "method": method, "status_code": r.status,
            "content_type": ctype, "content_length": length,
            "title": snippet, "allow": allow, "via_proxy": r.via_proxy,
        }

    def _probe_url(self, cand: dict) -> list[dict]:
        url = cand["url"]
        host_origin = origin_of(url)
        if not host_origin:
            return []
        recs: list[dict] = []
        # 1) existence probes: GET (+ OPTIONS) — cheap, also yields Allow header
        get_rec = self._probe_method(url, "GET") if "GET" in self.methods else None
        opt_rec = self._probe_method(url, "OPTIONS") if "OPTIONS" in self.methods else None
        for rec in (get_rec, opt_rec):
            if rec:
                recs.append(rec)
        exists = bool(get_rec or opt_rec)
        is_api = is_api_path(cand.get("path", "")) or is_api_path(url)
        # methods the server explicitly advertises (OPTIONS Allow / 405 Allow)
        allow_methods: set[str] = set()
        for rec in (opt_rec, get_rec):
            if rec and rec.get("allow"):
                allow_methods |= {m.strip().upper() for m in
                                  re.split(r"[,\s]+", rec["allow"]) if m.strip()}
        # 2) write-method probes: always for API-looking paths (APIs routinely
        #    404 on GET but accept POST/PUT), else only when the path exists
        for m in self.write_methods:
            if not (exists or is_api):
                continue
            # if the server advertised its verbs and this isn't one, skip noise
            if allow_methods and m not in allow_methods and (
                    "GET" in allow_methods or "POST" in allow_methods):
                continue
            rec = self._probe_method(url, m)
            if rec:
                recs.append(rec)
        for rec in recs:
            rec.update({"path": cand.get("path", ""),
                        "source_file": cand.get("source_file", ""),
                        "host": urlsplit(url).hostname or "",
                        "host_inferred": cand.get("host_inferred", False)})
        return recs

    def run(self, candidates: list[dict], persist: Callable[[dict], None],
            log: LogFn, should_stop: Callable[[], bool],
            workers: Optional[int] = None) -> int:
        workers = workers or SETTINGS.check_workers
        # de-dup candidate urls
        uniq: dict[str, dict] = {}
        for c in candidates:
            uniq.setdefault(c["url"], c)
        cand_list = list(uniq.values())
        log("info", f"endpoints: probing {len(cand_list)} candidate urls "
                    f"(methods={','.join(self.methods)}) over "
                    f"{len({urlsplit(c['url']).hostname for c in cand_list})} hosts")
        found = 0
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self._probe_url, c): c for c in cand_list}
            for fut in as_completed(futs):
                if should_stop():
                    break
                try:
                    for rec in fut.result():
                        persist(rec)
                        found += 1
                except Exception as e:
                    log("warn", f"endpoints probe error: {e}")
                done += 1
                if done % 200 == 0:
                    log("info", f"endpoints: {done}/{len(cand_list)} probed, {found} hits")
        log("info", f"endpoints: {found} live endpoint results from {done} candidates")
        return found
