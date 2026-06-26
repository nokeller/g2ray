"""curl_cffi HTTP client with Chrome impersonation and proxy rotation.

Strategy:
  1. request proxyless with a browser-like curl_cffi fingerprint
  2. if a WAF / IP-block / rate-limit signature is detected, optionally retry
     through operator-provided proxies
  3. return the first clean response, or the most informative blocked response
"""
from __future__ import annotations

import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from . import waf
from .config import SETTINGS

try:
    from curl_cffi import requests as cffi_requests
    _HAS_CFFI = True
except Exception:  # pragma: no cover
    import requests as cffi_requests  # type: ignore
    _HAS_CFFI = False

# Preferred Chrome impersonation, newest first; we fall back if a build of
# curl_cffi does not know a specific token.
_IMPERSONATE_CHAIN = ["chrome124", "chrome123", "chrome120", "chrome116", "chrome110"]


def _resolve_impersonate(preferred: str) -> str:
    chain = [preferred] + [c for c in _IMPERSONATE_CHAIN if c != preferred]
    if not _HAS_CFFI:
        return ""
    for cand in chain:
        try:
            s = cffi_requests.Session(impersonate=cand)
            s.close()
            return cand
        except Exception:
            continue
    return "chrome120"


IMPERSONATE = _resolve_impersonate(SETTINGS.impersonate)


def normalize_proxy(p: str) -> Optional[str]:
    """Accept 'host:port:user:pass', 'host:port', or 'scheme://user:pass@host:port'."""
    p = p.strip()
    if not p:
        return None
    if "://" in p:
        return p
    parts = p.split(":")
    if len(parts) == 4:
        host, port, user, pw = parts
        return f"http://{user}:{pw}@{host}:{port}"
    if len(parts) == 2:
        host, port = parts
        return f"http://{host}:{port}"
    return None


class ProxyPool:
    def __init__(self, proxies: list[str]):
        self._proxies = [np for p in proxies if (np := normalize_proxy(p))]
        self._cycle = itertools.cycle(self._proxies) if self._proxies else None
        self._lock = threading.Lock()

    def __bool__(self):
        return bool(self._proxies)

    @property
    def all(self) -> list[str]:
        return list(self._proxies)

    def next(self) -> Optional[str]:
        if not self._cycle:
            return None
        with self._lock:
            return next(self._cycle)


@dataclass
class Resp:
    status: int = 0
    url: str = ""
    final_url: str = ""
    headers: dict = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    via_proxy: bool = False
    proxy: str = ""
    waf: waf.WafVerdict = field(default_factory=waf.WafVerdict)
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.error == "" and 0 < self.status < 400

    @property
    def blocked(self) -> bool:
        return self.waf.blocked


class HttpClient:
    def __init__(self, proxies: list[str] | None = None, impersonate: str | None = None):
        self.pool = ProxyPool(proxies if proxies is not None else SETTINGS.proxies)
        self.impersonate = impersonate or IMPERSONATE
        self._local = threading.local()
        # host -> unix ts until which the *direct* IP is considered blocked.
        # While blocked we go straight to proxies; after it expires we re-probe
        # direct so the client auto-recovers when a temporary ban lifts.
        self._blocked_until: dict[str, float] = {}
        self._block_lock = threading.Lock()
        # circuit breaker for hosts that fail at the TRANSPORT level (DNS dead /
        # firewalled / hang until timeout). Without this, one dead host (e.g. a
        # stale inferred API host) stalls a whole probe sweep on full timeouts.
        # After `_dead_threshold` consecutive transport failures a host is
        # skipped for `_dead_cooldown` seconds (auto re-probes after that). A
        # real HTTP status (even 404/403/timeout-with-status) counts as alive.
        self._fail: dict[str, int] = {}
        self._dead_until: dict[str, float] = {}
        self._dead_threshold = 3
        self._dead_cooldown = 300

    # -- host block bookkeeping -------------------------------------------
    @staticmethod
    def _host(url: str) -> str:
        try:
            from urllib.parse import urlsplit
            return (urlsplit(url).hostname or "").lower()
        except Exception:
            return ""

    def _direct_blocked(self, host: str) -> bool:
        if not host:
            return False
        with self._block_lock:
            exp = self._blocked_until.get(host)
            if not exp:
                return False
            if time.time() >= exp:
                # cooldown elapsed -> allow a direct re-probe
                self._blocked_until.pop(host, None)
                return False
            return True

    def _mark_blocked(self, host: str):
        if not host:
            return
        with self._block_lock:
            self._blocked_until[host] = time.time() + max(1, SETTINGS.block_cooldown_sec)

    def _clear_block(self, host: str):
        if not host:
            return
        with self._block_lock:
            self._blocked_until.pop(host, None)

    def host_blocked(self, host: str) -> bool:
        return self._direct_blocked((host or "").lower())

    # -- transport-failure circuit breaker --------------------------------
    def _host_dead(self, host: str) -> bool:
        if not host:
            return False
        with self._block_lock:
            exp = self._dead_until.get(host)
            if not exp:
                return False
            if time.time() >= exp:
                self._dead_until.pop(host, None)
                self._fail.pop(host, None)
                return False
            return True

    def _note_fail(self, host: str):
        if not host:
            return
        with self._block_lock:
            n = self._fail.get(host, 0) + 1
            self._fail[host] = n
            if n >= self._dead_threshold:
                self._dead_until[host] = time.time() + self._dead_cooldown

    def _note_ok(self, host: str):
        if not host:
            return
        with self._block_lock:
            n = self._fail.get(host, 0)
            # decay (not full reset) so a FLAKY host — one that times out on many
            # probes but occasionally answers — still trends toward benched
            # instead of resetting its failure count on every lucky success.
            if n <= 1:
                self._fail.pop(host, None)
            else:
                self._fail[host] = n - 1
            self._dead_until.pop(host, None)

    # -- session management (thread-local) ---------------------------------
    def _session(self, plain: bool = False):
        """Thread-local session. ``plain`` returns a NON-impersonated session
        used only as a transport-failure fallback (see ``_attempt``)."""
        attr = "session_plain" if plain else "session"
        s = getattr(self._local, attr, None)
        if s is None:
            if _HAS_CFFI and self.impersonate and not plain:
                s = cffi_requests.Session(impersonate=self.impersonate)
            else:
                s = cffi_requests.Session()
            setattr(self._local, attr, s)
        return s

    # -- single attempt ----------------------------------------------------
    def _attempt(self, method: str, url: str, proxy: Optional[str], *,
                 allow_redirects=True, timeout=None, plain=False, **kw) -> Resp:
        s = self._session(plain=plain)
        proxies = {"http": proxy, "https": proxy} if proxy else None
        try:
            r = s.request(
                method, url,
                proxies=proxies,
                timeout=timeout or SETTINGS.request_timeout,
                allow_redirects=allow_redirects,
                **kw,
            )
        except Exception as e:  # network/proxy/timeout error
            # Transport-level failure (curl 28 timeout / 0 bytes / reset). Some
            # CDNs (e.g. CloudFront fronting otx.alienvault.com) accept the
            # chrome impersonation TLS/HTTP2 fingerprint then never respond,
            # while a plain (non-impersonated) client succeeds. Retry ONCE
            # without impersonation before declaring a network error. This only
            # triggers on a connection failure — a real WAF block is an HTTP
            # response, not an exception, so the impersonation fingerprint is
            # never weakened against actual blocks.
            if (not plain) and _HAS_CFFI and self.impersonate:
                # bound the fallback timeout: an impersonation-specific hang
                # (e.g. OTX) recovers on plain in well under a second, while a
                # genuinely dead host should not double the full wait.
                base_to = timeout or SETTINGS.request_timeout
                return self._attempt(method, url, proxy,
                                     allow_redirects=allow_redirects,
                                     timeout=min(base_to, 10), plain=True, **kw)
            return Resp(url=url, error=f"{type(e).__name__}: {e}",
                        via_proxy=bool(proxy), proxy=proxy or "",
                        waf=waf.WafVerdict(True, "network", str(e)[:120]))
        headers = {k: v for k, v in r.headers.items()}
        # read text safely
        try:
            text = r.text
        except Exception:
            text = ""
        try:
            content = r.content
        except Exception:
            content = b""
        verdict = waf.detect(r.status_code, headers, text)
        return Resp(status=r.status_code, url=url, final_url=str(r.url),
                    headers=headers, text=text, content=content,
                    via_proxy=bool(proxy), proxy=proxy or "", waf=verdict)

    # -- public request with full fallback ---------------------------------
    def request(self, method: str, url: str, *, allow_redirects=True,
                timeout=None, force_proxy=False, max_proxy_tries=None, **kw) -> Resp:
        delay = SETTINGS.request_delay_ms / 1000.0
        if delay:
            time.sleep(delay)

        host = self._host(url)
        # circuit breaker: skip a host that keeps failing at the transport level
        # (dead/firewalled/hangs to timeout) so it can't stall the whole sweep.
        if self._host_dead(host):
            return Resp(url=url, error="circuit-open: repeated transport failures",
                        waf=waf.WafVerdict(True, "dead-host", "circuit-open (transport)"))
        attempts: list[Resp] = []
        # if the direct IP is in a block cooldown for this host, skip straight
        # to proxies (still re-probes direct automatically once it expires).
        # force_proxy only skips direct when a proxy pool actually exists, so a
        # proxyless deploy never ends up making zero attempts.
        skip_direct = bool(self.pool) and (force_proxy or self._direct_blocked(host))

        # 1) proxyless first (unless forced or host is in direct-block cooldown)
        if not skip_direct:
            r = self._attempt(method, url, None, allow_redirects=allow_redirects,
                              timeout=timeout, **kw)
            if not r.blocked and not r.error:
                self._clear_block(host)
                self._note_ok(host)
                return r
            attempts.append(r)
            # remember that the direct IP is blocked for this host
            if r.blocked and self.pool:
                self._mark_blocked(host)

        # 2) rotate through proxy pool (bounded by max_proxy_tries so a stalled
        #    host can't burn pool_size * timeout on a single call)
        if self.pool:
            tried = 0
            if max_proxy_tries is not None:
                limit = max(1, max_proxy_tries)
            else:
                limit = max(len(self.pool.all), SETTINGS.max_retries)
            while tried < limit:
                proxy = self.pool.next()
                tried += 1
                backoff = min(0.4 * tried, 3.0)
                r = self._attempt(method, url, proxy, allow_redirects=allow_redirects,
                                  timeout=timeout, **kw)
                if not r.blocked and not r.error:
                    self._note_ok(host)
                    return r
                attempts.append(r)
                time.sleep(backoff)

        # nothing clean: return the most informative attempt
        for r in attempts:
            if r.status and not r.error:
                self._note_ok(host)        # a real HTTP status => host is alive
                return r
        # only transport failures (no HTTP status at all) => host unhealthy
        self._note_fail(host)
        return attempts[-1] if attempts else Resp(url=url, error="no attempt made")

    def get(self, url, **kw) -> Resp:
        return self.request("GET", url, **kw)

    def head(self, url, **kw) -> Resp:
        return self.request("HEAD", url, **kw)


_default_client: Optional[HttpClient] = None
_client_lock = threading.Lock()


def get_client(refresh: bool = False) -> HttpClient:
    global _default_client
    with _client_lock:
        if _default_client is None or refresh:
            _default_client = HttpClient(SETTINGS.proxies)
        return _default_client
