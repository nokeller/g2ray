"""curl_cffi HTTP client with Chrome impersonation, proxy rotation and
WAF/IP-block aware fallback.

Strategy (matches the recon spec):
  1. request proxyless with a real Chrome (impersonate) fingerprint
  2. if a WAF / IP-block / rate-limit signature is detected -> optionally rotate
     the local egress IP via a user-supplied WARP/VPN command, then retry
  3. still blocked -> rotate through the configured proxy pool
  4. return the first clean response, or the last response if all are blocked
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
        self._warp_lock = threading.Lock()
        self._last_warp = 0.0

    # -- session management (thread-local) ---------------------------------
    def _session(self):
        s = getattr(self._local, "session", None)
        if s is None:
            if _HAS_CFFI and self.impersonate:
                s = cffi_requests.Session(impersonate=self.impersonate)
            else:
                s = cffi_requests.Session()
            self._local.session = s
        return s

    def _maybe_warp(self):
        """Run a user-configured IP-rotation command (e.g. WARP). Best effort.
        Never touches anything but the configured command, so SSH stays intact."""
        cmd = SETTINGS.warp_command.strip()
        if not cmd:
            return False
        with self._warp_lock:
            if time.time() - self._last_warp < 5:
                return False
            self._last_warp = time.time()
        try:
            import subprocess
            subprocess.run(cmd, shell=True, timeout=30,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)
            return True
        except Exception:
            return False

    # -- single attempt ----------------------------------------------------
    def _attempt(self, method: str, url: str, proxy: Optional[str], *,
                 allow_redirects=True, timeout=None, **kw) -> Resp:
        s = self._session()
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
                timeout=None, force_proxy=False, **kw) -> Resp:
        delay = SETTINGS.request_delay_ms / 1000.0
        if delay:
            time.sleep(delay)

        attempts: list[Resp] = []

        # 1) proxyless first (unless caller forces proxy)
        if not force_proxy:
            r = self._attempt(method, url, None, allow_redirects=allow_redirects,
                              timeout=timeout, **kw)
            if not r.blocked and not r.error:
                return r
            attempts.append(r)

            # 2) try local IP rotation (WARP / VPN) once, proxyless again
            if self._maybe_warp():
                r = self._attempt(method, url, None, allow_redirects=allow_redirects,
                                  timeout=timeout, **kw)
                if not r.blocked and not r.error:
                    return r
                attempts.append(r)

        # 3) rotate through proxy pool
        if self.pool:
            tried = 0
            limit = max(len(self.pool.all), SETTINGS.max_retries)
            while tried < limit:
                proxy = self.pool.next()
                tried += 1
                backoff = min(0.4 * tried, 3.0)
                r = self._attempt(method, url, proxy, allow_redirects=allow_redirects,
                                  timeout=timeout, **kw)
                if not r.blocked and not r.error:
                    return r
                attempts.append(r)
                time.sleep(backoff)

        # nothing clean: return the most informative attempt
        for r in attempts:
            if r.status and not r.error:
                return r
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
