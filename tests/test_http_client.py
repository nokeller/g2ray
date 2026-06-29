"""Tests for the HTTP client robustness fixes:

* proxyless mode (empty pool) never skips the direct attempt, even with
  force_proxy — so a `disable_proxy` run always makes a real request.
* transport-failure fallback: when the chrome-impersonation session raises a
  connection error (curl 28 timeout / 0 bytes — e.g. CloudFront fronting OTX
  hangs on the chrome HTTP/2 fingerprint), the client retries ONCE without
  impersonation and returns the clean response.
"""
from __future__ import annotations

from g2recon.http_client import HttpClient, ProxyPool, normalize_proxy


def test_empty_pool_is_falsey_and_next_none():
    p = ProxyPool([])
    assert not p
    assert p.all == []
    assert p.next() is None


def test_normalize_proxy_forms():
    assert normalize_proxy("h:1:u:p") == "http://u:p@h:1"
    assert normalize_proxy("h:1") == "http://h:1"
    assert normalize_proxy("socks5://u:p@h:1") == "socks5://u:p@h:1"
    assert normalize_proxy("") is None


class _FakeResp:
    def __init__(self, status=200, body=b'{"ok":1}', ctype="application/json", url="https://x/y"):
        self.status_code = status
        self.headers = {"content-type": ctype}
        self.text = body.decode() if isinstance(body, bytes) else body
        self.content = body if isinstance(body, bytes) else body.encode()
        self.url = url


def test_plain_fallback_on_transport_failure(monkeypatch):
    """Impersonated session raises (connection hang); plain session succeeds."""
    c = HttpClient(proxies=[], impersonate="chrome124")
    calls = {"imp": 0, "plain": 0}

    class ImpSession:
        def request(self, *a, **k):
            calls["imp"] += 1
            raise RuntimeError("Failed to perform, curl: (28) Operation timed out "
                               "after 40000 milliseconds with 0 bytes received")

    class PlainSession:
        def request(self, *a, **k):
            calls["plain"] += 1
            return _FakeResp()

    monkeypatch.setattr(c, "_session",
                        lambda plain=False: PlainSession() if plain else ImpSession())
    r = c.get("https://otx.example.com/passive_dns")
    assert r.status == 200 and r.ok and not r.error
    assert calls["imp"] == 1 and calls["plain"] == 1     # exactly one retry


def test_plain_fallback_not_infinite(monkeypatch):
    """If BOTH impersonated and plain fail, we get a single error Resp (no loop)."""
    c = HttpClient(proxies=[], impersonate="chrome124")
    n = {"v": 0}

    class DeadSession:
        def request(self, *a, **k):
            n["v"] += 1
            raise RuntimeError("curl: (28) timed out with 0 bytes received")

    monkeypatch.setattr(c, "_session", lambda plain=False: DeadSession())
    r = c.get("https://dead.example.com/x")
    assert r.error and not r.ok
    assert n["v"] == 2          # imp attempt + one plain retry, then stop


def test_proxyless_request_still_attempts_direct(monkeypatch):
    """With an empty pool, force_proxy must NOT skip the direct attempt
    (otherwise a proxyless deploy would make zero requests)."""
    c = HttpClient(proxies=[], impersonate="chrome124")
    seen = {"n": 0}

    class OkSession:
        def request(self, *a, **k):
            seen["n"] += 1
            return _FakeResp()

    monkeypatch.setattr(c, "_session", lambda plain=False: OkSession())
    r = c.get("https://x.example.com/y", force_proxy=True)
    assert r.status == 200 and seen["n"] == 1


def test_circuit_breaker_benches_dead_host(monkeypatch):
    """After `_dead_threshold` transport failures a host is skipped fast
    (circuit-open) without making further network calls until cooldown."""
    c = HttpClient(proxies=[], impersonate="chrome124")
    c._dead_threshold = 2

    class DeadSession:
        def request(self, *a, **k):
            raise RuntimeError("curl: (28) Operation timed out with 0 bytes received")

    monkeypatch.setattr(c, "_session", lambda plain=False: DeadSession())
    assert c.get("https://dead.example.com/a").error
    assert c.get("https://dead.example.com/b").error      # threshold reached -> dead

    calls = {"n": 0}

    class TrapSession:
        def request(self, *a, **k):
            calls["n"] += 1
            raise RuntimeError("must not be called once circuit is open")

    monkeypatch.setattr(c, "_session", lambda plain=False: TrapSession())
    r = c.get("https://dead.example.com/c")
    assert "circuit-open" in r.error and calls["n"] == 0   # fast-failed, no network


def test_circuit_breaker_real_status_keeps_host_alive(monkeypatch):
    """A real HTTP status (even 404) must NOT bench the host."""
    c = HttpClient(proxies=[], impersonate="chrome124")
    c._dead_threshold = 2

    class NotFound:
        def __init__(self):
            self.status_code = 404; self.headers = {"content-type": "text/html"}
            self.text = "nope"; self.content = b"nope"; self.url = "https://h/x"

    class OkSession:
        def request(self, *a, **k):
            return NotFound()

    monkeypatch.setattr(c, "_session", lambda plain=False: OkSession())
    for _ in range(5):
        assert c.get("https://alive.example.com/x").status == 404
    assert not c._host_dead("alive.example.com")
