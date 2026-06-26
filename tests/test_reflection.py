"""Reflection scanner: the x8-style 'reflects-everything' guard must collapse a
page that echoes arbitrary params into ONE finding, while a page that reflects a
specific param is still recorded per-param.
"""
from __future__ import annotations

from urllib.parse import urlsplit, parse_qsl

from g2recon.modules.reflection import ReflectionScanner


class _Resp:
    def __init__(self, text):
        self.text = text
        self.status = 200
        self.error = ""
        self.headers = {}


class ReflectAllClient:
    """Echoes the whole URL (so every injected canary is reflected)."""
    def get(self, url, **kw):
        return _Resp(text="<html>you requested " + url + "</html>")


class ReflectOnlyQClient:
    """Reflects only the value of param 'q'."""
    def get(self, url, **kw):
        q = dict(parse_qsl(urlsplit(url).query))
        return _Resp(text="<div>search: " + q.get("q", "") + "</div>")


def test_reflects_everything_collapses_to_one_finding():
    sc = ReflectionScanner(ReflectAllClient())
    res = sc.scan_url("https://h.8x8.com/page", ["q", "foo", "bar", "redirect", "x"])
    assert len(res) == 1
    assert "any" in res[0]["param"].lower()


def test_specific_param_reflection_recorded():
    sc = ReflectionScanner(ReflectOnlyQClient())
    res = sc.scan_url("https://h.8x8.com/search", ["q", "foo", "bar"])
    params = {r["param"] for r in res}
    assert params == {"q"}            # only the genuinely reflecting param
