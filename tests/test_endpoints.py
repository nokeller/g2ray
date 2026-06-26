"""Deterministic tests for the endpoint discovery + probing engine.

Uses a FakeClient that returns canned responses per (method, url) so the
prober's accuracy logic (per-method soft-404 baseline, WAF skip, route-template
expansion, host inference) is verified without the network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import pytest

from g2recon.modules import endpoints as ep
from g2recon.modules import jsanalyze as ja


# --------------------------------------------------------------------------
# fake HTTP client
# --------------------------------------------------------------------------
@dataclass
class _Waf:
    blocked: bool = False
    vendor: str = ""


@dataclass
class _Resp:
    status: int = 0
    headers: dict = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    error: str = ""
    via_proxy: bool = False
    waf: _Waf = field(default_factory=_Waf)


class FakeClient:
    """rules: list of (method_regex, url_regex, response_factory)."""
    def __init__(self, rules):
        self.rules = rules

    def request(self, method, url, **kw):
        for (mrx, urx, fac) in self.rules:
            if re.fullmatch(mrx, method, re.I) and re.search(urx, url):
                return fac(method, url)
        return _Resp(status=404, content=b"nf", text="nf")

    def get(self, url, **kw):
        return self.request("GET", url, **kw)


def _r(status, body="", ctype="text/html", headers=None):
    h = {"content-type": ctype}
    if headers:
        h.update(headers)
    b = body.encode() if isinstance(body, str) else body
    return _Resp(status=status, headers=h, text=body if isinstance(body, str) else "",
                 content=b)


# --------------------------------------------------------------------------
# template / path helpers
# --------------------------------------------------------------------------
def test_template_helpers():
    assert ep.has_template("/api/apps/:token")
    assert ep.has_template("/x/{id}/y") and ep.has_template("/x/${v}") and ep.has_template("/x/*")
    assert ep.static_prefix("/api/apps/:token/settings") == "/api/apps/"
    assert ep.substitute_template("/api/apps/:token/{id}") == "/api/apps/1/1"
    assert not ep.has_template("/api/apps")


def test_static_asset_and_collapse():
    assert ep.is_static_asset("/assets/main.css") and ep.is_static_asset("/x.png?q=1")
    assert not ep.is_static_asset("/api/users.json")
    assert ep.collapse_ids("/api/users/12345/posts") == "/api/users/{id}/posts"
    assert ep.collapse_ids("/api/users/4f8a1b2c9d/x").endswith("/{id}/x")


def test_api_path_detection():
    assert ep.is_api_path("/api/x") and ep.is_api_path("/v2/users") and ep.is_api_path("/graphql")
    assert ep.is_api_path("/partner_ad_accounts_service/api/settings")
    assert not ep.is_api_path("/company/about")


# --------------------------------------------------------------------------
# host inference
# --------------------------------------------------------------------------
def test_rank_api_hosts_prefers_canonical():
    hosts = ["api.adjust.com", "www.adjust.com", "cdn.adjust.com", "dash.adjust.com",
             "tracker-api.kube.adjust.com", "help.adjust.com", "api-staging.adjust.com",
             "docs.adjust.com"]
    ranked = ep.rank_api_hosts(hosts, "adjust.com", api_origin_hosts={"api.adjust.com"})
    assert ranked[0] == "api.adjust.com"
    assert "www.adjust.com" not in ranked and "cdn.adjust.com" not in ranked
    assert "help.adjust.com" not in ranked and "docs.adjust.com" not in ranked


# --------------------------------------------------------------------------
# candidate building
# --------------------------------------------------------------------------
def test_build_candidates_relative_uses_parent_and_inferred():
    ranked = ["api.adjust.com", "dash.adjust.com"]
    c = ep.build_candidates("/api/apps/:token", "path",
                            "https://dash.adjust.com/scripts/v.js", "adjust.com",
                            ranked, max_inferred=2)
    urls = {x["url"] for x in c}
    assert "https://dash.adjust.com/api/apps/" in urls          # parent origin, static prefix
    assert any(u.startswith("https://api.adjust.com/api/apps") for u in urls)  # inferred
    # parent-origin candidate is NOT host_inferred; api.adjust.com one IS
    assert any((not x["host_inferred"]) and "dash.adjust.com" in x["url"] for x in c)
    assert any(x["host_inferred"] and "api.adjust.com" in x["url"] for x in c)


def test_build_candidates_absolute_and_scope():
    ranked = ["api.adjust.com"]
    c = ep.build_candidates("https://api.adjust.com/v1/track?x=1", "url", "", "adjust.com", ranked)
    assert c and all("api.adjust.com" in x["url"] for x in c)
    # out-of-scope absolute url is dropped entirely
    assert ep.build_candidates("https://evil.example.com/api/x", "url", "", "adjust.com", ranked) == []


def test_select_and_build_dedup_and_cap():
    items = [("/api/apps", "path", "https://dash.adjust.com/a.js"),
             ("/api/apps", "path", "https://dash.adjust.com/b.js"),       # dup signature
             ("/api/apps/123", "path", "https://dash.adjust.com/c.js"),   # id-collapsed dup
             ("/assets/x.css", "file", "https://www.adjust.com/a.js"),    # static -> skip
             ("/company/team", "path", "https://www.adjust.com/a.js")]    # non-api kept
    cands, n = ep.select_and_build(items, "adjust.com", ["api.adjust.com"], max_paths=0)
    assert not any("x.css" in x["url"] for x in cands)
    # /api/apps and /api/apps/{id} collapse to a single signature on dash host
    sigs = {ep.collapse_ids(x["path"].split("?")[0]) + "|" + (x["url"].split("/")[2]) for x in cands}
    assert n >= 2


# --------------------------------------------------------------------------
# api-call extraction
# --------------------------------------------------------------------------
def test_extract_api_calls_methods():
    js = ('axios.post("/api/login", d);'
          'fetch(`/api/v2/users/${id}`,{method:"PUT"});'
          'this.$http.get("/internal/health");'
          '$.ajax({url:"/api/legacy",type:"DELETE"});'
          'const u="/api/graphql";')
    calls = set(ja.extract_api_calls(js))
    assert ("POST", "/api/login") in calls
    assert ("PUT", "/api/v2/users/${id}") in calls
    assert ("GET", "/internal/health") in calls
    assert ("DELETE", "/api/legacy") in calls
    assert ("", "/api/graphql") in calls


# --------------------------------------------------------------------------
# prober accuracy (the heart of "no false positives")
# --------------------------------------------------------------------------
def _run(prober, cands):
    hits = []
    prober.run(cands, lambda r: hits.append(r), lambda l, m: None, lambda: False)
    return hits


def test_prober_soft404_spa_suppressed_real_recorded():
    SHELL = "<html><head><title>App</title></head><body>" + ("x" * 5000) + "</body></html>"
    rules = [
        # every GET returns the SPA shell EXCEPT the real one which is shorter JSON
        (r"GET", r"/api/real$", lambda m, u: _r(200, '{"ok":true}', "application/json")),
        (r"GET", r".*", lambda m, u: _r(200, SHELL)),
        (r"OPTIONS|POST|PUT|PATCH", r".*", lambda m, u: _r(404, "nf")),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET"])
    hits = _run(pr, [{"url": "https://h.adjust.com/api/real", "path": "/api/real",
                      "source_file": "", "host_inferred": False},
                     {"url": "https://h.adjust.com/api/fake", "path": "/api/fake",
                      "source_file": "", "host_inferred": False}])
    got = {(h["method"], h["url"].split("/")[-1]) for h in hits}
    assert ("GET", "real") in got            # distinct JSON body -> recorded
    assert ("GET", "fake") not in got        # SPA shell soft-404 -> suppressed


def test_prober_method_specific_endpoint():
    # GET 404 everywhere, but POST to the real endpoint returns 401 (exists!)
    rules = [
        (r"POST", r"/optout$", lambda m, u: _r(401, '{"error":"auth"}', "application/json")),
        (r"GET|OPTIONS|POST|PUT|PATCH", r".*", lambda m, u: _r(404, "nf")),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET", "OPTIONS", "POST", "PUT"])
    hits = _run(pr, [{"url": "https://api.adjust.com/optout", "path": "/api/optout",
                      "source_file": "x.js", "host_inferred": False}])
    rec = [h for h in hits if h["method"] == "POST"]
    assert rec and rec[0]["status_code"] == 401
    assert all(h["status_code"] != 404 for h in hits)


def test_prober_options_cors_noise_suppressed():
    # OPTIONS returns 200 for ANY path (blanket CORS preflight) -> must be noise
    rules = [
        (r"OPTIONS", r".*", lambda m, u: _r(200, "", "text/plain")),
        (r"GET|POST|PUT|PATCH", r".*", lambda m, u: _r(404, "nf")),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET", "OPTIONS", "POST"])
    hits = _run(pr, [{"url": "https://api.adjust.com/api/whatever", "path": "/api/whatever",
                      "source_file": "", "host_inferred": True}])
    assert hits == []        # blanket OPTIONS-200 baselined out


def test_prober_waf_block_not_recorded():
    rules = [
        (r".*", r".*", lambda m, u: _Resp(status=403, headers={"server": "cloudflare"},
                                          text="attention required", content=b"x" * 50,
                                          waf=_Waf(blocked=True, vendor="cloudflare"))),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET", "POST"])
    hits = _run(pr, [{"url": "https://api.adjust.com/api/x", "path": "/api/x",
                      "source_file": "", "host_inferred": False}])
    assert hits == []        # WAF block is not a real endpoint signal


def test_prober_real_403_recorded():
    # a *plain* 403 (no WAF signature) is a meaningful signal and IS recorded
    rules = [
        (r"GET", r"/admin$", lambda m, u: _r(403, "Forbidden")),
        (r".*", r".*", lambda m, u: _r(404, "nf")),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET"])
    hits = _run(pr, [{"url": "https://dash.adjust.com/admin", "path": "/admin",
                      "source_file": "", "host_inferred": False}])
    assert len(hits) == 1 and hits[0]["status_code"] == 403


def test_prober_catchall_redirect_suppressed():
    # 3xx are dropped from the endpoints view entirely (livecheck covers them)
    rules = [
        (r"GET", r".*", lambda m, u: _r(302, "", headers={"location": "https://dash.adjust.com/login?return=" + u})),
        (r"OPTIONS|POST|PUT|PATCH", r".*", lambda m, u: _r(404)),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET"])
    hits = _run(pr, [{"url": "https://dash.adjust.com/api/apps", "path": "/api/apps",
                      "source_file": "", "host_inferred": False}])
    assert hits == []


def test_3xx_dropped_even_to_new_path():
    rules = [
        (r"GET", r"/old$", lambda m, u: _r(301, "", headers={"location": "/totally/new/place"})),
        (r".*", r".*", lambda m, u: _r(404)),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET"])
    hits = _run(pr, [{"url": "https://dash.adjust.com/old", "path": "/old",
                      "source_file": "", "host_inferred": False}])
    assert hits == []


def test_is_strong_api():
    assert ep.is_strong_api("https://x.adjust.com/api/apps")
    assert ep.is_strong_api("https://x.adjust.com/v1/users")
    assert ep.is_strong_api("https://x.adjust.com/graphql")
    assert not ep.is_strong_api("https://x.adjust.com/partners/list")
    assert not ep.is_strong_api("https://x.adjust.com/events")


def test_worth_recording_filters_marketing_pages():
    rules = [
        (r"GET", r"/company$", lambda m, u: _r(200, "<html>about</html>", "text/html")),
        (r"GET", r"/data$", lambda m, u: _r(200, '{"a":1}', "application/json")),
        (r"GET", r"/api/x$", lambda m, u: _r(200, "<html>doc</html>", "text/html")),
        (r".*", r".*", lambda m, u: _r(404)),
    ]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET"])
    hits = _run(pr, [
        {"url": "https://www.adjust.com/company", "path": "/company", "source_file": "", "host_inferred": False},
        {"url": "https://api.adjust.com/data", "path": "/data", "source_file": "", "host_inferred": False},
        {"url": "https://api.adjust.com/api/x", "path": "/api/x", "source_file": "", "host_inferred": False},
    ])
    urls = {h["url"] for h in hits}
    assert "https://www.adjust.com/company" not in urls       # marketing html 200 -> skip
    assert "https://api.adjust.com/data" in urls              # json -> keep
    assert "https://api.adjust.com/api/x" in urls             # strong-api html -> keep


def test_generic_secret_placeholder_filter():
    js = ('e.AccessToken="access_token";e.PASSWORD="password";'
          'var c={accessToken:"QprCQ4FOIlRk4iTwRy7pkAtt"};'
          'var k={api_secret:"ACCESS_TOKEN"};'
          'var t={client_secret:"sk_live_realLOOKINGsecret12345"};')
    matches = [s["match"] for s in ja.find_secrets(js)]
    assert any("QprCQ4FOIlRk4iTwRy7pkAtt" in m for m in matches)      # real token kept
    assert any("sk_live_realLOOKINGsecret12345" in m for m in matches)  # real secret kept
    assert not any('"access_token"' in m for m in matches)            # placeholder dropped
    assert not any('"password"' in m for m in matches)                # placeholder dropped
    assert not any("ACCESS_TOKEN" in m for m in matches)              # SCREAMING_SNAKE dropped


def test_uniform_5xx_marketing_not_recorded_and_no_write_cascade():
    # host returns a uniform 500 html shell for EVERY verb (proxy/CDN error) on a
    # non-API path -> nothing recorded, and GET-500 must NOT trigger write probes
    probed = []
    def fac(m, u):
        probed.append((m, u))
        return _r(500, "<html>err " + "x" * 4000 + "</html>", "text/html")
    rules = [(r".*", r".*", fac)]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET", "OPTIONS", "POST", "PUT", "PATCH"])
    hits = _run(pr, [{"url": "https://www.adjust.com/blog/post", "path": "/blog/post",
                      "source_file": "", "host_inferred": False}])
    assert hits == []                                  # uniform 5xx html -> noise
    # GET 500 (worth_recording False) must not make exists True -> no POST/PUT/PATCH
    methods_probed = {m for (m, u) in probed if "/blog/post" in u}
    assert "POST" not in methods_probed and "PUT" not in methods_probed


def test_5xx_on_api_is_recorded():
    rules = [(r"POST", r"/api/x$", lambda m, u: _r(500, '{"error":"boom"}', "application/json")),
             (r".*", r".*", lambda m, u: _r(404))]
    pr = ep.EndpointProber(FakeClient(rules), methods=["GET", "POST"])
    hits = _run(pr, [{"url": "https://api.adjust.com/api/x", "path": "/api/x",
                      "source_file": "", "host_inferred": False}])
    assert any(h["status_code"] == 500 and h["method"] == "POST" for h in hits)


def test_waymore_cmd_prefers_console_script():
    # must never fall back to the broken `python -m waymore` when a console
    # script exists (this waymore package has no __main__)
    from g2recon.modules import waymore_runner as w
    cmd = w._waymore_cmd()
    assert cmd[0].endswith("/waymore") or cmd[0] == "waymore", cmd
    assert "-m" not in cmd, cmd
