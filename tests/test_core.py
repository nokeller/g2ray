from urllib.parse import parse_qs, urlsplit

from g2recon import util
from g2recon.db import Target, Url, FileRecord, get_session
from g2recon.http_client import normalize_proxy
from g2recon.modules import downloader, fuzz, jsanalyze, livecheck, params, subdomains, wayback
from g2recon.modules.openredirect import CANARY, OpenRedirectScanner
from g2recon.modules.reflection import ReflectionScanner, dedup_targets
from g2recon import store


class FakeResp:
    def __init__(self, status=200, text="", content=b"", headers=None, error="", via_proxy=False):
        self.status = status
        self.text = text
        self.content = content or text.encode()
        self.headers = headers or {}
        self.error = error
        self.via_proxy = via_proxy

    @property
    def ok(self):
        return self.error == "" and 0 < self.status < 400


def test_scope_filtering_and_subindex_import():
    raw = """
    https://api.adjust.com
    *.wild.adjust.com
    nope.example.net
    cdn.adjust.com/path
    """

    hosts = subdomains.from_subindex_import(raw, "adjust.com")

    assert "api.adjust.com" in hosts
    assert "cdn.adjust.com" in hosts
    assert "nope.example.net" not in hosts


def test_wayback_json_parser_with_resume_key():
    text = """[
      ["original","timestamp","statuscode","mimetype","digest"],
      ["https://api.adjust.com/app.js","20240101010101","200","application/javascript","abc"],
      [],
      ["resume-token"]
    ]"""

    rows, resume = wayback._parse_cdx_json(text)

    assert rows == [{
        "original": "https://api.adjust.com/app.js",
        "timestamp": "20240101010101",
        "statuscode": "200",
        "mimetype": "application/javascript",
        "digest": "abc",
    }]
    assert resume == "resume-token"


def test_js_analysis_finds_links_secrets_subdomains_and_recursive_files():
    source = "https://cdn.adjust.com/static/app.js"
    body = """
      const api = "/api/v1/users?token=abc";
      import("/static/chunk.js");
      fetch("https://api.adjust.com/config.json");
      const k = "AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      // hidden.dev.adjust.com
    """

    out = jsanalyze.analyze(body, source, "adjust.com")

    links = {x[0] for x in out["links"]}
    assert "/api/v1/users?token=abc" in links
    assert "https://api.adjust.com/config.json" in links
    assert "https://api.adjust.com/config.json" in out["new_files"]
    assert "https://cdn.adjust.com/static/chunk.js" in out["new_files"]
    assert "hidden.dev.adjust.com" in out["subdomains"]
    assert any(s["rule"] == "google_api_key" for s in out["secrets"])


def test_parameter_collection_and_signature_dedup():
    urls = [
        "https://www.adjust.com/search?q=one&lang=en",
        "https://www.adjust.com/search?lang=de&q=two",
        "https://www.adjust.com/search?id=1",
    ]

    assert params.collect_from_urls(urls) == {"q", "lang", "id"}
    assert util.param_signature(urls[0]) == util.param_signature(urls[1])
    assert util.param_signature(urls[0]) != util.param_signature(urls[2])
    assert len(dedup_targets(urls)) == 2


def test_reflection_scanner_batches_and_identifies_reflected_params():
    class Client:
        def get(self, url, **_):
            query = parse_qs(urlsplit(url).query)
            # only param 'q' is reflected; a missing 'q' (e.g. the reflects-all
            # control probe) yields an empty body so the control does NOT reflect
            body = (query["q"][0] + " only") if "q" in query else "no reflection"
            return FakeResp(200, text=body)

    scanner = ReflectionScanner(Client(), start_batch=8)
    found = scanner.scan_url("https://www.adjust.com/search", ["q", "lang"])

    # only 'q' reflects; the mock echoes the value DECODED (raw), so the breakout
    # chars survive => this is flagged UNENCODED (a real XSS candidate)
    assert len(found) == 1
    r = found[0]
    assert r["url"] == "https://www.adjust.com/search?q=FUZZ"
    assert r["param"] == "q"
    assert r["contexts"].startswith("text")
    assert "UNENCODED" in r["contexts"]
    assert r["payload"] == "\"'<>"
    assert r["status_code"] == 200


def test_reflection_scanner_marks_encoded_reflection_safe():
    """A page that reflects the value HTML/URL-encoded must NOT be flagged as an
    exploitable (UNENCODED) reflection \u2014 this is the 773/780 false-positive class."""
    from html import escape

    class EncodingClient:
        def get(self, url, **_):
            query = parse_qs(urlsplit(url).query)
            val = query["q"][0] if "q" in query else ""
            return FakeResp(200, text="<div>search: " + escape(val) + "</div>")

    scanner = ReflectionScanner(EncodingClient(), start_batch=8)
    found = scanner.scan_url("https://www.adjust.com/search", ["q"])
    assert len(found) == 1
    assert found[0]["param"] == "q"
    assert "(encoded)" in found[0]["contexts"]   # not exploitable
    assert found[0]["payload"] == ""


def test_open_redirect_scanner_detects_location_canary():
    class Client:
        def get(self, url, **_):
            return FakeResp(302, headers={"location": f"https://{CANARY}/x"})

    found = []
    OpenRedirectScanner(Client()).scan(
        ["https://www.adjust.com/login?next=/home"],
        found.append,
        lambda *_: None,
        lambda: False,
        workers=1,
    )

    assert len(found) == 1
    assert found[0]["param"] == "next"
    assert CANARY in found[0]["location"]


def test_downloader_saves_file_and_parent_mapping(tmp_path):
    class Client:
        def get(self, url, **_):
            assert url == "https://cdn.adjust.com/static/app.js"
            return FakeResp(
                200,
                text='fetch("/api/v1/config.json")',
                headers={"content-type": "application/javascript"},
            )

    rec = downloader.Downloader(tmp_path, Client()).download_one({
        "url": "https://cdn.adjust.com/static/app.js",
        "variant": "live",
        "parent_url": "https://www.adjust.com/",
        "kind": "js",
        "depth": 0,
    })

    assert rec["ok"] is True
    assert rec["parent_url"] == "https://www.adjust.com/"
    assert rec["text"] == 'fetch("/api/v1/config.json")'
    assert (tmp_path / "downloads" / "live" / "cdn.adjust.com").is_dir()


def test_livecheck_extracts_title_and_metadata():
    class Client:
        def get(self, url, **_):
            return FakeResp(
                200,
                text="<html><title> Adjust Console </title></html>",
                headers={"content-type": "text/html", "content-length": "43"},
                via_proxy=True,
            )

    rec = livecheck.LiveChecker(Client()).check_one("https://www.adjust.com/")

    assert rec["status_code"] == 200
    assert rec["title"] == "Adjust Console"
    assert rec["via_proxy"] is True


def test_fuzzer_filters_soft_404_and_records_real_hit():
    class Client:
        def get(self, url, **_):
            if url.endswith("/app.js"):
                return FakeResp(200, text="console.log(1)", headers={"content-type": "application/javascript"})
            return FakeResp(404, text="missing", headers={"content-type": "text/plain"})

    found = []
    fuzzer = fuzz.Fuzzer(Client(), exts=["js"], max_base_dirs=2)
    count = fuzzer.fuzz(
        ["https://cdn.adjust.com/static/"],
        ["app", "nope"],
        found.append,
        lambda *_: None,
        lambda: False,
        workers=1,
    )

    assert count == 1
    assert found[0]["found_url"] == "https://cdn.adjust.com/static/app.js"


def test_proxy_normalization_masks_supported_formats():
    assert normalize_proxy("geo.iproyal.com:11201:user:pass") == (
        "http://user:pass@geo.iproyal.com:11201"
    )
    assert normalize_proxy("http://u:p@example:8080") == "http://u:p@example:8080"
    assert normalize_proxy("bad") is None


def test_http_client_block_cooldown_and_auto_recovery():
    import time as _t
    from g2recon.config import SETTINGS
    from g2recon.http_client import HttpClient
    old = SETTINGS.block_cooldown_sec
    SETTINGS.block_cooldown_sec = 60
    try:
        c = HttpClient(proxies=["http://u:p@h:1"])
        assert c.host_blocked("x.adjust.com") is False
        c._mark_blocked("x.adjust.com")
        assert c.host_blocked("x.adjust.com") is True      # routed via proxy now
        # simulate cooldown elapsing -> direct is re-probed (auto recovery)
        c._blocked_until["x.adjust.com"] = _t.time() - 1
        assert c.host_blocked("x.adjust.com") is False
        c._mark_blocked("y.adjust.com")
        c._clear_block("y.adjust.com")                     # clean response clears it
        assert c.host_blocked("y.adjust.com") is False
    finally:
        SETTINGS.block_cooldown_sec = old


def test_valid_host_filters_archive_artifacts():
    assert util.is_valid_host("api.adjust.com")
    assert util.is_valid_host("a.b.c.adjust.com")
    assert not util.is_valid_host("__extcc_www.adjust.com")   # underscore label artifact
    assert not util.is_valid_host("adjust")                   # single label
    assert not util.is_valid_host("bad..adjust.com")          # empty label
    assert util.in_scope("api.adjust.com", "adjust.com")
    assert not util.in_scope("__extcc_www.adjust.com", "adjust.com")


def test_param_name_filter_rejects_value_tokens():
    assert params.is_param_name("redirect_uri")
    assert params.is_param_name("q")
    assert params.is_param_name("utm_source")
    assert params.is_param_name("event_callback_u3fj91")
    assert not params.is_param_name("00f6476a-94b9-4cd4-a5e6-bf62609bc96c")  # uuid
    assert not params.is_param_name("123456")                                # numeric
    assert not params.is_param_name("a" * 60)                                # too long
    assert not params.is_param_name("deadbeefdeadbeefdeadbeef")              # long hex


def test_capture_map_key_groups_scheme_and_query():
    assert wayback._cap_key("https://x.adjust.com/a/app.js?v=1") == \
        wayback._cap_key("http://x.adjust.com/a/app.js")
    assert wayback._cap_key("https://x.adjust.com/a.js") != \
        wayback._cap_key("https://x.adjust.com/b.js")


def test_juicy_capture_map_parses_and_dedups_by_digest(monkeypatch):
    """One CDX page with duplicate digests collapses to unique captures per file."""
    page = (
        '[["original","timestamp","digest","statuscode","mimetype"],'
        '["https://cdn.adjust.com/app.js","20240101000000","DIG1","200","application/javascript"],'
        '["https://cdn.adjust.com/app.js","20230101000000","DIG1","200","application/javascript"],'
        '["https://cdn.adjust.com/app.js","20220101000000","DIG2","200","application/javascript"]]'
    )

    class Client:
        def get(self, url, **_):
            return FakeResp(200, text=page)

    cap = wayback.juicy_capture_map(Client(), "adjust.com", exts=["js"],
                                    batch=10, max_caps_per_url=10)
    key = wayback._cap_key("https://cdn.adjust.com/app.js")
    # DIG1 dedups (2 captures -> 1), DIG2 kept -> 2 unique captures, newest first
    assert cap[key]["caps"] == ["20240101000000", "20220101000000"]
    assert cap[key]["url"] == "https://cdn.adjust.com/app.js"


def test_archive_url_and_file_records_preserve_multiple_timestamps():
    session = get_session()
    target = Target(name="multi-ts-adjust.com", slug="multi-ts-adjust.com")
    session.add(target)
    session.commit()

    rows = [
        {
            "url": "https://cdn.multi-ts-adjust.com/app.js",
            "host": "cdn.multi-ts-adjust.com",
            "source": "wayback",
            "archive_ts": "20200101000000",
            "mime": "application/javascript",
            "is_juicy": True,
            "has_params": False,
        },
        {
            "url": "https://cdn.multi-ts-adjust.com/app.js",
            "host": "cdn.multi-ts-adjust.com",
            "source": "wayback",
            "archive_ts": "20210101000000",
            "mime": "application/javascript",
            "is_juicy": True,
            "has_params": False,
        },
    ]
    store.add_urls(session, target.id, rows)
    assert session.query(Url).filter_by(target_id=target.id).count() == 2

    for row in rows:
        store.add_file(session, target.id, {
            "url": row["url"],
            "variant": "archived",
            "archive_ts": row["archive_ts"],
            "parent_url": "wayback",
            "kind": "js",
            "path": f"/tmp/{row['archive_ts']}.js",
            "size": 1,
            "sha256": row["archive_ts"],
            "status_code": 200,
            "content_type": row["mime"],
            "depth": 0,
        })
    assert session.query(FileRecord).filter_by(target_id=target.id).count() == 2
    session.close()


def test_harvest_domain_paginates_via_resumekey():
    """Domain-wide CDX harvest follows resumeKey across pages and marks done."""
    page1 = ('[["original","timestamp","statuscode","mimetype","digest"],'
             '["https://adjust.com/a","20200101000000","200","text/html","D1"],'
             '["https://app.adjust.com/b","20210101000000","200","text/html","D2"],'
             '[],["RK1"]]')
    page2 = ('[["original","timestamp","statuscode","mimetype","digest"],'
             '["https://adjust.com/c","20220101000000","200","text/html","D3"]]')

    class Client:
        def get(self, url, **_):
            return FakeResp(200, text=(page2 if "resumeKey=RK1" in url else page1))

    cursors = {}
    collected = []
    total = wayback.harvest_domain(
        Client(), "adjust.com",
        on_rows=lambda rows: collected.extend(r["original"] for r in rows),
        get_cursor=lambda k: cursors.get(k),
        set_cursor=lambda k, v: cursors.__setitem__(k, v),
        log=lambda *a: None, should_stop=lambda: False,
        from_year=2024, to_year=2024)
    assert total == 3
    assert collected == ["https://adjust.com/a", "https://app.adjust.com/b",
                         "https://adjust.com/c"]
    assert cursors.get("dom:y2024:done") == "1"


def test_juicy_capture_map_keeps_representative_url():
    """cap_map exposes a downloadable original URL per file (the files-step fix)."""
    page = ('[["original","timestamp","digest","statuscode","mimetype"],'
            '["http://cdn.adjust.com/x.js","20200101000000","D1","200","application/javascript"],'
            '["https://cdn.adjust.com/x.js","20240101000000","D2","200","application/javascript"]]')

    class Client:
        def get(self, url, **_):
            return FakeResp(200, text=page)

    cap = wayback.juicy_capture_map(Client(), "adjust.com", exts=["js"],
                                    batch=10, max_caps_per_url=10)
    key = wayback._cap_key("https://cdn.adjust.com/x.js")
    assert cap[key]["url"].startswith("https://")   # prefers https original
    assert len(cap[key]["caps"]) == 2


def test_openredirect_only_flags_canary_host():
    from g2recon.modules.openredirect import _redirects_to_canary
    # genuine redirects to the canary host
    assert _redirects_to_canary("https://g2r-oob.example")
    assert _redirects_to_canary("//g2r-oob.example/path")
    assert _redirects_to_canary("/\\g2r-oob.example")           # browsers treat \\ as /
    assert _redirects_to_canary("https://localhost.g2r-oob.example")
    # NOT a redirect to canary: legit host that merely echoes canary in a param
    assert not _redirects_to_canary(
        "https://play.google.com/store/apps/details?id=x&referrer=g2r-oob.example")
    assert not _redirects_to_canary("/relative/path?u=g2r-oob.example")


def test_jsanalyze_filters_namespace_and_mime_noise():
    assert jsanalyze._is_noise_link("text/css")
    assert jsanalyze._is_noise_link("application/json")
    assert jsanalyze._is_noise_link("http://www.w3.org/2005/Atom")
    assert not jsanalyze._is_noise_link("/api/v1/users")
    assert not jsanalyze._is_noise_link("/smart_banner")
    assert not jsanalyze._is_noise_link("https://api.adjust.com/track")


def test_basic_auth_url_ignores_jsonld_schema():
    from g2recon.modules import jsanalyze
    fp = '"sameAs":"https://schema.org","mainEntityOfPage":{"@type":"WebPage"}'
    hits = [s for s in jsanalyze.find_secrets(fp) if s["rule"] == "basic_auth_url"]
    assert hits == []
    real = [s for s in jsanalyze.find_secrets("mongodb://admin:S3cr3t@db.example.com/x")
            if s["rule"] == "basic_auth_url"]
    assert len(real) == 1


def test_is_html_shell_detects_soft404():
    from g2recon.pipeline import _is_html_shell
    assert _is_html_shell({"kind": "js", "content_type": "text/html; charset=utf-8",
                           "text": "<!DOCTYPE html><html><head>"})
    assert not _is_html_shell({"kind": "json", "content_type": "application/json",
                               "text": '{"a":1}'})
    assert not _is_html_shell({"kind": "js", "content_type": "application/javascript",
                               "text": "window.x=1"})


def test_order_diverse_spreads_hosts():
    from g2recon.modules import reflection as refl
    urls = ([f"https://app.adjust.com/a{i}?x=1" for i in range(50)] +
            ["https://help.adjust.com/p?y=1", "https://dash.adjust.com/q?z=1"])
    ordered = refl.order_diverse(refl.dedup_targets(urls))
    from urllib.parse import urlsplit
    first5 = {urlsplit(it["base"]).hostname for it in ordered[:5]}
    # round-robin must surface non-app hosts early, not bury them after 50 app urls
    assert "help.adjust.com" in first5 and "dash.adjust.com" in first5


def test_fuzz_record_status_excludes_5xx():
    from g2recon.modules import fuzz
    assert 500 not in fuzz.RECORD_STATUS and 503 not in fuzz.RECORD_STATUS
    assert 200 in fuzz.RECORD_STATUS and 403 in fuzz.RECORD_STATUS
