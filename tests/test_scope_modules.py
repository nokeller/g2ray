"""Unit tests for the scope filter, takeover fingerprints, and CORS classifier."""
from __future__ import annotations

from g2recon.modules import scope
from g2recon.modules.takeover import classify_cname, is_takeover
from g2recon.modules.corscheck import classify, EVIL_ORIGIN


def test_scope_parse_and_exclude():
    pats = scope.parse_patterns(
        "www.8x8.com\n*.msteams.8x8.com, jitsi.org\nhttps://get8x8.com/x\n# comment")
    assert "www.8x8.com" in pats
    assert "msteams.8x8.com" in pats
    assert "jitsi.org" in pats
    assert "get8x8.com" in pats
    assert scope.host_excluded("www.8x8.com", pats)
    assert scope.host_excluded("a.msteams.8x8.com", pats)   # wildcard suffix
    assert scope.host_excluded("msteams.8x8.com", pats)     # apex of wildcard
    assert scope.host_excluded("sub.jitsi.org", pats)
    assert not scope.host_excluded("vcc-na2.8x8.com", pats)  # in scope


def test_takeover_classify_cname():
    assert classify_cname("8x8.github.io.") == "github_pages"
    assert classify_cname("foo.herokuapp.com") == "heroku"
    assert classify_cname("wavecell.zendesk.com") == "zendesk"
    assert classify_cname("d156.cloudfront.net") == ""        # CDN, not takeover-prone here
    assert classify_cname("") == ""


def test_takeover_signature_match():
    assert is_takeover("github_pages", "404 There isn't a GitHub Pages site here.")
    assert is_takeover("aws_s3", "<Code>NoSuchBucket</Code>")
    assert not is_takeover("github_pages", "<html>real developer portal</html>")


def test_cors_classifier_severity():
    # exploitable: arbitrary origin + creds + cookie, not gated
    sev, _ = classify(EVIL_ORIGIN, True, True, status=200, location="")
    assert sev == "high"
    # gated behind Cloudflare Access -> downgraded
    sev, note = classify(EVIL_ORIGIN, True, True, status=302,
                         location="https://8x8com.cloudflareaccess.com/cdn-cgi/access/login/x")
    assert sev == "low" and "gated" in note.lower()
    # token auth (creds, no cookie) -> low
    sev, _ = classify(EVIL_ORIGIN, True, False)
    assert sev == "low"
    # null origin + creds -> high
    sev, _ = classify("null", True, False)
    assert sev == "high"
    # wildcard, no creds -> info
    sev, _ = classify("*", False, False)
    assert sev == "info"
    # no ACAO -> not a finding
    sev, _ = classify("", False, False)
    assert sev == ""
