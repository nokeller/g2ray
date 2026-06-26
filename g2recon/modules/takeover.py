"""Subdomain-takeover detection.

For each in-scope host we resolve the CNAME chain + A records, classify the
CNAME against a fingerprint table of takeover-prone SaaS providers, and (for
candidates) fetch the page and look for the provider's "unclaimed" signature.

Reported rows are high-signal: a host CNAME'd to a provider whose page shows the
unclaimed signature is ``vulnerable`` (high); a CNAME to a provider that serves
real content is ``claimed`` (info, so the operator can see the inventory); a
CNAME whose target does not resolve (NXDOMAIN) is ``dangling`` (worth a manual
look). Hosts with a plain A record and no SaaS CNAME are not recorded.

DNS uses ``dig`` against public resolvers (1.1.1.1 / 8.8.8.8) because the local
systemd-resolved stub is unreliable under concurrency.
"""
from __future__ import annotations

import concurrent.futures as cf
import subprocess
from typing import Callable

LogFn = Callable[[str, str], None]

# provider -> (cname substrings, unclaimed-page signatures)
FINGERPRINTS: dict[str, tuple[list[str], list[str]]] = {
    "github_pages": (["github.io"],
                     ["there isn't a github pages site here",
                      "for root urls (like http"]),
    "heroku": (["herokuapp.com", "herokudns.com"],
               ["no such app", "herokucdn.com/error-pages/no-such-app"]),
    "aws_s3": (["s3.amazonaws.com", "s3-website", ".s3.", "amazonaws.com"],
               ["nosuchbucket", "the specified bucket does not exist"]),
    "netlify": (["netlify.com", "netlifyglobalcdn.com", "netlify.app"],
                ["not found - request id", "no such site", "not found"]),
    "zendesk": (["zendesk.com"],
                ["help center closed", "this help center no longer exists"]),
    "shopify": (["myshopify.com"], ["sorry, this shop is currently unavailable"]),
    "fastly": (["fastly.net"], ["fastly error: unknown domain"]),
    "pantheon": (["pantheonsite.io"], ["the gods are wise", "404 error unknown site"]),
    "surge": (["surge.sh"], ["project not found"]),
    "bitbucket": (["bitbucket.io"], ["repository not found"]),
    "ghost": (["ghost.io"], ["domain error"]),
    "wpengine": (["wpengine.com"], ["404 that's an error"]),
    "readme": (["readme.io"], ["project doesnt exist"]),
    "azure": (["azurewebsites.net", "cloudapp.net", "trafficmanager.net",
               "azureedge.net", "blob.core.windows.net"],
              ["404 web site not found",
               "the resource you are looking for has been removed"]),
    "frontify": (["frontify.com"], ["404", "page not found"]),
}


def classify_cname(cname: str) -> str:
    """Return the provider key whose CNAME substrings match, or ''."""
    c = (cname or "").lower()
    if not c:
        return ""
    for prov, (subs, _sig) in FINGERPRINTS.items():
        if any(s in c for s in subs):
            return prov
    return ""


def is_takeover(provider: str, body: str) -> bool:
    """True if the page body carries the provider's unclaimed-resource signature."""
    sigs = FINGERPRINTS.get(provider, (None, []))[1]
    low = (body or "").lower()
    return any(sig in low for sig in sigs)


def _dig(rtype: str, host: str) -> str:
    for resolver in ("@1.1.1.1", "@8.8.8.8"):
        try:
            out = subprocess.run(["dig", resolver, "+short", "+time=4", "+tries=1",
                                  rtype, host], capture_output=True, text=True,
                                 timeout=8).stdout.strip()
            if out and ";;" not in out:
                return out
        except Exception:
            continue
    return ""


class TakeoverScanner:
    def __init__(self, client):
        self.client = client

    def _check(self, host: str) -> dict | None:
        cname = _dig("CNAME", host)
        a = _dig("A", host)
        provider = classify_cname(cname)
        if not provider and (cname or a):
            return None  # resolves fine, not a SaaS CNAME -> not interesting
        if not provider and not cname and not a:
            return None  # no records at all (could be wildcard noise); skip
        status, sev, evidence = "claimed", "info", ""
        if provider and not a:
            # CNAME to a provider but the target does not resolve -> dangling
            status, sev = "dangling", "medium"
            evidence = "CNAME resolves to nothing (NXDOMAIN)"
        if provider:
            try:
                r = self.client.get(f"https://{host}/", allow_redirects=True,
                                    timeout=12, max_proxy_tries=1)
                body = r.text or ""
                if is_takeover(provider, body):
                    status, sev = "vulnerable", "high"
                    evidence = f"{provider} unclaimed signature in response (HTTP {r.status})"
                elif not evidence:
                    evidence = f"{provider} serves content (HTTP {r.status})"
            except Exception as e:
                if status == "dangling":
                    evidence += f"; fetch failed: {str(e)[:80]}"
                else:
                    return None
        return {"host": host, "cname": cname[:300], "a_record": a[:300],
                "provider": provider, "status": status, "severity": sev,
                "evidence": evidence[:400]}

    def run(self, hosts: list[str], persist: Callable[[dict], None],
            log: LogFn, should_stop: Callable[[], bool], workers: int = 40) -> int:
        hosts = sorted(set(h for h in hosts if h))
        log("info", f"takeover: resolving {len(hosts)} hosts (CNAME/A) for dangling SaaS")
        count = 0
        with cf.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self._check, h): h for h in hosts}
            for fut in cf.as_completed(futs):
                if should_stop():
                    break
                try:
                    rec = fut.result()
                except Exception:
                    rec = None
                if rec:
                    persist(rec)
                    count += 1
                    if rec["status"] in ("vulnerable", "dangling"):
                        log("warn", f"takeover: {rec['status'].upper()} {rec['host']} "
                                    f"-> {rec['cname']} ({rec['evidence']})")
        log("info", f"takeover: {count} SaaS-CNAME hosts recorded")
        return count
