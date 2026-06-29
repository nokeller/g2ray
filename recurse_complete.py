"""Targeted recursive JS/juicy completion using the app's own Downloader +
jsanalyze + store (the exact on_file logic the pipeline uses), seeded from the
in-scope juicy files referenced in JS but not yet downloaded. Proves recursion
end-to-end and completes coverage where a huge depth-0 archive set had starved it.
"""
import sys, threading, traceback
from pathlib import Path
from urllib.parse import urljoin

from g2recon.config import SETTINGS
from g2recon import store, util
from g2recon.db import get_session, FileRecord, Target, JsLink
from g2recon.modules import downloader as m_dl, jsanalyze
from g2recon.modules import wayback as m_wb
from g2recon.http_client import get_client
from sqlalchemy import select, func

ROOT = "adjust.com"; TID = 1; MAXD = 3
s = get_session()
t = s.get(Target, TID)
d = Path(SETTINGS.data_dir) / "targets" / t.slug
client = get_client(refresh=True)
dl = m_dl.Downloader(d, client)
lock = threading.Lock()

have_url = {r[0].split("#")[0] for r in s.execute(
    select(FileRecord.url).where(FileRecord.target_id == TID))}
seen_keys = {m_wb._cap_key(u) for u in have_url}
print("already-downloaded urls:", len(have_url), flush=True)

from g2recon.db import Secret, Subdomain, Endpoint
b_jl = s.execute(select(func.count()).select_from(JsLink).where(JsLink.target_id == TID)).scalar()
b_sec = s.execute(select(func.count()).select_from(Secret).where(Secret.target_id == TID)).scalar()
b_sub = s.execute(select(func.count()).select_from(Subdomain).where(Subdomain.target_id == TID)).scalar()

def html_shell(rec):
    ct = (rec.get("content_type") or "").lower()
    txt = (rec.get("text") or "")[:300].lstrip().lower()
    if rec.get("kind") in ("js", "json", "config", "map") and (
            "text/html" in ct or txt.startswith("<!doctype html") or txt.startswith("<html")):
        return True
    return False

new_parent = {}
fetched_ok = {"n": 0}

def on_file(rec):
    analysis = None
    analyzable = rec.get("kind") in ("js", "json", "config", "map")
    if analyzable and html_shell(rec):
        analyzable = False
    if rec.get("ok") and rec.get("text") and analyzable:
        analysis = jsanalyze.analyze(rec["text"], rec["url"], ROOT)
    rec["analyzed"] = analysis is not None
    with lock:
        store.add_file(s, TID, rec)
        if rec.get("ok"):
            fetched_ok["n"] += 1
        if analysis:
            store.add_jslinks(s, TID, [(l, k, rec["url"]) for (l, k) in analysis["links"]])
            store.add_secrets(s, TID, [{**sc, "source_file": rec["url"]} for sc in analysis["secrets"]])
            if analysis["subdomains"]:
                store.add_subdomains(s, TID, [(h, "js") for h in analysis["subdomains"]])
            for nf in analysis["new_files"]:
                new_parent.setdefault(nf, rec["url"])

# seed depth-1 = in-scope juicy files referenced in JS but not downloaded
seed = {}
for r in s.execute(select(JsLink.link, JsLink.source_file).where(
        JsLink.target_id == TID, JsLink.kind == "file")):
    link, src = r[0], r[1] or ""
    if not src or "://" not in src:
        continue
    try:
        absu = ("https:" + link) if link.startswith("//") else urljoin(src, link)
    except Exception:
        continue
    absu = absu.split("#")[0]
    h = util.host_of(absu)
    if util.in_scope(h, ROOT) and util.ext_of(absu) in util.JUICY_EXT and absu not in have_url:
        seed.setdefault(absu, src)
entries = [{"url": u, "parent": p} for u, p in seed.items()]
print("seed depth-1 new files:", len(entries), flush=True)

depth = 1
while entries and depth <= MAXD:
    items = []
    for e in entries:
        k = m_wb._cap_key(e["url"])
        if k in seen_keys:
            continue
        seen_keys.add(k)
        items.append({"url": e["url"], "variant": "live", "parent_url": e.get("parent", ""),
                      "kind": util.kind_for_url(e["url"]), "depth": depth})
    print(f"depth {depth}: fetching {len(items)} files", flush=True)
    new_parent.clear()
    for i in range(0, len(items), 400):
        dl.download_many(items[i:i + 400], on_file, lambda l, m: None, lambda: False)
        print(f"  depth {depth}: {min(i+400,len(items))}/{len(items)} (ok so far {fetched_ok['n']})", flush=True)
    nxt = []
    for nf, par in list(new_parent.items()):
        if (m_wb._cap_key(nf) not in seen_keys and nf not in have_url
                and util.in_scope(util.host_of(nf), ROOT)
                and util.ext_of(nf) in util.JUICY_EXT):
            nxt.append({"url": nf, "parent": par})
    print(f"depth {depth}: discovered {len(nxt)} further new files", flush=True)
    depth += 1
    entries = nxt

a_jl = s.execute(select(func.count()).select_from(JsLink).where(JsLink.target_id == TID)).scalar()
a_sec = s.execute(select(func.count()).select_from(Secret).where(Secret.target_id == TID)).scalar()
a_sub = s.execute(select(func.count()).select_from(Subdomain).where(Subdomain.target_id == TID)).scalar()
print(f"RESULT fetched_ok={fetched_ok['n']} | jslinks {b_jl}->{a_jl} (+{a_jl-b_jl}) | "
      f"secrets {b_sec}->{a_sec} (+{a_sec-b_sec}) | subs {b_sub}->{a_sub} (+{a_sub-b_sub})", flush=True)
# depth distribution of files now
import sqlite3
c = sqlite3.connect(str(Path(SETTINGS.data_dir) / "g2recon.db"))
print("files by depth:", [(r[0], r[1]) for r in c.execute(
    "SELECT depth,COUNT(*) FROM files WHERE target_id=1 GROUP BY depth ORDER BY depth")])
c.close()
s.close()
print("DONE", flush=True)
