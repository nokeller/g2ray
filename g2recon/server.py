"""FastAPI application: auth, REST API, exports, secure downloads, static UI."""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import time
import zipfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Response, UploadFile, File, Form, Body
from fastapi.responses import (JSONResponse, HTMLResponse, FileResponse,
                               StreamingResponse, PlainTextResponse, RedirectResponse)
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select, func, delete, or_

from . import config, store, util
from .config import SETTINGS, save_settings, hash_password, verify_password, WORDLIST_DIR
from .db import (init_db, get_session, Target, Subdomain, Url, FileRecord, JsLink,
                 Secret, Param, Reflection, OpenRedirect, LiveResult, FuzzResult, Job, JobLog)
from .http_client import get_client
from .worker import get_manager

WEB_DIR = Path(__file__).resolve().parent / "web"
COOKIE = "g2r_session"

app = FastAPI(title="g2recon", version="1.2.0")


@app.on_event("startup")
def _startup():
    init_db()
    get_manager()


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------
def make_token(user: str) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"u": user, "exp": time.time() + 7 * 86400}).encode()).decode()
    sig = hmac.new(SETTINGS.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def verify_token(tok: str) -> Optional[str]:
    try:
        payload, sig = tok.split(".", 1)
        good = hmac.new(SETTINGS.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        if data.get("exp", 0) < time.time():
            return None
        return data.get("u")
    except Exception:
        return None


def require_auth(request: Request) -> str:
    tok = request.cookies.get(COOKIE, "")
    user = verify_token(tok) if tok else None
    if not user:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


@app.post("/api/login")
async def login(response: Response, body: dict = Body(...)):
    user = (body.get("user") or "").strip()
    pw = body.get("password") or ""
    if user == SETTINGS.admin_user and verify_password(pw, SETTINGS.admin_password_hash):
        tok = make_token(user)
        resp = JSONResponse({"ok": True, "user": user})
        resp.set_cookie(COOKIE, tok, httponly=True, samesite="lax",
                        max_age=7 * 86400, secure=False)
        return resp
    raise HTTPException(status_code=401, detail="invalid credentials")


@app.post("/api/logout")
async def logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(COOKIE)
    return resp


@app.get("/api/me")
async def me(user: str = Depends(require_auth)):
    return {"user": user, "version": app.version}


# --------------------------------------------------------------------------
# serialization helpers
# --------------------------------------------------------------------------
def row_to_dict(obj) -> dict:
    out = {}
    for col in obj.__table__.columns:
        v = getattr(obj, col.name)
        if hasattr(v, "isoformat"):
            v = v.isoformat()
        out[col.name] = v
    return out


def list_response(session, model, target_id: int, *, filters=None, search_cols=None,
                  q="", limit=100, offset=0, order_col=None, order_desc=True):
    filters = list(filters or [])
    base = [model.target_id == target_id, *filters]
    if q and search_cols:
        like = f"%{q}%"
        base.append(or_(*[c.like(like) for c in search_cols]))
    total = session.execute(select(func.count()).select_from(model).where(*base)).scalar() or 0
    stmt = select(model).where(*base)
    oc = order_col if order_col is not None else model.id
    stmt = stmt.order_by(oc.desc() if order_desc else oc.asc()).limit(min(limit, 2000)).offset(offset)
    items = [row_to_dict(r) for r in session.execute(stmt).scalars().all()]
    return {"total": total, "items": items, "limit": limit, "offset": offset}


# --------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------
@app.get("/api/settings")
async def get_settings(user: str = Depends(require_auth)):
    d = SETTINGS.public_dict()
    d["impersonate_active"] = get_client().impersonate
    return d


@app.post("/api/settings")
async def update_settings(body: dict = Body(...), user: str = Depends(require_auth)):
    changed = False
    if "proxies" in body and isinstance(body["proxies"], list):
        # only replace if values are real (not masked)
        real = [p for p in body["proxies"] if "****" not in p and p.strip()]
        SETTINGS.proxies = real
        changed = True
    for key in ("impersonate", "wayback_batch_size",
                "wayback_from_year", "wayback_to_year", "download_workers",
                "check_workers", "fuzz_workers", "request_delay_ms",
                "max_files_per_target", "max_concurrent_jobs",
                "use_proxy_only_on_block"):
        if key in body:
            setattr(SETTINGS, key, body[key])
            changed = True
    if body.get("new_password"):
        SETTINGS.admin_password_hash = hash_password(body["new_password"])
        changed = True
    if changed:
        save_settings(SETTINGS)
        get_client(refresh=True)
    return SETTINGS.public_dict()


# --------------------------------------------------------------------------
# targets
# --------------------------------------------------------------------------
@app.get("/api/targets")
async def list_targets(user: str = Depends(require_auth)):
    s = get_session()
    out = []
    for t in s.execute(select(Target).order_by(Target.id.desc())).scalars().all():
        d = row_to_dict(t)
        d["counts"] = store.counts(s, t.id)
        last = s.execute(select(Job).where(Job.target_id == t.id)
                         .order_by(Job.id.desc()).limit(1)).scalars().first()
        d["job"] = row_to_dict(last) if last else None
        out.append(d)
    s.close()
    return out


@app.post("/api/targets")
async def create_target(body: dict = Body(...), user: str = Depends(require_auth)):
    name = util.root_domain(body.get("name") or "")
    if not name:
        raise HTTPException(400, "invalid domain")
    s = get_session()
    existing = s.execute(select(Target).where(Target.name == name)).scalars().first()
    if existing:
        s.close()
        raise HTTPException(409, "target already exists")
    t = Target(name=name, slug=util.slugify(name), scope_note=body.get("scope_note", ""))
    s.add(t)
    s.commit()
    tid = t.id
    d = row_to_dict(t)
    s.close()
    (Path(SETTINGS.data_dir) / "targets" / util.slugify(name)).mkdir(parents=True, exist_ok=True)
    return d


@app.get("/api/targets/{tid}")
async def get_target(tid: int, user: str = Depends(require_auth)):
    s = get_session()
    t = s.get(Target, tid)
    if not t:
        s.close()
        raise HTTPException(404, "not found")
    d = row_to_dict(t)
    d["counts"] = store.counts(s, tid)
    last = s.execute(select(Job).where(Job.target_id == tid)
                     .order_by(Job.id.desc()).limit(1)).scalars().first()
    d["job"] = row_to_dict(last) if last else None
    s.close()
    return d


@app.delete("/api/targets/{tid}")
async def delete_target(tid: int, user: str = Depends(require_auth)):
    get_manager().stop_target(tid)
    s = get_session()
    t = s.get(Target, tid)
    if not t:
        s.close()
        raise HTTPException(404, "not found")
    for model in (Subdomain, Url, FileRecord, JsLink, Secret, Param, Reflection,
                  OpenRedirect, LiveResult, FuzzResult, JobLog, Job):
        s.execute(delete(model).where(model.target_id == tid))
    slug = t.slug
    s.delete(t)
    s.commit()
    s.close()
    import shutil
    shutil.rmtree(Path(SETTINGS.data_dir) / "targets" / slug, ignore_errors=True)
    return {"ok": True}


@app.post("/api/targets/{tid}/upload_params")
async def upload_params(tid: int, file: UploadFile = File(...), user: str = Depends(require_auth)):
    s = get_session(); t = s.get(Target, tid); s.close()
    if not t:
        raise HTTPException(404, "not found")
    d = Path(SETTINGS.data_dir) / "targets" / t.slug
    d.mkdir(parents=True, exist_ok=True)
    dest = d / "base_params.txt"
    dest.write_bytes(await file.read())
    return {"ok": True, "path": str(dest), "lines": len(dest.read_text(errors='ignore').splitlines())}


@app.post("/api/targets/{tid}/upload_subdomains")
async def upload_subdomains(tid: int, file: UploadFile = File(...), user: str = Depends(require_auth)):
    s = get_session(); t = s.get(Target, tid); s.close()
    if not t:
        raise HTTPException(404, "not found")
    d = Path(SETTINGS.data_dir) / "targets" / t.slug
    d.mkdir(parents=True, exist_ok=True)
    dest = d / "subindex_output.txt"
    dest.write_bytes(await file.read())
    return {"ok": True, "path": str(dest), "lines": len(dest.read_text(errors='ignore').splitlines())}


@app.post("/api/targets/{tid}/start")
async def start_target(tid: int, body: dict = Body(default={}), user: str = Depends(require_auth)):
    s = get_session(); t = s.get(Target, tid); s.close()
    if not t:
        raise HTTPException(404, "not found")
    options = dict(body or {})
    base_params = Path(SETTINGS.data_dir) / "targets" / t.slug / "base_params.txt"
    if base_params.exists():
        options.setdefault("base_params_path", str(base_params))
    subindex = Path(SETTINGS.data_dir) / "targets" / t.slug / "subindex_output.txt"
    if subindex.exists() and not options.get("subindex_output"):
        options["subindex_output"] = subindex.read_text(errors="ignore")
    job_id = get_manager().submit(tid, options)
    return {"ok": True, "job_id": job_id}


@app.post("/api/targets/{tid}/stop")
async def stop_target(tid: int, user: str = Depends(require_auth)):
    n = get_manager().stop_target(tid)
    return {"ok": True, "stopped": n}


# --------------------------------------------------------------------------
# logs / job status
# --------------------------------------------------------------------------
@app.get("/api/targets/{tid}/logs")
async def get_logs(tid: int, after: int = 0, limit: int = 300, user: str = Depends(require_auth)):
    s = get_session()
    rows = s.execute(select(JobLog).where(JobLog.target_id == tid, JobLog.id > after)
                     .order_by(JobLog.id.asc()).limit(limit)).scalars().all()
    out = [row_to_dict(r) for r in rows]
    s.close()
    return {"items": out, "last_id": out[-1]["id"] if out else after}


# --------------------------------------------------------------------------
# data listing endpoints
# --------------------------------------------------------------------------
@app.get("/api/targets/{tid}/subdomains")
async def d_subdomains(tid: int, q: str = "", limit: int = 200, offset: int = 0,
                       user: str = Depends(require_auth)):
    s = get_session()
    r = list_response(s, Subdomain, tid, search_cols=[Subdomain.host, Subdomain.source],
                      q=q, limit=limit, offset=offset, order_col=Subdomain.host, order_desc=False)
    s.close(); return r


@app.get("/api/targets/{tid}/urls")
async def d_urls(tid: int, q: str = "", juicy: int = 0, params: int = 0,
                 limit: int = 200, offset: int = 0, user: str = Depends(require_auth)):
    s = get_session()
    filters = []
    if juicy:
        filters.append(Url.is_juicy == True)   # noqa: E712
    if params:
        filters.append(Url.has_params == True)  # noqa: E712
    r = list_response(s, Url, tid, filters=filters, search_cols=[Url.url],
                      q=q, limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/files")
async def d_files(tid: int, q: str = "", kind: str = "", variant: str = "",
                  limit: int = 200, offset: int = 0, user: str = Depends(require_auth)):
    s = get_session()
    filters = []
    if kind:
        filters.append(FileRecord.kind == kind)
    if variant:
        filters.append(FileRecord.variant == variant)
    r = list_response(s, FileRecord, tid, filters=filters,
                      search_cols=[FileRecord.url, FileRecord.parent_url],
                      q=q, limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/jslinks")
async def d_jslinks(tid: int, q: str = "", kind: str = "", limit: int = 200, offset: int = 0,
                    user: str = Depends(require_auth)):
    s = get_session()
    filters = [JsLink.kind == kind] if kind else []
    r = list_response(s, JsLink, tid, filters=filters,
                      search_cols=[JsLink.link, JsLink.source_file], q=q,
                      limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/secrets")
async def d_secrets(tid: int, q: str = "", limit: int = 200, offset: int = 0,
                    user: str = Depends(require_auth)):
    s = get_session()
    r = list_response(s, Secret, tid, search_cols=[Secret.rule, Secret.match, Secret.source_file],
                      q=q, limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/params")
async def d_params(tid: int, q: str = "", limit: int = 500, offset: int = 0,
                   user: str = Depends(require_auth)):
    s = get_session()
    r = list_response(s, Param, tid, search_cols=[Param.name], q=q,
                      limit=limit, offset=offset, order_col=Param.name, order_desc=False)
    s.close(); return r


@app.get("/api/targets/{tid}/reflections")
async def d_reflections(tid: int, q: str = "", limit: int = 200, offset: int = 0,
                        user: str = Depends(require_auth)):
    s = get_session()
    r = list_response(s, Reflection, tid, search_cols=[Reflection.url, Reflection.param],
                      q=q, limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/openredirects")
async def d_openredirects(tid: int, q: str = "", limit: int = 200, offset: int = 0,
                          user: str = Depends(require_auth)):
    s = get_session()
    r = list_response(s, OpenRedirect, tid, search_cols=[OpenRedirect.url, OpenRedirect.param],
                      q=q, limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/live")
async def d_live(tid: int, q: str = "", status: int = 0, limit: int = 200, offset: int = 0,
                 user: str = Depends(require_auth)):
    s = get_session()
    filters = [LiveResult.status_code == status] if status else []
    r = list_response(s, LiveResult, tid, filters=filters,
                      search_cols=[LiveResult.url, LiveResult.title], q=q,
                      limit=limit, offset=offset)
    s.close(); return r


@app.get("/api/targets/{tid}/fuzz")
async def d_fuzz(tid: int, q: str = "", limit: int = 200, offset: int = 0,
                 user: str = Depends(require_auth)):
    s = get_session()
    r = list_response(s, FuzzResult, tid, search_cols=[FuzzResult.found_url, FuzzResult.base_url],
                      q=q, limit=limit, offset=offset)
    s.close(); return r


# --------------------------------------------------------------------------
# exports + downloads
# --------------------------------------------------------------------------
_EXPORT_MODELS = {
    "subdomains": Subdomain, "urls": Url, "files": FileRecord, "jslinks": JsLink,
    "secrets": Secret, "params": Param, "reflections": Reflection,
    "openredirects": OpenRedirect, "live": LiveResult, "fuzz": FuzzResult,
}


@app.get("/api/targets/{tid}/export/{kind}.csv")
async def export_csv(tid: int, kind: str, user: str = Depends(require_auth)):
    model = _EXPORT_MODELS.get(kind)
    if not model:
        raise HTTPException(404, "unknown export")
    s = get_session()
    rows = s.execute(select(model).where(model.target_id == tid)).scalars().all()
    cols = [c.name for c in model.__table__.columns]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([getattr(r, c) for c in cols])
    s.close()
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{kind}_{tid}.csv"'})


@app.get("/api/targets/{tid}/files/{fid}/raw")
async def file_raw(tid: int, fid: int, user: str = Depends(require_auth)):
    s = get_session()
    f = s.get(FileRecord, fid)
    s.close()
    if not f or f.target_id != tid or not f.path:
        raise HTTPException(404, "not found")
    p = Path(f.path).resolve()
    data_root = Path(SETTINGS.data_dir).resolve()
    if data_root not in p.parents or not p.exists():
        raise HTTPException(404, "file missing")
    return FileResponse(str(p), filename=p.name, media_type="application/octet-stream")


@app.get("/api/targets/{tid}/master/{name}")
async def master_file(tid: int, name: str, user: str = Depends(require_auth)):
    s = get_session(); t = s.get(Target, tid); s.close()
    if not t:
        raise HTTPException(404, "not found")
    safe = "".join(c for c in name if c.isalnum() or c in "._-")
    p = (Path(SETTINGS.data_dir) / "targets" / t.slug / safe).resolve()
    data_root = Path(SETTINGS.data_dir).resolve()
    if data_root not in p.parents or not p.exists():
        raise HTTPException(404, "file missing")
    return FileResponse(str(p), filename=p.name, media_type="text/plain")


@app.get("/api/targets/{tid}/zip")
async def target_zip(tid: int, user: str = Depends(require_auth)):
    s = get_session(); t = s.get(Target, tid); s.close()
    if not t:
        raise HTTPException(404, "not found")
    base = Path(SETTINGS.data_dir) / "targets" / t.slug
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in base.rglob("*"):
            if f.is_file():
                z.write(f, f.relative_to(base))
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{t.slug}_recon.zip"'})


# --------------------------------------------------------------------------
# static UI
# --------------------------------------------------------------------------
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    idx = WEB_DIR / "index.html"
    return HTMLResponse(idx.read_text())


@app.get("/healthz")
async def healthz():
    return {"ok": True, "version": app.version}
