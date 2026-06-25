"""Database access helpers (dedup-aware inserts + queries)."""
from __future__ import annotations

from typing import Iterable, Optional
from sqlalchemy import select, func, delete
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .db import (
    get_session, Target, Subdomain, Url, FileRecord, JsLink, Secret, Param,
    Reflection, OpenRedirect, LiveResult, FuzzResult, Job, JobLog, Setting,
)


# ---------- cursors (resume) ----------
def cursor_get(session, key: str) -> Optional[str]:
    row = session.get(Setting, key)
    return row.value if row else None


def cursor_set(session, key: str, value: str) -> None:
    stmt = sqlite_insert(Setting).values(key=key, value=value)
    stmt = stmt.on_conflict_do_update(index_elements=["key"], set_={"value": value})
    session.execute(stmt)
    session.commit()


# ---------- inserts (ignore duplicates on unique constraints) ----------
def _insert_ignore(session, model, rows: list[dict], index_elements: list[str]):
    if not rows:
        return 0
    stmt = sqlite_insert(model).on_conflict_do_nothing(index_elements=index_elements)
    session.execute(stmt, rows)
    session.commit()
    return len(rows)


def add_subdomains(session, target_id: int, items: Iterable[tuple[str, str]]) -> int:
    rows = [{"target_id": target_id, "host": h, "source": s, "in_scope": True}
            for (h, s) in {(h, s) for h, s in items} if h]
    return _insert_ignore(session, Subdomain, rows, ["target_id", "host"])


def add_urls(session, target_id: int, rows: list[dict]) -> int:
    payload = [{"target_id": target_id, **r} for r in rows]
    return _insert_ignore(session, Url, payload, ["target_id", "url", "source", "archive_ts"])


def add_file(session, target_id: int, rec: dict) -> int:
    row = {"target_id": target_id, "url": rec["url"], "parent_url": rec.get("parent_url", ""),
           "kind": rec.get("kind", "other"), "variant": rec.get("variant", "live"),
           "archive_ts": rec.get("archive_ts", ""), "path": rec.get("path", ""),
           "size": rec.get("size", 0), "sha256": rec.get("sha256", ""),
           "status_code": rec.get("status_code", 0),
           "content_type": rec.get("content_type", ""), "depth": rec.get("depth", 0)}
    stmt = sqlite_insert(FileRecord).values(**row).on_conflict_do_update(
        index_elements=["target_id", "url", "variant", "archive_ts"],
        set_={"status_code": row["status_code"], "size": row["size"],
              "sha256": row["sha256"], "path": row["path"],
              "content_type": row["content_type"], "parent_url": row["parent_url"]})
    session.execute(stmt)
    session.commit()
    return 1


def add_jslinks(session, target_id: int, items: Iterable[tuple[str, str, str]]) -> int:
    rows = [{"target_id": target_id, "link": l[:1000], "kind": k, "source_file": sf}
            for (l, k, sf) in items if l]
    return _insert_ignore(session, JsLink, rows, ["target_id", "link", "source_file"])


def add_secrets(session, target_id: int, items: Iterable[dict]) -> int:
    rows = [{"target_id": target_id, "rule": it["rule"], "match": it["match"],
             "severity": it.get("severity", "medium"), "context": it.get("context", ""),
             "source_file": it.get("source_file", "")} for it in items]
    return _insert_ignore(session, Secret, rows, ["target_id", "rule", "match", "source_file"])


def add_params(session, target_id: int, items: Iterable[tuple[str, str]]) -> int:
    rows = [{"target_id": target_id, "name": n, "source": s}
            for (n, s) in {(n, s) for n, s in items} if n]
    return _insert_ignore(session, Param, rows, ["target_id", "name"])


def add_reflection(session, target_id: int, rec: dict) -> None:
    session.add(Reflection(target_id=target_id, url=rec["url"], param=rec["param"],
                           payload=rec.get("payload", ""), reflected=True,
                           contexts=rec.get("contexts", ""),
                           status_code=rec.get("status_code", 0)))
    session.commit()


def add_openredirect(session, target_id: int, rec: dict) -> None:
    session.add(OpenRedirect(target_id=target_id, url=rec["url"], param=rec["param"],
                             payload=rec.get("payload", ""), location=rec.get("location", ""),
                             status_code=rec.get("status_code", 0)))
    session.commit()


def add_liveresult(session, target_id: int, rec: dict) -> int:
    row = {"target_id": target_id, "url": rec["url"], "status_code": rec["status_code"],
           "title": rec.get("title", ""), "content_type": rec.get("content_type", ""),
           "content_length": rec.get("content_length", 0), "via_proxy": rec.get("via_proxy", False)}
    stmt = sqlite_insert(LiveResult).values(**row).on_conflict_do_update(
        index_elements=["target_id", "url"],
        set_={"status_code": row["status_code"], "title": row["title"],
              "content_type": row["content_type"], "content_length": row["content_length"]})
    session.execute(stmt)
    session.commit()
    return 1


def add_fuzzresult(session, target_id: int, rec: dict) -> int:
    return _insert_ignore(session, FuzzResult, [{"target_id": target_id, **rec}],
                          ["target_id", "found_url"])


# ---------- job + log ----------
def reset_orphan_jobs(session) -> int:
    """On startup, any job still 'running'/'queued' has no live thread behind it
    (the process restarted). Mark them stopped and their targets idle so the UI
    doesn't show a phantom run forever."""
    from sqlalchemy import update
    orphans = session.execute(
        select(Job.id, Job.target_id).where(Job.status.in_(["running", "queued"]))).all()
    if not orphans:
        return 0
    tids = {t for (_, t) in orphans}
    session.execute(update(Job).where(Job.status.in_(["running", "queued"]))
                    .values(status="stopped", detail="reset on restart"))
    for tid in tids:
        t = session.get(Target, tid)
        if t and t.status in ("running", "queued"):
            t.status = "stopped"
    session.commit()
    return len(orphans)


def log(session, job_id: int, target_id: int, level: str, step: str, message: str):
    session.add(JobLog(job_id=job_id, target_id=target_id, level=level,
                       step=step, message=message[:2000]))
    session.commit()


def update_job(session, job_id: int, **kw):
    job = session.get(Job, job_id)
    if not job:
        return
    for k, v in kw.items():
        setattr(job, k, v)
    session.commit()


# ---------- queries for the API ----------
def counts(session, target_id: int) -> dict:
    def c(model, *crit):
        q = select(func.count()).select_from(model).where(model.target_id == target_id, *crit)
        return session.execute(q).scalar() or 0
    return {
        "subdomains": c(Subdomain),
        "urls": c(Url),
        "juicy_urls": c(Url, Url.is_juicy == True),  # noqa: E712
        "param_urls": c(Url, Url.has_params == True),  # noqa: E712
        "files": c(FileRecord),
        "jslinks": c(JsLink),
        "secrets": c(Secret),
        "params": c(Param),
        "reflections": c(Reflection),
        "openredirects": c(OpenRedirect),
        "live": c(LiveResult),
        "fuzz": c(FuzzResult),
    }
