"""SQLAlchemy models + engine for g2recon (SQLite, WAL)."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    create_engine, String, Integer, Text, Boolean, DateTime, ForeignKey,
    UniqueConstraint, Index, event,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker, Session,
)

from .config import SETTINGS


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)   # root domain
    slug: Mapped[str] = mapped_column(String(255), unique=True)
    status: Mapped[str] = mapped_column(String(32), default="idle")
    scope_note: Mapped[str] = mapped_column(Text, default="")
    excluded_steps: Mapped[str] = mapped_column(Text, default="[]")  # json list
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("target_id", "host"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    host: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(64), default="")
    in_scope: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Url(Base):
    __tablename__ = "urls"
    __table_args__ = (UniqueConstraint("target_id", "url", "source", "archive_ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(255), index=True, default="")
    source: Mapped[str] = mapped_column(String(32), default="wayback")  # wayback/js/fuzz/live
    mime: Mapped[str] = mapped_column(String(128), default="")
    archive_ts: Mapped[str] = mapped_column(String(20), default="")
    is_juicy: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    has_params: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class FileRecord(Base):
    __tablename__ = "files"
    __table_args__ = (UniqueConstraint("target_id", "url", "variant", "archive_ts"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    parent_url: Mapped[str] = mapped_column(Text, default="")     # where it was discovered
    kind: Mapped[str] = mapped_column(String(32), default="other")  # js/json/config/map/...
    variant: Mapped[str] = mapped_column(String(16), default="live")  # live/archived
    archive_ts: Mapped[str] = mapped_column(String(20), default="")
    path: Mapped[str] = mapped_column(Text, default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64), default="", index=True)
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    content_type: Mapped[str] = mapped_column(String(128), default="")
    analyzed: Mapped[bool] = mapped_column(Boolean, default=False)
    depth: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class JsLink(Base):
    __tablename__ = "jslinks"
    __table_args__ = (UniqueConstraint("target_id", "link", "source_file"),
                      Index("ix_jslinks_target_kind", "target_id", "kind"))
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    link: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(32), default="path")  # path/url/endpoint/subdomain
    source_file: Mapped[str] = mapped_column(Text, default="")     # parent file url
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Secret(Base):
    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("target_id", "rule", "match", "source_file"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    rule: Mapped[str] = mapped_column(String(96))
    match: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    context: Mapped[str] = mapped_column(Text, default="")
    source_file: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Param(Base):
    __tablename__ = "params"
    __table_args__ = (UniqueConstraint("target_id", "name"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    source: Mapped[str] = mapped_column(String(32), default="archive")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Reflection(Base):
    __tablename__ = "reflections"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    param: Mapped[str] = mapped_column(String(255))
    payload: Mapped[str] = mapped_column(String(64), default="")
    reflected: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    contexts: Mapped[str] = mapped_column(Text, default="")  # html/attr/js/...
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class OpenRedirect(Base):
    __tablename__ = "openredirects"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    param: Mapped[str] = mapped_column(String(255))
    payload: Mapped[str] = mapped_column(Text, default="")
    location: Mapped[str] = mapped_column(Text, default="")
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class LiveResult(Base):
    __tablename__ = "liveresults"
    __table_args__ = (UniqueConstraint("target_id", "url"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer, default=0, index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    content_type: Mapped[str] = mapped_column(String(128), default="")
    content_length: Mapped[int] = mapped_column(Integer, default=0)
    via_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class FuzzResult(Base):
    __tablename__ = "fuzzresults"
    __table_args__ = (UniqueConstraint("target_id", "found_url"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    base_url: Mapped[str] = mapped_column(Text)
    found_url: Mapped[str] = mapped_column(Text)
    status_code: Mapped[int] = mapped_column(Integer, default=0, index=True)
    content_type: Mapped[str] = mapped_column(String(128), default="")
    length: Mapped[int] = mapped_column(Integer, default=0)
    via_proxy: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Job(Base):
    __tablename__ = "jobs"
    id: Mapped[int] = mapped_column(primary_key=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    kind: Mapped[str] = mapped_column(String(32), default="pipeline")
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued/running/done/error/stopped
    current_step: Mapped[str] = mapped_column(String(64), default="")
    progress: Mapped[int] = mapped_column(Integer, default=0)     # 0-100
    detail: Mapped[str] = mapped_column(Text, default="")
    excluded_steps: Mapped[str] = mapped_column(Text, default="[]")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow, onupdate=_utcnow)


class JobLog(Base):
    __tablename__ = "joblogs"
    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), index=True)
    target_id: Mapped[int] = mapped_column(ForeignKey("targets.id"), index=True)
    level: Mapped[str] = mapped_column(String(8), default="info")
    step: Mapped[str] = mapped_column(String(64), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=_utcnow)


class Setting(Base):
    """Runtime key/value store (e.g. resume cursors). NOT for secrets in repo."""
    __tablename__ = "settings_kv"
    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


_engine = None
_SessionLocal: Optional[sessionmaker] = None


def init_db():
    global _engine, _SessionLocal
    if _engine is not None:
        return
    data_dir = Path(SETTINGS.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "g2recon.db"
    _engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 30},
        future=True,
    )

    @event.listens_for(_engine, "connect")
    def _set_pragma(dbapi_conn, _):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False, class_=Session)


def get_session() -> Session:
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    return _SessionLocal()
