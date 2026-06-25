"""In-process job manager: queues and runs target pipelines in threads."""
from __future__ import annotations

import threading
from typing import Optional

from . import store
from .config import SETTINGS
from .db import get_session, Job, Target
from .pipeline import PipelineRunner


class JobManager:
    def __init__(self):
        self.max = max(1, SETTINGS.max_concurrent_jobs)
        self._running: dict[int, threading.Event] = {}
        self._queue: list[tuple[int, int, dict]] = []
        self._lock = threading.Lock()

    # -- public API --------------------------------------------------------
    def submit(self, target_id: int, options: dict) -> int:
        s = get_session()
        excl = options.get("excluded_steps") or []
        import json
        job = Job(target_id=target_id, kind="pipeline", status="queued",
                  excluded_steps=json.dumps(excl))
        s.add(job)
        s.commit()
        job_id = job.id
        # persist excluded steps on target too
        t = s.get(Target, target_id)
        if t:
            t.excluded_steps = json.dumps(excl)
            t.status = "queued"
            s.commit()
        s.close()
        with self._lock:
            self._queue.append((job_id, target_id, options))
        self._dispatch()
        return job_id

    def stop(self, job_id: int) -> bool:
        with self._lock:
            ev = self._running.get(job_id)
            if ev:
                ev.set()
                return True
            # remove from queue if still queued
            self._queue = [q for q in self._queue if q[0] != job_id]
        s = get_session()
        job = s.get(Job, job_id)
        if job and job.status in ("queued", "running"):
            job.status = "stopped"
            s.commit()
        s.close()
        return True

    def stop_target(self, target_id: int) -> int:
        s = get_session()
        from sqlalchemy import select
        ids = [r[0] for r in s.execute(
            select(Job.id).where(Job.target_id == target_id,
                                 Job.status.in_(["queued", "running"]))).all()]
        s.close()
        for jid in ids:
            self.stop(jid)
        return len(ids)

    def running_jobs(self) -> list[int]:
        with self._lock:
            return list(self._running.keys())

    # -- internals ---------------------------------------------------------
    def _dispatch(self):
        with self._lock:
            while len(self._running) < self.max and self._queue:
                job_id, target_id, options = self._queue.pop(0)
                ev = threading.Event()
                self._running[job_id] = ev
                t = threading.Thread(target=self._run, args=(job_id, target_id, options, ev),
                                     daemon=True)
                t.start()

    def _run(self, job_id: int, target_id: int, options: dict, ev: threading.Event):
        try:
            PipelineRunner(target_id, job_id, options, ev).run()
        except Exception as e:
            s = get_session()
            job = s.get(Job, job_id)
            if job:
                job.status = "error"
                job.detail = str(e)[:500]
                s.commit()
            s.close()
        finally:
            with self._lock:
                self._running.pop(job_id, None)
            self._dispatch()


MANAGER: Optional[JobManager] = None


def get_manager() -> JobManager:
    global MANAGER
    if MANAGER is None:
        MANAGER = JobManager()
    return MANAGER
