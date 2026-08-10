"""In-memory job store. PoC; future: SQLite or Redis."""
from __future__ import annotations

import threading
from typing import Optional

from .models import JobStatus


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, JobStatus] = {}
        self._lock = threading.Lock()

    def add(self, job: JobStatus) -> None:
        with self._lock:
            self._jobs[job.id] = job

    def get(self, job_id: str) -> Optional[JobStatus]:
        with self._lock:
            return self._jobs.get(job_id)

    def update(self, job_id: str, **fields) -> None:
        with self._lock:
            j = self._jobs.get(job_id)
            if j is None:
                return
            for k, v in fields.items():
                setattr(j, k, v)

    def list(self) -> list[JobStatus]:
        with self._lock:
            return list(self._jobs.values())


store = JobStore()
