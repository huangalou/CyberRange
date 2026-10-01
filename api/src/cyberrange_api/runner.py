"""Background thread runner for generation jobs."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_one
from cyberrange.sinks import open_sink
from cyberrange.timing import Schedule, burst, emit, uniform

from .models import GenerateRequest
from .store import store

PROGRESS_EVERY = 100


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _schedule(req: GenerateRequest) -> Schedule:
    if req.burst is not None:
        b = req.burst
        return burst(b.size, b.window_s, repeat=b.repeat, gap=b.gap_s)
    return uniform(req.count, req.rate)


def _run(job_id: str, req: GenerateRequest) -> None:
    sent = 0

    def _progress(n: int) -> None:
        nonlocal sent
        sent = n
        if n % PROGRESS_EVERY == 0:
            store.update(job_id, sent=n)

    try:
        store.update(job_id, status="running", started_at=_utcnow_iso())
        spec_path = find_spec(req.vendor, req.product, req.version, req.log_type)
        spec = load_spec(spec_path)

        # v4 — flatten override Pydantic models to engine kwargs.
        cef_header_kw = (
            req.cef_header_overrides.model_dump(exclude_none=True)
            if req.cef_header_overrides is not None
            else None
        )
        cef_ext_kw = {
            pa_field: ov.model_dump(exclude_none=True)
            for pa_field, ov in req.cef_extension_overrides.items()
        }

        def _render(at: datetime) -> str:
            return render_one(
                spec,
                req.params,
                cef_header_overrides=cef_header_kw,
                cef_extension_overrides=cef_ext_kw,
                at=at,
            )

        with open_sink(req.sink) as sink:
            emit(_schedule(req), _render, sink, on_sent=_progress)
        store.update(
            job_id, sent=sent, status="completed", completed_at=_utcnow_iso()
        )
    except Exception as exc:  # noqa: BLE001
        store.update(
            job_id,
            sent=sent,
            status="failed",
            completed_at=_utcnow_iso(),
            error=f"{type(exc).__name__}: {exc}",
        )


def start_job(job_id: str, req: GenerateRequest) -> None:
    t = threading.Thread(target=_run, args=(job_id, req), daemon=True)
    t.start()
