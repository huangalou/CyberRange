"""Background thread runner for generation jobs."""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from cyberrange import find_spec, load_spec, render_many
from cyberrange.sinks import open_sink

from .models import GenerateRequest
from .store import store


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run(job_id: str, req: GenerateRequest) -> None:
    try:
        store.update(job_id, status="running", started_at=_utcnow_iso())
        spec_path = find_spec(req.vendor, req.product, req.version, req.log_type)
        spec = load_spec(spec_path)
        interval = (1.0 / req.rate) if req.rate > 0 else 0.0
        sent = 0

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

        with open_sink(req.sink) as sink:
            for line in render_many(
                spec,
                req.count,
                req.params,
                cef_header_overrides=cef_header_kw,
                cef_extension_overrides=cef_ext_kw,
            ):
                sink.write(line)
                sent += 1
                if sent % 100 == 0:
                    store.update(job_id, sent=sent)
                if interval:
                    time.sleep(interval)
        store.update(
            job_id, sent=sent, status="completed", completed_at=_utcnow_iso()
        )
    except Exception as exc:  # noqa: BLE001
        store.update(
            job_id,
            status="failed",
            completed_at=_utcnow_iso(),
            error=f"{type(exc).__name__}: {exc}",
        )


def start_job(job_id: str, req: GenerateRequest) -> None:
    t = threading.Thread(target=_run, args=(job_id, req), daemon=True)
    t.start()
