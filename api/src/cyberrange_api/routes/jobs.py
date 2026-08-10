"""Background generation jobs: POST /generate, GET /jobs, GET /jobs/{id}."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException

from ..models import GenerateRequest, JobStatus, SpecID
from ..runner import start_job
from ..sink_policy import SinkNotAllowed, validate_sink
from ..store import store

router = APIRouter(tags=["jobs"])


@router.post("/generate", response_model=JobStatus, status_code=202)
def create_job(req: GenerateRequest) -> JobStatus:
    if req.count < 1:
        raise HTTPException(status_code=400, detail="count must be >= 1")

    try:
        validate_sink(req.sink)
    except SinkNotAllowed as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    job_id = str(uuid.uuid4())
    job = JobStatus(
        id=job_id,
        spec=SpecID(
            vendor=req.vendor,
            product=req.product,
            version=req.version,
            log_type=req.log_type,
        ),
        count=req.count,
        rate=req.rate,
        sink=req.sink,
        status="pending",
    )
    store.add(job)
    start_job(job_id, req)
    return job


@router.get("/jobs", response_model=list[JobStatus])
def list_jobs() -> list[JobStatus]:
    return store.list()


@router.get("/jobs/{job_id}", response_model=JobStatus)
def get_job(job_id: str) -> JobStatus:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return job
