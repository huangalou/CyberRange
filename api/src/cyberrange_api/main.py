"""FastAPI app entry."""
from __future__ import annotations

import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .auth import require_auth
from .routes import catalog, cti_metrics, jobs, preview, vulnops


def _allowed_origins() -> list[str]:
    raw = os.environ.get(
        "CYBERRANGE_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    )
    return [o.strip() for o in raw.split(",") if o.strip()]


app = FastAPI(
    title="CyberRange API",
    description=(
        "Catalog-driven log generator backend. Browses YAML specs, previews "
        "samples synchronously, and dispatches generation jobs to syslog/file sinks."
    ),
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/healthz", tags=["meta"])
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


_protected = [Depends(require_auth)]
app.include_router(catalog.router, dependencies=_protected)
app.include_router(preview.router, dependencies=_protected)
app.include_router(jobs.router, dependencies=_protected)
app.include_router(vulnops.router, dependencies=_protected)
app.include_router(cti_metrics.router, dependencies=_protected)


def run() -> None:
    """Console-script entry: `cyberrange-api` -> uvicorn dev server."""
    import uvicorn

    uvicorn.run(
        "cyberrange_api.main:app",
        host=os.environ.get("API_HOST", "127.0.0.1"),
        port=int(os.environ.get("API_PORT", "8001")),
        reload=False,
        log_level=os.environ.get("API_LOG_LEVEL", "info"),
    )
