"""Synchronous preview endpoint - render N samples and return inline."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException

from cyberrange import find_spec, load_spec, render_many

from ..models import PreviewRequest, PreviewResponse

router = APIRouter(tags=["preview"])

PREVIEW_COUNT_MAX = 100


@router.post("/preview", response_model=PreviewResponse)
def preview(req: PreviewRequest) -> PreviewResponse:
    if req.count < 1 or req.count > PREVIEW_COUNT_MAX:
        raise HTTPException(
            status_code=400,
            detail=f"count must be 1..{PREVIEW_COUNT_MAX} for preview",
        )
    try:
        path = find_spec(req.vendor, req.product, req.version, req.log_type)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    spec = load_spec(path)

    # v4 — pass CEF overrides through. Engine ignores them when the catalog
    # has no cef_mapping / cef_header. exclude_none keeps "unset" fields out
    # so engine's "is None" gates work as expected.
    cef_header_kw = (
        req.cef_header_overrides.model_dump(exclude_none=True)
        if req.cef_header_overrides is not None
        else None
    )
    cef_ext_kw = {
        pa_field: ov.model_dump(exclude_none=True)
        for pa_field, ov in req.cef_extension_overrides.items()
    }

    samples = list(
        render_many(
            spec,
            req.count,
            req.params,
            cef_header_overrides=cef_header_kw,
            cef_extension_overrides=cef_ext_kw,
        )
    )
    return PreviewResponse(samples=samples)
