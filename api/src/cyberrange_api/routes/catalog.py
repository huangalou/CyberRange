"""Catalog browsing endpoints."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException

from cyberrange import find_spec, list_specs, load_spec

from ..models import (
    CatalogDetail,
    CatalogEntry,
    CefHeaderModel,
    CefMappingEntryModel,
    FieldDescriptor,
)

router = APIRouter(prefix="/catalog", tags=["catalog"])


@router.get("", response_model=list[CatalogEntry])
def list_catalog(
    vendor: Optional[str] = None,
    product: Optional[str] = None,
) -> list[CatalogEntry]:
    out: list[CatalogEntry] = []
    for _path, spec in list_specs():
        if vendor and spec.vendor != vendor:
            continue
        if product and spec.product != product:
            continue
        out.append(
            CatalogEntry(
                vendor=spec.vendor,
                product=spec.product,
                version=spec.version,
                log_type=spec.log_type,
                description=spec.description,
                format=spec.format,
                transport=spec.transport,
            )
        )
    return out


@router.get(
    "/{vendor}/{product}/{version}/{log_type:path}",
    response_model=CatalogDetail,
)
def get_catalog_detail(
    vendor: str, product: str, version: str, log_type: str
) -> CatalogDetail:
    try:
        spec_path = find_spec(vendor, product, version, log_type)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    spec = load_spec(spec_path)

    # v4 — expose CEF customizable mapping when the catalog declares it.
    # Older catalogs return null for both fields → frontend hides editor.
    cef_header = (
        CefHeaderModel(**spec.cef_header.model_dump())
        if spec.cef_header is not None
        else None
    )
    cef_mapping = (
        [CefMappingEntryModel(**e.model_dump()) for e in spec.cef_mapping]
        if spec.cef_mapping is not None
        else None
    )

    return CatalogDetail(
        vendor=spec.vendor,
        product=spec.product,
        version=spec.version,
        log_type=spec.log_type,
        description=spec.description,
        format=spec.format,
        transport=spec.transport,
        params={k: v.default for k, v in spec.params.items()},
        fields=[
            FieldDescriptor(
                name=f.name,
                type=f.type,
                extras=f.model_dump(exclude={"name", "type"}),
            )
            for f in spec.fields
        ],
        template=spec.template,
        cef_header=cef_header,
        cef_mapping=cef_mapping,
    )
