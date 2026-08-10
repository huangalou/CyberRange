"""VulnOps × DetectOps reverse-lookup endpoint.

Wraps `cyberrange.vulnops.query()`. Phase 5.5 Web UI entry point — pass
the same union-semantics keywords (cve / advisory / package / campaign)
the CLI accepts; get back matched catalogs plus an aggregate summary.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from cyberrange.vulnops import (
    CatalogMatch,
    PackageQuery,
    QuerySummary,
    query as vulnops_query,
    summarize as vulnops_summarize,
)

router = APIRouter(prefix="/vulnops", tags=["vulnops"])


class VulnOpsMatch(BaseModel):
    """One catalog matched by the query."""

    path: str
    log_type: str
    vendor: str
    product: str
    version: str
    advisory_id: Optional[str] = None
    related_campaign: Optional[str] = None
    regression_critical: bool = False
    matched_by: list[str] = Field(default_factory=list)


class VulnOpsSummary(BaseModel):
    catalog_count: int
    p0_count: int
    by_advisory: dict[str, int] = Field(default_factory=dict)
    by_campaign: dict[str, int] = Field(default_factory=dict)
    by_vendor_product: dict[str, int] = Field(default_factory=dict)


class VulnOpsQueryResponse(BaseModel):
    summary: VulnOpsSummary
    matches: list[VulnOpsMatch]


def _to_response(
    matches: list[CatalogMatch], summary: QuerySummary,
) -> VulnOpsQueryResponse:
    return VulnOpsQueryResponse(
        summary=VulnOpsSummary(
            catalog_count=summary.catalog_count,
            p0_count=summary.p0_count,
            by_advisory=summary.by_advisory,
            by_campaign=summary.by_campaign,
            by_vendor_product=summary.by_vendor_product,
        ),
        matches=[
            VulnOpsMatch(
                path=m.path,
                log_type=m.log_type,
                vendor=m.vendor,
                product=m.product,
                version=m.version,
                advisory_id=m.advisory_id,
                related_campaign=m.related_campaign,
                regression_critical=m.regression_critical,
                matched_by=list(m.matched_by),
            )
            for m in matches
        ],
    )


@router.get("/query", response_model=VulnOpsQueryResponse)
def vulnops_query_route(
    cve: list[str] = Query(default_factory=list),
    advisory: list[str] = Query(default_factory=list),
    package: list[str] = Query(default_factory=list),
    campaign: list[str] = Query(default_factory=list),
) -> VulnOpsQueryResponse:
    """Reverse-lookup catalogs from VulnOps / CTI keywords.

    Union semantics: a catalog appears if it matches *any* keyword.
    ``matched_by`` on each match lists the keyword(s) that hit, so the
    UI can show *why* a catalog landed in the result set.

    Returns 400 when every keyword is empty — refusing to enumerate the
    full catalog with no filter is intentional (avoids accidentally
    shadowing real reverse-lookups as "all catalogs" queries).

    Returns 400 on malformed ``package`` query (must be
    ``ecosystem:name[:version]``).
    """
    if not (cve or advisory or package or campaign):
        raise HTTPException(
            status_code=400,
            detail=(
                "at least one of cve / advisory / package / campaign "
                "is required"
            ),
        )

    try:
        package_queries = [PackageQuery.parse(p) for p in package]
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    matches = vulnops_query(
        cve=cve or None,
        advisory_id=advisory or None,
        package=package_queries or None,
        campaign=campaign or None,
    )
    summary = vulnops_summarize(matches)
    return _to_response(matches, summary)
