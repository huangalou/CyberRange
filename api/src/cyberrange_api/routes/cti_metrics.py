"""Time-to-Catalog metrics endpoint.

Wraps `cyberrange.cti.metrics.collect_metrics()`. Note: when the API
container is built from a clean COPY (no `.git/`), git-based first-
commit timestamps cannot be computed and ``delta_days`` will be null
for every entry. The UI is expected to render this gracefully with a
"git history unavailable in this environment" note.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from cyberrange.cti.metrics import (
    CatalogMetric,
    MetricsSummary,
    collect_metrics,
    summarize,
)

router = APIRouter(prefix="/cti/metrics", tags=["cti-metrics"])


class MetricEntry(BaseModel):
    path: str
    advisory_id: Optional[str] = None
    related_campaign: Optional[str] = None
    ingested_at: Optional[str] = None
    first_commit_at: Optional[str] = None
    delta_days: Optional[int] = None
    regression_critical: bool = False


class MetricsSummaryModel(BaseModel):
    catalog_count: int
    measured_count: int
    median_delta_days: Optional[float] = None
    p90_delta_days: Optional[int] = None
    max_delta_days: Optional[int] = None
    same_day_count: int = 0
    by_campaign: dict[str, int] = Field(default_factory=dict)
    p0_count: int = 0


class MetricsResponse(BaseModel):
    summary: MetricsSummaryModel
    catalogs: list[MetricEntry]


def _to_response(
    metrics: list[CatalogMetric], summary: MetricsSummary,
) -> MetricsResponse:
    return MetricsResponse(
        summary=MetricsSummaryModel(
            catalog_count=summary.catalog_count,
            measured_count=summary.measured_count,
            median_delta_days=summary.median_delta_days,
            p90_delta_days=summary.p90_delta_days,
            max_delta_days=summary.max_delta_days,
            same_day_count=summary.same_day_count,
            by_campaign=summary.by_campaign,
            p0_count=summary.p0_count,
        ),
        catalogs=[
            MetricEntry(
                path=m.path,
                advisory_id=m.advisory_id,
                related_campaign=m.related_campaign,
                ingested_at=m.ingested_at,
                first_commit_at=m.first_commit_at,
                delta_days=m.delta_days,
                regression_critical=m.regression_critical,
            )
            for m in metrics
        ],
    )


@router.get("", response_model=MetricsResponse)
def get_metrics() -> MetricsResponse:
    """Return Time-to-Catalog metrics for every catalog with
    ``cti.ingested_at`` set. Sorted by (advisory_id, path)."""
    metrics = collect_metrics()
    summary = summarize(metrics)
    return _to_response(metrics, summary)
