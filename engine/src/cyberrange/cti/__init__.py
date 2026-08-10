"""CTI feed integration — Mythos-ready R10 (Threat Detection Lagging
Intelligence) work line.

Public API:

- `extract_iocs(text)`: regex-based IOC extraction from advisory markdown,
  returns a v3 `IocBundle`.
- `feeds`: vendor-advisory RSS fetchers (Datadog Security Labs, Aqua,
  GitHub Security) + JSON-backed dedup state store.
- `draft_catalog(advisory_md, ingested_at, ...)`: LLM-assisted catalog
  YAML drafter — heuristic surface inference + stub template + axis-
  ownership filtering, with optional `LlmClient` for description /
  template refinement. Offline-first (NoOpLlmClient default).
- `metrics`: Time-to-Catalog computation (R10 Mythos-ready metric) —
  advisory.ingested_at → catalog file first git commit delta.

Future modules:

- `cti.digest`: daily IOC digest aggregator for companion SOC stack sync
"""
from __future__ import annotations

from . import feeds, metrics
from .catalog_writer import (
    CatalogDraft,
    DetectionSurface,
    LlmClient,
    NoOpLlmClient,
    draft_catalog,
    infer_campaign_id,
    infer_surface,
)
from .ioc_extractor import ExtractionResult, IocExtractor, extract_iocs
from .metrics import (
    CatalogMetric,
    MetricsSummary,
    collect_metrics,
    summarize,
)

__all__ = [
    "CatalogDraft",
    "CatalogMetric",
    "DetectionSurface",
    "ExtractionResult",
    "IocExtractor",
    "LlmClient",
    "MetricsSummary",
    "NoOpLlmClient",
    "collect_metrics",
    "draft_catalog",
    "extract_iocs",
    "feeds",
    "infer_campaign_id",
    "infer_surface",
    "metrics",
    "summarize",
]
