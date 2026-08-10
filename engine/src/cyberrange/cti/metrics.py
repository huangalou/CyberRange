"""Time-to-Catalog metrics for Mythos-ready R10 alignment.

R10 "Threat Detection Dependent on Lagging Intelligence" measures how
fast a SOC can convert a fresh advisory into a verified detection asset.
CyberRange's slice of that is **Time-to-Catalog**:

    advisory `cti.ingested_at`  →  catalog YAML's first git commit

A small/zero delta means the org reacted within the operational window
that matters (hours/days, not weeks). This module computes the delta
per catalog, and the CLI `cyberrange cti metrics` summarizes the fleet.

The git-time read is **injectable** so tests can stay offline and CI
runs are deterministic. Production CLI uses the default `git log`
provider; tests pass a stub mapping.
"""
from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Iterable, Optional

from ..loader import CATALOG_ROOT, list_specs
from ..schema import CatalogSpec


# ──────────────── git-time provider ────────────────


GitTimeProvider = Callable[[Path], Optional[datetime]]
"""Callable: catalog YAML path → first-commit datetime (UTC) or None
if the file is uncommitted / git unavailable."""


def git_first_commit_time(path: Path) -> Optional[datetime]:
    """Default provider: shell out to `git log --diff-filter=A --follow`.

    Returns the file's earliest add-commit time **in its committer-local
    timezone** (matches how `git log` displays dates). Time-to-Catalog
    intentionally measures advisory-day → commit-day in author local
    time — UTC-normalizing here would silently shift commits across the
    date boundary for committers near UTC±12, producing negative deltas
    for same-day work. Returns None on any failure (uncommitted file,
    no git, etc.) — metrics degrade gracefully on a fresh clone."""
    try:
        # --follow handles renames; --diff-filter=A picks add events;
        # %aI is author date in ISO-8601 with the committer's timezone.
        result = subprocess.run(
            [
                "git", "log", "--diff-filter=A", "--follow",
                "--format=%aI", "--", str(path),
            ],
            cwd=path.parent if path.is_absolute() else None,
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None

    lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    if not lines:
        return None

    # `git log` prints newest-first; --follow + --diff-filter=A may yield
    # multiple A events across renames. The earliest one is the bottom.
    raw = lines[-1]
    try:
        # Preserve the committer's tz so the .date() below matches what
        # the committer saw on their clock.
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


# ──────────────── data model ────────────────


@dataclass(frozen=True)
class CatalogMetric:
    """One catalog's Time-to-Catalog measurement."""

    path: str                              # path relative to catalog root
    advisory_id: Optional[str]
    related_campaign: Optional[str]
    ingested_at: Optional[str]             # ISO date as it appears in YAML
    first_commit_at: Optional[str]         # ISO date in UTC
    delta_days: Optional[int]              # None if any side missing
    regression_critical: bool

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# ──────────────── compute ────────────────


def _parse_ingested(value: str) -> Optional[date]:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def compute_metric(
    catalog_path: Path,
    spec: CatalogSpec,
    *,
    git_time: GitTimeProvider,
    catalog_root: Path = CATALOG_ROOT,
) -> Optional[CatalogMetric]:
    """Compute Time-to-Catalog for one catalog. Returns None when the
    catalog has no `cti.ingested_at` (nothing to measure)."""
    if spec.cti is None or not spec.cti.ingested_at:
        return None

    ingested = _parse_ingested(spec.cti.ingested_at)
    commit_dt = git_time(catalog_path)
    delta_days: Optional[int] = None
    if ingested is not None and commit_dt is not None:
        delta_days = (commit_dt.date() - ingested).days

    try:
        rel = catalog_path.relative_to(catalog_root).as_posix()
    except ValueError:
        rel = catalog_path.as_posix()

    return CatalogMetric(
        path=rel,
        advisory_id=spec.cti.advisory_id,
        related_campaign=spec.cti.related_campaign,
        ingested_at=spec.cti.ingested_at,
        first_commit_at=(
            commit_dt.date().isoformat() if commit_dt else None
        ),
        delta_days=delta_days,
        regression_critical=(
            bool(spec.vulnops and spec.vulnops.regression_critical)
        ),
    )


def collect_metrics(
    *,
    catalog_root: Path = CATALOG_ROOT,
    git_time: GitTimeProvider = git_first_commit_time,
    specs: Optional[Iterable[tuple[Path, CatalogSpec]]] = None,
) -> list[CatalogMetric]:
    """Compute Time-to-Catalog for every catalog under ``catalog_root``
    that has ``cti.ingested_at`` set. Sorted by (advisory_id, path) for
    stable output."""
    if specs is None:
        specs = list_specs(catalog_root)

    out: list[CatalogMetric] = []
    for path, spec in specs:
        m = compute_metric(
            path, spec, git_time=git_time, catalog_root=catalog_root,
        )
        if m is not None:
            out.append(m)

    return sorted(
        out,
        key=lambda m: (m.advisory_id or "", m.path),
    )


# ──────────────── summary stats ────────────────


@dataclass(frozen=True)
class MetricsSummary:
    """Fleet-level Time-to-Catalog statistics."""

    catalog_count: int                     # catalogs with ingested_at
    measured_count: int                    # also have a git commit time
    median_delta_days: Optional[float]
    p90_delta_days: Optional[int]
    max_delta_days: Optional[int]
    same_day_count: int                    # delta == 0 days
    by_campaign: dict[str, int]            # campaign id → catalog count
    p0_count: int                          # regression_critical catalogs

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def summarize(metrics: list[CatalogMetric]) -> MetricsSummary:
    deltas = sorted(
        m.delta_days for m in metrics if m.delta_days is not None
    )
    by_campaign: dict[str, int] = {}
    p0 = 0
    same_day = 0
    for m in metrics:
        if m.related_campaign:
            by_campaign[m.related_campaign] = (
                by_campaign.get(m.related_campaign, 0) + 1
            )
        if m.regression_critical:
            p0 += 1
        if m.delta_days == 0:
            same_day += 1

    median: Optional[float] = None
    p90: Optional[int] = None
    max_d: Optional[int] = None
    if deltas:
        mid = len(deltas) // 2
        median = (
            float(deltas[mid])
            if len(deltas) % 2
            else (deltas[mid - 1] + deltas[mid]) / 2.0
        )
        p90_idx = max(0, min(len(deltas) - 1, int(0.9 * len(deltas)) - 1))
        # 90th percentile via nearest-rank above the partition
        # (small n keeps the choice unambiguous)
        p90 = deltas[p90_idx] if len(deltas) >= 2 else deltas[-1]
        max_d = deltas[-1]

    return MetricsSummary(
        catalog_count=len(metrics),
        measured_count=len(deltas),
        median_delta_days=median,
        p90_delta_days=p90,
        max_delta_days=max_d,
        same_day_count=same_day,
        by_campaign=by_campaign,
        p0_count=p0,
    )


# ──────────────── formatting helpers ────────────────


def format_table(metrics: list[CatalogMetric]) -> str:
    """Pretty-print metrics as a fixed-width table.

    Columns: advisory_id | days | ingested → commit | P0 | path
    """
    if not metrics:
        return "(no catalogs with cti.ingested_at set)\n"

    rows: list[tuple[str, ...]] = [
        (
            m.advisory_id or "-",
            (
                f"{m.delta_days:>2}d"
                if m.delta_days is not None
                else "  ?"
            ),
            (
                f"{m.ingested_at or '?'} → "
                f"{m.first_commit_at or '?'}"
            ),
            "P0" if m.regression_critical else "  ",
            m.path,
        )
        for m in metrics
    ]
    headers = ("advisory", "delta", "ingested → commit", "pri", "catalog")

    widths = [
        max(len(h), *(len(r[i]) for r in rows))
        for i, h in enumerate(headers)
    ]

    def fmt(parts: tuple[str, ...]) -> str:
        return "  ".join(p.ljust(widths[i]) for i, p in enumerate(parts))

    out_lines = [fmt(headers), fmt(tuple("-" * w for w in widths))]
    out_lines.extend(fmt(r) for r in rows)
    return "\n".join(out_lines) + "\n"


def to_json(
    metrics: list[CatalogMetric], summary: MetricsSummary,
) -> str:
    """Stable JSON payload for downstream tools (Grafana / dashboards)."""
    return json.dumps(
        {
            "summary": summary.to_dict(),
            "catalogs": [m.to_dict() for m in metrics],
        },
        indent=2,
        sort_keys=True,
    )
