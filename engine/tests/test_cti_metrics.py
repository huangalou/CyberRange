"""Tests for `cyberrange.cti.metrics` — Time-to-Catalog computation.

All tests are offline: git_time provider is injected as a stub mapping
from path → datetime, so no `git log` shell-out happens. Tests construct
synthetic CatalogSpec objects to exercise edge cases (missing
ingested_at, missing commit time, negative-delta defence).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from cyberrange.cti.metrics import (
    CatalogMetric,
    collect_metrics,
    compute_metric,
    format_table,
    git_first_commit_time,
    summarize,
    to_json,
)
from cyberrange.schema import (
    CatalogSpec,
    CtiSpec,
    IocBundle,
    VulnOpsSpec,
)


# ──────────────── helpers ────────────────


def _make_spec(
    *,
    ingested_at: str | None = "2026-05-07",
    advisory_id: str | None = "PYSEC-2026-2",
    related_campaign: str | None = "teampcp",
    regression_critical: bool = True,
    template: str = "x",
) -> CatalogSpec:
    return CatalogSpec.model_validate({
        "vendor": "linux",
        "product": "auditd",
        "version": "3.x",
        "log_type": "auditd.test",
        "format": "auditd_raw",
        "template": template,
        "cti": CtiSpec(
            advisory_id=advisory_id,
            ingested_at=ingested_at,
            related_campaign=related_campaign,
            iocs=IocBundle(),
        ).model_dump(exclude_none=True) if ingested_at is not None else None,
        "vulnops": VulnOpsSpec(
            regression_critical=regression_critical
        ).model_dump(),
    })


def _fixed_time_provider(
    mapping: dict[str, datetime],
):
    """Return a GitTimeProvider that looks up Path.name → datetime."""
    def _provider(path: Path):
        return mapping.get(path.name)
    return _provider


# ──────────────── compute_metric edge cases ────────────────


@pytest.mark.unit
class TestComputeMetric:
    def test_no_cti_block_returns_none(self, tmp_path: Path):
        spec = _make_spec(ingested_at=None)
        assert spec.cti is None  # sanity
        metric = compute_metric(
            tmp_path / "x.yaml", spec, git_time=lambda p: None,
        )
        assert metric is None

    def test_no_git_commit_returns_metric_with_null_delta(
        self, tmp_path: Path,
    ):
        spec = _make_spec(ingested_at="2026-05-07")
        path = tmp_path / "a.yaml"
        metric = compute_metric(
            path, spec, git_time=lambda p: None,
            catalog_root=tmp_path,
        )
        assert metric is not None
        assert metric.delta_days is None
        assert metric.first_commit_at is None
        assert metric.ingested_at == "2026-05-07"

    def test_delta_zero_for_same_day(self, tmp_path: Path):
        spec = _make_spec(ingested_at="2026-05-12")
        path = tmp_path / "a.yaml"
        commit_dt = datetime.fromisoformat("2026-05-12T15:00:00+08:00")
        metric = compute_metric(
            path, spec, git_time=lambda p: commit_dt,
            catalog_root=tmp_path,
        )
        assert metric is not None
        assert metric.delta_days == 0

    def test_delta_positive_for_later_commit(self, tmp_path: Path):
        spec = _make_spec(ingested_at="2026-05-07")
        path = tmp_path / "a.yaml"
        commit_dt = datetime.fromisoformat("2026-05-09T10:00:00+08:00")
        metric = compute_metric(
            path, spec, git_time=lambda p: commit_dt,
            catalog_root=tmp_path,
        )
        assert metric is not None
        assert metric.delta_days == 2

    def test_tz_preserved_does_not_flip_day(self, tmp_path: Path):
        """Regression: previously commits in +0800 were UTC-normalized,
        making same-day Taipei commits show up as previous-day UTC and
        producing negative deltas. Now we keep the committer's tz."""
        spec = _make_spec(ingested_at="2026-05-12")
        path = tmp_path / "a.yaml"
        # 02:00 Asia/Taipei == 18:00 previous-day UTC. Pre-fix this
        # would compute delta = -1 days.
        commit_dt = datetime.fromisoformat("2026-05-12T02:00:00+08:00")
        metric = compute_metric(
            path, spec, git_time=lambda p: commit_dt,
            catalog_root=tmp_path,
        )
        assert metric is not None
        assert metric.delta_days == 0
        assert metric.first_commit_at == "2026-05-12"

    def test_relative_path_returned(self, tmp_path: Path):
        spec = _make_spec()
        nested = tmp_path / "linux" / "auditd" / "3.x" / "x.yaml"
        nested.parent.mkdir(parents=True)
        nested.write_text("placeholder")
        metric = compute_metric(
            nested, spec, git_time=lambda p: None,
            catalog_root=tmp_path,
        )
        assert metric is not None
        assert metric.path == "linux/auditd/3.x/x.yaml"

    def test_invalid_ingested_at_yields_null_delta(self, tmp_path: Path):
        spec = _make_spec(ingested_at="not-a-date")
        commit_dt = datetime.fromisoformat("2026-05-09T10:00:00+08:00")
        metric = compute_metric(
            tmp_path / "x.yaml", spec, git_time=lambda p: commit_dt,
            catalog_root=tmp_path,
        )
        # The metric still exists (advisory had ingested_at set), but
        # delta cannot be computed.
        assert metric is not None
        assert metric.delta_days is None


# ──────────────── collect_metrics over multiple specs ────────────────


@pytest.mark.unit
class TestCollect:
    @pytest.fixture
    def specs_with_paths(self, tmp_path: Path):
        specs = [
            (tmp_path / "a.yaml", _make_spec(ingested_at="2026-05-07")),
            (tmp_path / "b.yaml", _make_spec(ingested_at="2026-05-12")),
            (tmp_path / "c.yaml", _make_spec(ingested_at=None)),
        ]
        return specs

    def test_skips_specs_without_ingested_at(self, tmp_path, specs_with_paths):
        provider = _fixed_time_provider({
            "a.yaml": datetime.fromisoformat("2026-05-09T10:00:00+08:00"),
            "b.yaml": datetime.fromisoformat("2026-05-12T11:00:00+08:00"),
        })
        metrics = collect_metrics(
            catalog_root=tmp_path,
            git_time=provider,
            specs=specs_with_paths,
        )
        assert len(metrics) == 2
        assert {m.path for m in metrics} == {"a.yaml", "b.yaml"}

    def test_sorted_by_advisory_then_path(self, tmp_path):
        s1 = _make_spec(ingested_at="2026-05-07", advisory_id="PYSEC-2026-2")
        s2 = _make_spec(ingested_at="2026-05-12", advisory_id="GHSA-2026-1")
        s3 = _make_spec(ingested_at="2026-05-08", advisory_id="PYSEC-2026-2")
        specs = [
            (tmp_path / "zzz.yaml", s1),
            (tmp_path / "aaa.yaml", s2),
            (tmp_path / "mmm.yaml", s3),
        ]
        metrics = collect_metrics(
            catalog_root=tmp_path,
            git_time=lambda p: None,
            specs=specs,
        )
        ids = [(m.advisory_id, m.path) for m in metrics]
        assert ids == [
            ("GHSA-2026-1", "aaa.yaml"),
            ("PYSEC-2026-2", "mmm.yaml"),
            ("PYSEC-2026-2", "zzz.yaml"),
        ]


# ──────────────── summarize ────────────────


@pytest.mark.unit
class TestSummarize:
    def _metric(
        self,
        path: str = "a.yaml",
        advisory: str = "PYSEC-2026-2",
        campaign: str = "teampcp",
        delta: int | None = 0,
        critical: bool = True,
        ingested: str = "2026-05-12",
        commit: str = "2026-05-12",
    ) -> CatalogMetric:
        return CatalogMetric(
            path=path,
            advisory_id=advisory,
            related_campaign=campaign,
            ingested_at=ingested,
            first_commit_at=commit,
            delta_days=delta,
            regression_critical=critical,
        )

    def test_empty_summary(self):
        s = summarize([])
        assert s.catalog_count == 0
        assert s.measured_count == 0
        assert s.median_delta_days is None
        assert s.same_day_count == 0
        assert s.by_campaign == {}

    def test_typical_summary(self):
        metrics = [
            self._metric("a", delta=0),
            self._metric("b", delta=0),
            self._metric("c", delta=2),
            self._metric("d", delta=2),
            self._metric("e", delta=2),
            self._metric("f", delta=2),
        ]
        s = summarize(metrics)
        assert s.catalog_count == 6
        assert s.measured_count == 6
        assert s.same_day_count == 2
        assert s.median_delta_days == 2.0
        assert s.max_delta_days == 2
        assert s.by_campaign == {"teampcp": 6}
        assert s.p0_count == 6

    def test_unmeasured_excluded_from_delta_stats(self):
        metrics = [
            self._metric("a", delta=0),
            self._metric("b", delta=None, commit=""),  # uncommitted
            self._metric("c", delta=4),
        ]
        s = summarize(metrics)
        assert s.catalog_count == 3
        assert s.measured_count == 2
        # delta values [0, 4] → median = 2.0
        assert s.median_delta_days == 2.0


# ──────────────── formatting ────────────────


@pytest.mark.unit
class TestFormatting:
    def test_table_empty(self):
        out = format_table([])
        assert "(no catalogs" in out

    def test_table_includes_p0_marker(self):
        m = CatalogMetric(
            path="a.yaml", advisory_id="PYSEC-X",
            related_campaign="x", ingested_at="2026-05-12",
            first_commit_at="2026-05-12", delta_days=0,
            regression_critical=True,
        )
        out = format_table([m])
        assert "P0" in out
        assert " 0d" in out

    def test_json_round_trip(self):
        import json as _json
        m = CatalogMetric(
            path="a.yaml", advisory_id="PYSEC-X",
            related_campaign="x", ingested_at="2026-05-12",
            first_commit_at="2026-05-12", delta_days=0,
            regression_critical=True,
        )
        out = to_json([m], summarize([m]))
        data = _json.loads(out)
        assert "summary" in data
        assert "catalogs" in data
        assert data["summary"]["same_day_count"] == 1
        assert data["catalogs"][0]["path"] == "a.yaml"


# ──────────────── default git provider (graceful failure) ────────────────


@pytest.mark.unit
class TestDefaultGitProvider:
    def test_uncommitted_path_returns_none(self, tmp_path: Path):
        """A fresh file with no git history must return None, not raise."""
        f = tmp_path / "never-committed.yaml"
        f.write_text("placeholder")
        # In test sandbox tmp_path is unlikely to be a git repo; even if
        # it is, the file isn't tracked → git log emits nothing.
        assert git_first_commit_time(f) is None
