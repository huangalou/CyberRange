"""Contract tests for /cti/metrics endpoint."""
from __future__ import annotations

from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)


def test_metrics_returns_summary_and_catalogs():
    r = client.get("/cti/metrics")
    assert r.status_code == 200
    body = r.json()
    assert "summary" in body
    assert "catalogs" in body


def test_summary_shape():
    r = client.get("/cti/metrics")
    body = r.json()
    s = body["summary"]
    for key in (
        "catalog_count", "measured_count",
        "median_delta_days", "p90_delta_days", "max_delta_days",
        "same_day_count", "by_campaign", "p0_count",
    ):
        assert key in s


def test_catalogs_only_include_those_with_ingested_at():
    """Every entry must have ingested_at set — that's the precondition
    for computing Time-to-Catalog. Catalogs without it are skipped."""
    r = client.get("/cti/metrics")
    body = r.json()
    for entry in body["catalogs"]:
        assert entry["ingested_at"], (
            f"{entry['path']} has no ingested_at — should not appear"
        )


def test_teampcp_catalogs_appear():
    """The 6 TeamPCP backfill catalogs all have cti.ingested_at set."""
    r = client.get("/cti/metrics")
    body = r.json()
    paths = [e["path"] for e in body["catalogs"]]
    assert any("teampcp" in p.lower() for p in paths)
    assert body["summary"]["catalog_count"] >= 6


def test_p0_count_matches_regression_critical_entries():
    r = client.get("/cti/metrics")
    body = r.json()
    p0_entries = [e for e in body["catalogs"] if e["regression_critical"]]
    assert body["summary"]["p0_count"] == len(p0_entries)


def test_entry_shape():
    r = client.get("/cti/metrics")
    body = r.json()
    if body["catalogs"]:
        for key in (
            "path", "advisory_id", "related_campaign",
            "ingested_at", "first_commit_at", "delta_days",
            "regression_critical",
        ):
            assert key in body["catalogs"][0]
