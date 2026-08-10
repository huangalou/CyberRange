"""Contract tests for /vulnops endpoint."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cyberrange_api.main import app

client = TestClient(app)


def test_query_requires_at_least_one_keyword():
    r = client.get("/vulnops/query")
    assert r.status_code == 400
    assert "required" in r.json()["detail"].lower()


def test_query_by_package_returns_teampcp_catalogs():
    """Production catalog has 6 TeamPCP entries with vulnops.affects[]
    referencing pypi:litellm. The endpoint must find them all."""
    r = client.get(
        "/vulnops/query", params={"package": "pypi:litellm"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["summary"]["catalog_count"] >= 6
    assert body["summary"]["p0_count"] >= 6
    assert "teampcp" in body["summary"]["by_campaign"]


def test_query_by_advisory_id():
    r = client.get(
        "/vulnops/query", params={"advisory": "PYSEC-2026-2"}
    )
    assert r.status_code == 200
    body = r.json()
    # All 6 TeamPCP catalogs share this advisory id
    assert body["summary"]["catalog_count"] >= 6
    for match in body["matches"]:
        assert match["advisory_id"] == "PYSEC-2026-2"


def test_query_by_campaign():
    r = client.get(
        "/vulnops/query", params={"campaign": "teampcp"}
    )
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["catalog_count"] >= 6
    for match in body["matches"]:
        assert match["related_campaign"] == "teampcp"


def test_query_package_version_in_affects():
    r = client.get(
        "/vulnops/query",
        params={"package": "pypi:litellm:1.82.8"},
    )
    assert r.status_code == 200
    assert r.json()["summary"]["catalog_count"] >= 6


def test_query_package_version_not_in_affects():
    """Version 1.82.6 is not in any catalog's affects list."""
    r = client.get(
        "/vulnops/query",
        params={"package": "pypi:litellm:1.82.6"},
    )
    assert r.status_code == 200
    assert r.json()["summary"]["catalog_count"] == 0


def test_query_invalid_package_spec_400():
    r = client.get(
        "/vulnops/query", params={"package": "no-colon-here"}
    )
    assert r.status_code == 400
    assert "ecosystem:name" in r.json()["detail"]


def test_query_repeatable_keywords():
    """Each repeatable param uses 'package' twice → union of both."""
    r = client.get(
        "/vulnops/query",
        params=[
            ("package", "pypi:litellm"),
            ("package", "pypi:telnyx"),
        ],
    )
    assert r.status_code == 200
    body = r.json()
    # Both packages live in same 6 catalogs → 6 results, matched_by
    # accumulates both tokens.
    assert body["summary"]["catalog_count"] >= 6
    for match in body["matches"]:
        # at least one of the two package tokens present
        tokens = match["matched_by"]
        assert any("package:pypi:" in t for t in tokens)


def test_query_union_across_keyword_types():
    r = client.get(
        "/vulnops/query",
        params=[
            ("advisory", "PYSEC-2026-2"),
            ("campaign", "teampcp"),
            ("package", "pypi:litellm"),
        ],
    )
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["catalog_count"] >= 6
    for match in body["matches"]:
        tokens = match["matched_by"]
        # All 6 TeamPCP catalogs match all 3 keywords
        assert "advisory:PYSEC-2026-2" in tokens
        assert "campaign:teampcp" in tokens
        assert "package:pypi:litellm" in tokens


def test_query_response_shape_matches_schema():
    r = client.get("/vulnops/query", params={"campaign": "teampcp"})
    assert r.status_code == 200
    body = r.json()
    # summary keys
    for key in (
        "catalog_count", "p0_count", "by_advisory",
        "by_campaign", "by_vendor_product",
    ):
        assert key in body["summary"]
    # match keys
    if body["matches"]:
        for key in (
            "path", "log_type", "vendor", "product", "version",
            "advisory_id", "related_campaign",
            "regression_critical", "matched_by",
        ):
            assert key in body["matches"][0]
