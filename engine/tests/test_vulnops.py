"""Tests for `cyberrange.vulnops` — reverse-lookup catalog queries.

All offline:specs are passed in directly via the `specs=...` kwarg, no
catalog directory I/O. Covers PackageQuery parsing, version_range
matching, single-keyword queries, multi-keyword union semantics, and
empty-query refusal.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cyberrange.schema import (
    AffectsSpec,
    CatalogSpec,
    CtiSpec,
    IocBundle,
    VulnOpsSpec,
)
from cyberrange.vulnops import (
    CatalogMatch,
    PackageQuery,
    _version_matches,
    format_table,
    query,
    summarize,
    to_json,
)


# ──────────────── builder ────────────────


def _spec(
    *,
    log_type: str = "test.logs",
    advisory_id: str | None = "PYSEC-2026-2",
    related_campaign: str | None = "teampcp",
    cve_refs_vulnops: list[str] | None = None,
    cve_refs_cti: list[str] | None = None,
    affects: list[tuple[str, str, str]] | None = None,
    regression_critical: bool = True,
) -> CatalogSpec:
    cti_dump = None
    if advisory_id or related_campaign or cve_refs_cti:
        cti_dump = CtiSpec(
            advisory_id=advisory_id,
            related_campaign=related_campaign,
            cve_refs=cve_refs_cti or [],
            iocs=IocBundle(),
        ).model_dump(exclude_none=True)

    vulnops_dump = VulnOpsSpec(
        cve_refs=cve_refs_vulnops or [],
        affects=[
            AffectsSpec(vendor=v, product=p, version_range=vr)
            for v, p, vr in (affects or [])
        ],
        regression_critical=regression_critical,
    ).model_dump()

    return CatalogSpec.model_validate({
        "vendor": "linux",
        "product": "auditd",
        "version": "3.x",
        "log_type": log_type,
        "format": "auditd_raw",
        "template": "x",
        "cti": cti_dump,
        "vulnops": vulnops_dump,
    })


def _specs_with_paths(items: list[tuple[str, CatalogSpec]]):
    """Wrap (filename, spec) tuples as the (Path, CatalogSpec) iterable
    that ``query(specs=...)`` expects."""
    return [(Path(name), spec) for name, spec in items]


# ──────────────── PackageQuery.parse ────────────────


@pytest.mark.unit
class TestPackageQueryParse:
    def test_two_parts(self):
        pq = PackageQuery.parse("pypi:litellm")
        assert pq.ecosystem == "pypi"
        assert pq.name == "litellm"
        assert pq.version is None

    def test_three_parts(self):
        pq = PackageQuery.parse("npm:lodash:4.17.21")
        assert pq.ecosystem == "npm"
        assert pq.name == "lodash"
        assert pq.version == "4.17.21"

    def test_normalizes_ecosystem_name_case(self):
        pq = PackageQuery.parse("PyPI:LiteLLM")
        assert pq.ecosystem == "pypi"
        assert pq.name == "litellm"

    def test_version_case_preserved(self):
        # Versions are case-sensitive (`1.0.0-RC1` ≠ `1.0.0-rc1`)
        pq = PackageQuery.parse("npm:foo:1.0.0-RC1")
        assert pq.version == "1.0.0-RC1"

    def test_one_part_rejected(self):
        with pytest.raises(ValueError):
            PackageQuery.parse("litellm")

    def test_empty_ecosystem_rejected(self):
        with pytest.raises(ValueError):
            PackageQuery.parse(":litellm")

    def test_too_many_colons_rejected(self):
        with pytest.raises(ValueError):
            PackageQuery.parse("npm:foo:1.0.0:extra")

    def test_token_includes_version_when_present(self):
        assert (
            PackageQuery.parse("pypi:litellm:1.82.8").token()
            == "package:pypi:litellm:1.82.8"
        )

    def test_token_omits_version_when_absent(self):
        assert (
            PackageQuery.parse("pypi:litellm").token()
            == "package:pypi:litellm"
        )


# ──────────────── version match ────────────────


@pytest.mark.unit
class TestVersionMatches:
    def test_target_none_always_matches(self):
        assert _version_matches("1.0.0,1.0.1", None) is True
        assert _version_matches("*", None) is True

    def test_wildcard_matches_any_target(self):
        assert _version_matches("*", "1.0.0") is True
        assert _version_matches("*", "99.99.99-rc1") is True

    def test_exact_version_in_list(self):
        assert _version_matches("1.82.7, 1.82.8", "1.82.7") is True
        assert _version_matches("1.82.7,1.82.8", "1.82.8") is True

    def test_version_outside_list(self):
        assert _version_matches("1.82.7,1.82.8", "1.82.6") is False
        assert _version_matches("1.82.7,1.82.8", "1.82.9") is False

    def test_whitespace_tolerated(self):
        assert _version_matches("  1.0.0 , 1.0.1  ", "1.0.0") is True


# ──────────────── single-keyword queries ────────────────


@pytest.mark.unit
class TestQueryByCve:
    def test_match_via_vulnops_cve_refs(self):
        spec_a = _spec(log_type="a", cve_refs_vulnops=["CVE-2026-0001"])
        spec_b = _spec(log_type="b", cve_refs_vulnops=["CVE-2026-0002"])
        out = query(
            cve=["CVE-2026-0001"],
            specs=_specs_with_paths([("a.yaml", spec_a), ("b.yaml", spec_b)]),
            catalog_root=Path("."),
        )
        assert {m.path for m in out} == {"a.yaml"}
        assert out[0].matched_by == ("cve:CVE-2026-0001",)

    def test_match_via_cti_cve_refs(self):
        # Some catalogs put CVEs only in cti.cve_refs, not vulnops —
        # query must check both sources.
        spec_a = _spec(log_type="a", cve_refs_cti=["CVE-2026-0001"])
        out = query(
            cve=["CVE-2026-0001"],
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert len(out) == 1
        assert out[0].matched_by == ("cve:CVE-2026-0001",)

    def test_multiple_cves_repeatable(self):
        spec_a = _spec(log_type="a", cve_refs_vulnops=["CVE-A"])
        spec_b = _spec(log_type="b", cve_refs_vulnops=["CVE-B"])
        spec_c = _spec(log_type="c", cve_refs_vulnops=["CVE-C"])
        out = query(
            cve=["CVE-A", "CVE-B"],
            specs=_specs_with_paths([
                ("a.yaml", spec_a), ("b.yaml", spec_b), ("c.yaml", spec_c),
            ]),
            catalog_root=Path("."),
        )
        assert {m.path for m in out} == {"a.yaml", "b.yaml"}


@pytest.mark.unit
class TestQueryByAdvisory:
    def test_match_advisory_id(self):
        spec_a = _spec(log_type="a", advisory_id="PYSEC-2026-2")
        spec_b = _spec(log_type="b", advisory_id="GHSA-9999")
        out = query(
            advisory_id=["PYSEC-2026-2"],
            specs=_specs_with_paths(
                [("a.yaml", spec_a), ("b.yaml", spec_b)]
            ),
            catalog_root=Path("."),
        )
        assert {m.path for m in out} == {"a.yaml"}


@pytest.mark.unit
class TestQueryByCampaign:
    def test_match_campaign(self):
        spec_a = _spec(log_type="a", related_campaign="teampcp")
        spec_b = _spec(log_type="b", related_campaign="other-camp")
        out = query(
            campaign=["teampcp"],
            specs=_specs_with_paths(
                [("a.yaml", spec_a), ("b.yaml", spec_b)]
            ),
            catalog_root=Path("."),
        )
        assert {m.path for m in out} == {"a.yaml"}


@pytest.mark.unit
class TestQueryByPackage:
    def test_match_package_name_only(self):
        spec_a = _spec(
            log_type="a",
            affects=[("pypi", "litellm", "1.82.7,1.82.8")],
        )
        spec_b = _spec(
            log_type="b",
            affects=[("npm", "lodash", "4.17.21")],
        )
        out = query(
            package=["pypi:litellm"],
            specs=_specs_with_paths(
                [("a.yaml", spec_a), ("b.yaml", spec_b)]
            ),
            catalog_root=Path("."),
        )
        assert {m.path for m in out} == {"a.yaml"}

    def test_match_package_with_exact_version_hit(self):
        spec_a = _spec(
            log_type="a", affects=[("pypi", "litellm", "1.82.7,1.82.8")]
        )
        out = query(
            package=["pypi:litellm:1.82.8"],
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert len(out) == 1

    def test_match_package_with_version_miss(self):
        spec_a = _spec(
            log_type="a", affects=[("pypi", "litellm", "1.82.7,1.82.8")]
        )
        out = query(
            package=["pypi:litellm:1.82.6"],
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert out == []

    def test_ecosystem_must_match(self):
        spec_a = _spec(
            log_type="a", affects=[("pypi", "litellm", "1.82.7")]
        )
        out = query(
            package=["npm:litellm"],
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert out == []

    def test_packagequery_object_accepted(self):
        spec_a = _spec(
            log_type="a", affects=[("pypi", "litellm", "1.82.7,1.82.8")]
        )
        out = query(
            package=[PackageQuery(
                ecosystem="pypi", name="litellm", version="1.82.7"
            )],
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert len(out) == 1


# ──────────────── union semantics ────────────────


@pytest.mark.unit
class TestUnionSemantics:
    def test_two_keywords_union(self):
        spec_a = _spec(
            log_type="a", advisory_id="PYSEC-2026-2",
            related_campaign=None,
        )
        spec_b = _spec(
            log_type="b", advisory_id="GHSA-99",
            related_campaign="teampcp",
        )
        spec_c = _spec(
            log_type="c", advisory_id=None, related_campaign="other-camp",
            cve_refs_cti=None,
        )
        # A matches via advisory, B matches via campaign — C neither
        out = query(
            advisory_id=["PYSEC-2026-2"],
            campaign=["teampcp"],
            specs=_specs_with_paths([
                ("a.yaml", spec_a), ("b.yaml", spec_b), ("c.yaml", spec_c),
            ]),
            catalog_root=Path("."),
        )
        assert {m.path for m in out} == {"a.yaml", "b.yaml"}

    def test_same_spec_accumulates_matched_by(self):
        """One catalog matching multiple keywords records all tokens."""
        spec = _spec(
            log_type="a",
            advisory_id="PYSEC-2026-2",
            related_campaign="teampcp",
            affects=[("pypi", "litellm", "1.82.7,1.82.8")],
        )
        out = query(
            advisory_id=["PYSEC-2026-2"],
            campaign=["teampcp"],
            package=["pypi:litellm"],
            specs=_specs_with_paths([("a.yaml", spec)]),
            catalog_root=Path("."),
        )
        assert len(out) == 1
        m = out[0]
        assert "advisory:PYSEC-2026-2" in m.matched_by
        assert "campaign:teampcp" in m.matched_by
        assert "package:pypi:litellm" in m.matched_by


# ──────────────── empty-query refusal ────────────────


@pytest.mark.unit
class TestEmptyQuery:
    def test_no_keywords_returns_empty(self):
        spec_a = _spec(log_type="a")
        out = query(
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert out == []

    def test_all_empty_lists_returns_empty(self):
        spec_a = _spec(log_type="a")
        out = query(
            cve=[], advisory_id=[], package=[], campaign=[],
            specs=_specs_with_paths([("a.yaml", spec_a)]),
            catalog_root=Path("."),
        )
        assert out == []


# ──────────────── ordering ────────────────


@pytest.mark.unit
class TestOrdering:
    def test_p0_before_non_p0(self):
        p0 = _spec(
            log_type="p0", regression_critical=True,
            advisory_id="A", related_campaign="x",
            affects=[("pypi", "foo", "1.0")],
        )
        non_p0 = _spec(
            log_type="non_p0", regression_critical=False,
            advisory_id="A", related_campaign="x",
            affects=[("pypi", "foo", "1.0")],
        )
        out = query(
            package=["pypi:foo"],
            specs=_specs_with_paths(
                [("z-non-p0.yaml", non_p0), ("a-p0.yaml", p0)]
            ),
            catalog_root=Path("."),
        )
        assert [m.path for m in out] == ["a-p0.yaml", "z-non-p0.yaml"]


# ──────────────── summary + JSON ────────────────


@pytest.mark.unit
class TestSummaryAndJson:
    def test_summary_counts(self):
        m1 = CatalogMatch(
            path="a", log_type="a", vendor="v", product="p", version="1",
            advisory_id="PYSEC-X", related_campaign="camp1",
            regression_critical=True, matched_by=("advisory:PYSEC-X",),
        )
        m2 = CatalogMatch(
            path="b", log_type="b", vendor="v", product="p", version="1",
            advisory_id="PYSEC-X", related_campaign="camp1",
            regression_critical=False, matched_by=("advisory:PYSEC-X",),
        )
        s = summarize([m1, m2])
        assert s.catalog_count == 2
        assert s.p0_count == 1
        assert s.by_advisory == {"PYSEC-X": 2}
        assert s.by_campaign == {"camp1": 2}
        assert s.by_vendor_product == {"v/p": 2}

    def test_empty_summary(self):
        s = summarize([])
        assert s.catalog_count == 0
        assert s.p0_count == 0

    def test_format_table_no_matches(self):
        assert "no catalogs match" in format_table([])

    def test_format_table_marks_p0(self):
        m = CatalogMatch(
            path="a", log_type="a", vendor="v", product="p", version="1",
            advisory_id="X", related_campaign="c",
            regression_critical=True, matched_by=("campaign:c",),
        )
        out = format_table([m])
        assert "P0" in out
        assert "campaign:c" in out

    def test_json_round_trip(self):
        import json as _json
        m = CatalogMatch(
            path="a", log_type="a", vendor="v", product="p", version="1",
            advisory_id="X", related_campaign="c",
            regression_critical=True, matched_by=("campaign:c",),
        )
        text = to_json([m], summarize([m]))
        data = _json.loads(text)
        assert data["summary"]["p0_count"] == 1
        assert data["matches"][0]["matched_by"] == ["campaign:c"]
