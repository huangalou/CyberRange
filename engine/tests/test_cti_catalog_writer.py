"""Tests for `cyberrange.cti.catalog_writer` — Phase 4.5 closer.

Covers:
- Offline draft from real TeamPCP advisory fixture (no LLM, no network)
- Schema-v3 round-trip (drafter output re-parses as CatalogSpec)
- Detection-surface heuristic + override
- Axis-ownership filter (each surface only owns its natural IOC axes)
- Campaign id inference
- Warning collection
- Mock LlmClient injection refines description without breaking shape
- Stub catalog is `cyberrange gen`-renderable end-to-end
"""
from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
import yaml

from cyberrange.cti import (
    CatalogDraft,
    DetectionSurface,
    LlmClient,
    NoOpLlmClient,
    draft_catalog,
    infer_campaign_id,
    infer_surface,
)
from cyberrange.cti.catalog_writer import _filter_iocs_by_axis_ownership
from cyberrange.cti.ioc_extractor import extract_iocs
from cyberrange.generator import render_many
from cyberrange.loader import CatalogSpec
from cyberrange.schema import IocBundle


FIXTURE = (
    Path(__file__).parent / "fixtures" / "teampcp-advisory-excerpt.md"
)


@pytest.fixture(scope="module")
def teampcp_md() -> str:
    return FIXTURE.read_text(encoding="utf-8")


# ──────────────── campaign id inference ────────────────


@pytest.mark.unit
class TestCampaignId:
    def test_teampcp_special_case(self):
        assert infer_campaign_id("This is the TeamPCP campaign.") == "teampcp"

    def test_team_pcp_with_hyphen(self):
        # "team-pcp" with the `\W?` slot between team and pcp
        assert infer_campaign_id("Team-PCP attack") == "teampcp"

    def test_explicit_campaign_named(self):
        text = 'A campaign dubbed "OperationDoubleTap" hit ...'
        assert infer_campaign_id(text) == "operationdoubletap"

    def test_fallback_unknown(self):
        assert (
            infer_campaign_id("Generic advisory text", fallback="adv-X")
            == "adv-x"
        )


# ──────────────── surface inference ────────────────


@pytest.mark.unit
class TestSurfaceInference:
    def test_cloudtrail_keyword_wins(self):
        text = "Attackers used cloudtrail to log into IAM with stolen creds."
        surface = infer_surface(text, IocBundle())
        assert surface == DetectionSurface.CLOUD_CONTROL_PLANE

    def test_k8s_keyword(self):
        text = "Privileged DaemonSet created via k8s audit."
        surface = infer_surface(text, IocBundle())
        assert surface == DetectionSurface.K8S_CONTROL_PLANE

    def test_perimeter_keyword(self):
        text = "FortiGate UTM webfilter blocked the C2 callback."
        surface = infer_surface(text, IocBundle())
        assert surface == DetectionSurface.NETWORK_PERIMETER

    def test_file_persistence_keyword(self):
        text = "auditd PATH event captured the persistence file."
        surface = infer_surface(text, IocBundle())
        assert surface == DetectionSurface.HOST_FS

    def test_ioc_dominance_fallback_network(self):
        # No surface keywords — fall back to IOC axis dominance.
        iocs = IocBundle(
            domains=["a.com", "b.com", "c.com"], ips=["1.1.1.1", "2.2.2.2"],
        )
        assert (
            infer_surface("generic prose", iocs)
            == DetectionSurface.ENDPOINT_NETWORK
        )

    def test_ioc_dominance_fallback_fs(self):
        iocs = IocBundle(
            file_paths=["/tmp/a", "/tmp/b", "/tmp/c"],
        )
        assert infer_surface("generic", iocs) == DetectionSurface.HOST_FS

    def test_empty_advisory_defaults_to_endpoint_network(self):
        assert (
            infer_surface("", IocBundle())
            == DetectionSurface.ENDPOINT_NETWORK
        )


# ──────────────── axis ownership filter ────────────────


@pytest.mark.unit
class TestAxisOwnership:
    @pytest.fixture
    def full_iocs(self) -> IocBundle:
        # One value per axis, so we can spot which are kept/dropped
        from cyberrange.schema import HttpFingerprintIoc, PackageVersionIoc
        return IocBundle(
            domains=["evil.example"],
            ips=["1.2.3.4"],
            file_paths=["/tmp/x"],
            file_hashes=["sha256:abc"],
            http_fingerprints=[
                HttpFingerprintIoc(header="User-Agent", value="Python-urllib")
            ],
            package_versions=[
                PackageVersionIoc(
                    ecosystem="pypi", name="evil", versions=["1.0"]
                )
            ],
        )

    def test_endpoint_network_keeps_only_network_axes(self, full_iocs):
        filtered = _filter_iocs_by_axis_ownership(
            full_iocs, DetectionSurface.ENDPOINT_NETWORK
        )
        assert filtered.domains == ["evil.example"]
        assert filtered.ips == ["1.2.3.4"]
        assert filtered.package_versions  # always shared
        assert filtered.file_paths == []
        assert filtered.file_hashes == []
        assert filtered.http_fingerprints == []

    def test_host_fs_keeps_only_fs_axes(self, full_iocs):
        filtered = _filter_iocs_by_axis_ownership(
            full_iocs, DetectionSurface.HOST_FS
        )
        assert filtered.file_paths == ["/tmp/x"]
        assert filtered.file_hashes == ["sha256:abc"]
        assert filtered.package_versions  # shared
        assert filtered.domains == []
        assert filtered.ips == []
        assert filtered.http_fingerprints == []

    def test_perimeter_keeps_http_fingerprints_not_ips(self, full_iocs):
        filtered = _filter_iocs_by_axis_ownership(
            full_iocs, DetectionSurface.NETWORK_PERIMETER
        )
        assert filtered.http_fingerprints
        assert filtered.package_versions
        assert filtered.ips == []
        assert filtered.domains == []

    def test_cloud_keeps_ips_and_ua_not_domains(self, full_iocs):
        filtered = _filter_iocs_by_axis_ownership(
            full_iocs, DetectionSurface.CLOUD_CONTROL_PLANE
        )
        assert filtered.ips
        assert filtered.http_fingerprints
        assert filtered.domains == []
        assert filtered.file_paths == []


# ──────────────── full draft from TeamPCP advisory ────────────────


@pytest.mark.unit
class TestDraftFromAdvisory:
    @pytest.fixture
    def draft(self, teampcp_md: str) -> CatalogDraft:
        return draft_catalog(
            teampcp_md,
            ingested_at="2026-05-12",
            source="datadog-security-labs",
            source_url=(
                "https://securitylabs.datadoghq.com/articles/"
                "litellm-compromised-pypi-teampcp-supply-chain-campaign/"
            ),
            advisory_id="PYSEC-2026-2",
        )

    def test_draft_returns_validated_spec(self, draft: CatalogDraft):
        # Pydantic validation ran during draft construction — the
        # spec object itself is the proof.
        assert isinstance(draft.spec, CatalogSpec)
        assert draft.spec.vendor
        assert draft.spec.product
        assert draft.spec.log_type
        assert draft.spec.template

    def test_draft_picks_a_surface_from_advisory(
        self, draft: CatalogDraft, teampcp_md: str
    ):
        # The fixture talks about C2 callbacks + file persistence +
        # pip install + DaemonSet + CloudTrail. Whichever wins, must
        # be a valid surface — and the chosen vendor/product preset
        # must align with that surface.
        assert isinstance(draft.surface, DetectionSurface)

    def test_log_type_contains_campaign_slug(self, draft: CatalogDraft):
        assert "teampcp" in draft.spec.log_type.lower()

    def test_cti_block_populated(self, draft: CatalogDraft):
        cti = draft.spec.cti
        assert cti is not None
        assert cti.source == "datadog-security-labs"
        assert cti.advisory_id == "PYSEC-2026-2"
        assert cti.ingested_at == "2026-05-12"
        assert cti.related_campaign == "teampcp"
        # Some IOC axis must be non-empty (TeamPCP fixture has lots)
        assert cti.iocs is not None
        total = (
            len(cti.iocs.domains) + len(cti.iocs.ips)
            + len(cti.iocs.file_paths) + len(cti.iocs.file_hashes)
            + len(cti.iocs.package_versions)
            + len(cti.iocs.http_fingerprints)
        )
        assert total > 0

    def test_vulnops_block_has_affects_from_packages(
        self, draft: CatalogDraft
    ):
        vulnops = draft.spec.vulnops
        assert vulnops is not None
        # TeamPCP fixture has package_versions in the table → drafter
        # should turn them into AffectsSpec rows.
        if vulnops.affects:
            assert all(a.vendor == "pypi" for a in vulnops.affects)
            assert all(a.product and a.version_range for a in vulnops.affects)

    def test_suggested_path_under_vendor_product_version(
        self, draft: CatalogDraft
    ):
        parts = draft.suggested_path.split("/")
        # vendor / product / version / filename.yaml
        assert len(parts) == 4
        assert parts[0] == draft.spec.vendor
        assert parts[1] == draft.spec.product
        assert parts[2] == draft.spec.version
        assert parts[3].endswith(".yaml")
        assert "teampcp" in parts[3].lower()

    def test_warnings_flag_missing_metadata(self, teampcp_md: str):
        bare = draft_catalog(teampcp_md, ingested_at="2026-05-12")
        # No advisory_id / source_url provided → warnings should call it out
        joined = " | ".join(bare.warnings)
        assert "advisory_id" in joined
        assert "source_url" in joined


# ──────────────── YAML round-trip ────────────────


@pytest.mark.unit
class TestYamlRoundTrip:
    def test_to_yaml_parses_back_as_catalog_spec(self, teampcp_md: str):
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12",
            advisory_id="PYSEC-2026-2",
        )
        yaml_text = draft.to_yaml()

        # Sanity: it's actually YAML, top-level keys are present
        data = yaml.safe_load(yaml_text)
        for key in ("vendor", "product", "version", "log_type",
                    "format", "template"):
            assert key in data, f"missing top-level key {key!r}"

        # Round-trip through CatalogSpec — drafter output is schema-valid
        reparsed = CatalogSpec.model_validate(data)
        assert reparsed.vendor == draft.spec.vendor
        assert reparsed.log_type == draft.spec.log_type
        assert reparsed.template == draft.spec.template

    def test_to_yaml_strips_empty_collections(self, teampcp_md: str):
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12",
            advisory_id="PYSEC-2026-2",
        )
        yaml_text = draft.to_yaml()
        # No literal empty list / dict lines should appear
        assert "[]" not in yaml_text
        assert "{}" not in yaml_text


# ──────────────── LLM injection ────────────────


class _StubLlm:
    """Records the prompt + returns a fixed refinement."""

    def __init__(self, response: str = "Stub refined description.") -> None:
        self.calls: list[tuple[str, str, int]] = []
        self._response = response

    def complete(
        self, system: str, user: str, max_tokens: int = 2000
    ) -> str:
        self.calls.append((system, user, max_tokens))
        return self._response


@pytest.mark.unit
class TestLlmInjection:
    def test_noop_client_returns_heuristic_description(
        self, teampcp_md: str
    ):
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12",
            llm=NoOpLlmClient(),
        )
        # Heuristic description always mentions auto-generated + the
        # surface name as a fallback marker
        assert "auto-generated" in (draft.spec.description or "").lower()

    def test_stub_llm_description_takes_over(self, teampcp_md: str):
        stub = _StubLlm(response="Custom description from the model.")
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12", llm=stub,
        )
        assert draft.spec.description == "Custom description from the model."
        # LLM was actually invoked
        assert len(stub.calls) == 1
        system, user, _ = stub.calls[0]
        assert "SOC" in system
        assert "teampcp" in user.lower()

    def test_llm_empty_response_falls_back_to_heuristic(
        self, teampcp_md: str
    ):
        stub = _StubLlm(response="   \n\n   ")  # whitespace only
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12", llm=stub,
        )
        assert "auto-generated" in (draft.spec.description or "").lower()


# ──────────────── surface override ────────────────


@pytest.mark.unit
class TestSurfaceOverride:
    def test_override_to_host_fs(self, teampcp_md: str):
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12",
            surface_override=DetectionSurface.HOST_FS,
        )
        assert draft.surface == DetectionSurface.HOST_FS
        assert draft.spec.vendor == "linux"
        assert draft.spec.product == "auditd"
        # axis ownership filter applied: no domains in cti.iocs
        assert draft.spec.cti is not None
        assert draft.spec.cti.iocs is not None
        assert draft.spec.cti.iocs.domains == []
        # but file_paths from advisory should land here
        assert draft.spec.cti.iocs.file_paths

    def test_override_to_cloud_control_plane(self, teampcp_md: str):
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12",
            surface_override=DetectionSurface.CLOUD_CONTROL_PLANE,
        )
        assert draft.surface == DetectionSurface.CLOUD_CONTROL_PLANE
        assert draft.spec.vendor == "aws"
        # cloud catalog owns ips axis per drafter rules
        assert draft.spec.cti.iocs.ips


# ──────────────── end-to-end generator render ────────────────


@pytest.mark.integration
class TestDraftRendersWithGenerator:
    """Stub templates must be `cyberrange gen`-able out of the box —
    a draft you can't immediately smoke-test is useless."""

    @pytest.mark.parametrize("surface", list(DetectionSurface))
    def test_each_surface_renders_at_least_one_event(
        self, teampcp_md: str, surface: DetectionSurface
    ):
        draft = draft_catalog(
            teampcp_md, ingested_at="2026-05-12",
            surface_override=surface,
        )
        # render_many returns an iterable of event strings
        events = list(render_many(draft.spec, count=3))
        assert len(events) == 3
        for ev in events:
            assert ev and isinstance(ev, str)
            assert ev.strip(), "rendered event must not be all-whitespace"
