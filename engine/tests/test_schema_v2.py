"""Schema v2 tests: detection mappings, Mythos-ready alignment, regression baseline.

v1 catalogs (without these fields) MUST continue to load — covered by
`test_smoke.py::test_every_spec_in_catalog_renders_without_error` running
across the whole catalog tree.
"""
from __future__ import annotations

import pytest

from cyberrange import find_spec, load_spec
from cyberrange.schema import (
    CatalogSpec,
    DetectionSpec,
    MythosAlignmentSpec,
    RegressionSpec,
    WazuhDetection,
)


@pytest.mark.unit
def test_apache_baseline_alignment():
    """apache/access.combined is web-baseline → R6 only, no PA, weeks ttx."""
    path = find_spec("apache", "httpd", "2.4", "access.combined")
    spec = load_spec(path)
    assert spec.detections is not None
    assert spec.detections.wazuh[0].decoder == "web-accesslog"
    # baseline → no rule_id (alerts come from Sigma overlay)
    assert spec.detections.wazuh[0].rule_id is None
    assert spec.mythos_alignment is not None
    assert spec.mythos_alignment.risk_refs == ["R6"]
    assert spec.mythos_alignment.ttx_class == "weeks"
    assert spec.regression is not None
    assert spec.regression.baseline_alert_count == 0


@pytest.mark.unit
def test_fortinet_traffic_has_v2_baseline_metadata():
    path = find_spec("fortinet", "fortios", "7.4", "traffic.forward")
    spec = load_spec(path)
    assert spec.detections is not None
    assert len(spec.detections.wazuh) == 1
    assert spec.detections.wazuh[0].decoder == "fortigate"
    # baseline catalog: no rule_id expected, no Mythos risk refs
    assert spec.detections.wazuh[0].rule_id is None
    assert spec.mythos_alignment is not None
    assert spec.mythos_alignment.risk_refs == []
    assert spec.regression is not None
    assert spec.regression.baseline_alert_count == 0


@pytest.mark.unit
def test_openssh_auth_failure_full_v2_alignment():
    path = find_spec("linux", "openssh", "9.x", "auth.failure")
    spec = load_spec(path)
    # detections present across all three SOC stacks
    assert spec.detections is not None
    assert any(d.rule_id == 5712 for d in spec.detections.wazuh), (
        "expected Wazuh rule 5712 (ssh brute force) in detections"
    )
    assert spec.detections.sigma, "expected at least one Sigma rule mapping"
    assert spec.detections.elk_detection, "expected ELK detection mapping"
    # Mythos alignment claims R1/R4 + PA5/PA9/PA10
    assert spec.mythos_alignment is not None
    assert "R1" in spec.mythos_alignment.risk_refs
    assert "R4" in spec.mythos_alignment.risk_refs
    assert "PA5" in spec.mythos_alignment.pa_refs
    assert spec.mythos_alignment.ttx_class == "rapid"
    # regression baseline expects fan-out alerts
    assert spec.regression is not None
    assert spec.regression.baseline_alert_count > 0


@pytest.mark.unit
def test_v2_schema_models_construct_directly():
    """Pure schema-level test — no YAML, just model construction & defaults."""
    wd = WazuhDetection(rule_id=5712, decoder="sshd", level=10)
    assert wd.rule_id == 5712

    det = DetectionSpec(wazuh=[wd])
    assert det.sigma == []
    assert det.elk_detection == []

    align = MythosAlignmentSpec(risk_refs=["R4"], pa_refs=["PA10"], ttx_class="rapid")
    assert align.ttx_class == "rapid"

    reg = RegressionSpec(baseline_alert_count=100)
    assert reg.baseline_ttd_ms is None  # optional


@pytest.mark.unit
def test_invalid_ttx_class_rejected():
    """ttx_class is a Literal — typo should error rather than silently pass."""
    with pytest.raises(Exception):  # pydantic ValidationError
        MythosAlignmentSpec(ttx_class="quick")  # type: ignore[arg-type]


@pytest.mark.unit
def test_minimal_catalog_with_only_v1_fields_still_valid():
    """Smallest possible v1 catalog still loads (regression guard for the
    'all v2 fields are optional' contract)."""
    minimal = {
        "vendor": "test",
        "product": "p",
        "version": "1.0",
        "log_type": "noop",
        "format": "raw",
        "template": "hello",
    }
    spec = CatalogSpec.model_validate(minimal)
    assert spec.detections is None
    assert spec.mythos_alignment is None
    assert spec.regression is None
