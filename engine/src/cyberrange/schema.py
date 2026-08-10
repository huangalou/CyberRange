"""Pydantic models for catalog YAML specs.

Schema versions:
- v1 (initial): vendor/product/version/log_type/format/transport/ocsf/params/fields/template
- v2 (2026-05-08): adds optional `detections`, `mythos_alignment`, `regression` for
  DetectOps Harness — let each catalog declare which Wazuh/Sigma/ELK detection
  rule it should fire, which Mythos-ready risk/PA it simulates, and the
  regression baseline (expected alert count, time-to-detect ceiling).
- v3 (2026-05-09): adds optional `cti` and `vulnops` blocks for CTI feed
  integration (Mythos-ready R10) and VulnOps × DetectOps reverse lookup
  (Mythos-ready PA 11). See `MythosAlignmentSpec` below for the risk/PA
  reference taxonomy.

v1 / v2 catalogs continue to load unchanged — all v3 additions are Optional.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class FieldSpec(BaseModel):
    """One field in a catalog template. type-specific extras allowed."""
    model_config = ConfigDict(extra="allow")

    name: str
    type: str


class ParamSpec(BaseModel):
    default: Any = None


class OcsfSpec(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    class_: Optional[str] = Field(default=None, alias="class")
    category_uid: Optional[int] = None
    class_uid: Optional[int] = None


# ──────────────── v2: detection mappings ────────────────


class WazuhDetection(BaseModel):
    """Expected Wazuh decoder/rule that should fire for this catalog."""

    rule_id: Optional[int] = None
    decoder: Optional[str] = None
    level: Optional[int] = None


class SigmaDetection(BaseModel):
    """Expected Sigma rule (community / custom) covering this catalog."""

    rule: str
    ref: Optional[str] = None


class ElkDetection(BaseModel):
    """Expected Kibana detection rule for this catalog."""

    kibana_rule_id: Optional[str] = None
    severity: Optional[str] = None


class DetectionSpec(BaseModel):
    """Detection-rule mappings across the SOC stacks this catalog feeds."""

    wazuh: list[WazuhDetection] = Field(default_factory=list)
    sigma: list[SigmaDetection] = Field(default_factory=list)
    elk_detection: list[ElkDetection] = Field(default_factory=list)


# ──────────────── v2: Mythos-ready alignment ────────────────


class MythosAlignmentSpec(BaseModel):
    """Annotate which Mythos-ready risk/PA scenario this catalog stresses.

    Uses this project's internal risk/PA reference taxonomy
    (R1..R13, PA1..PA11) — see `mythos_alignment` usage across the
    catalog YAML files for concrete examples of each ref.
    """

    risk_refs: list[str] = Field(default_factory=list)
    pa_refs: list[str] = Field(default_factory=list)
    ttx_class: Optional[Literal["rapid", "weeks", "months"]] = None


# ──────────────── v2: regression baseline ────────────────


class RegressionSpec(BaseModel):
    """Baseline expectations for `cyberrange regression` runs."""

    baseline_alert_count: Optional[int] = None
    baseline_ttd_ms: Optional[int] = None


# ──────────────── v3: CTI integration ────────────────


class PackageVersionIoc(BaseModel):
    """Compromised package version IOC across an ecosystem."""

    ecosystem: Literal["pypi", "npm", "maven", "gem", "cargo", "nuget", "go"]
    name: str
    versions: list[str] = Field(default_factory=list)


class HttpFingerprintIoc(BaseModel):
    """HTTP header / value pair that identifies attacker traffic."""

    header: str
    value: str


class IocBundle(BaseModel):
    """Indicators of compromise drawn from a CTI advisory.

    Lists are intentionally separate by IOC type so detection rules /
    enrichment pipelines can pick the right fields without parsing.
    """

    domains: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)
    package_versions: list[PackageVersionIoc] = Field(default_factory=list)
    http_fingerprints: list[HttpFingerprintIoc] = Field(default_factory=list)


class CtiSpec(BaseModel):
    """CTI advisory provenance + IOCs for this catalog.

    Mythos-ready R10 alignment: `Time-to-Catalog` and
    `Time-to-Verified-Detection` are derived from `ingested_at` plus the
    catalog's git history.
    """

    source: Optional[str] = None              # e.g. datadog-security-labs
    source_url: Optional[str] = None
    advisory_id: Optional[str] = None         # GHSA / PYSEC / CVE-* id
    ingested_at: Optional[str] = None         # ISO date — when wiki ingested
    iocs: Optional[IocBundle] = None
    cve_refs: list[str] = Field(default_factory=list)
    related_campaign: Optional[str] = None    # internal campaign id (chains/)


# ──────────────── v3: VulnOps reverse-lookup ────────────────


class AffectsSpec(BaseModel):
    """Vendor/product/version-range a CVE applies to."""

    vendor: str
    product: str
    version_range: str                         # semver-style or text


class VulnOpsSpec(BaseModel):
    """VulnOps × DetectOps reverse-lookup metadata.

    Mythos-ready PA 11 alignment: when a CVE is patched upstream, query
    catalogs by `cve_refs` to determine which detection regressions to
    re-run. `regression_critical: true` triggers P0 in the triage queue.
    """

    cve_refs: list[str] = Field(default_factory=list)
    affects: list[AffectsSpec] = Field(default_factory=list)
    patch_signal: list[str] = Field(default_factory=list)
    regression_critical: bool = False


# ──────────────── v4: CEF customizable mapping ────────────────


class CefHeader(BaseModel):
    """CEF v0 header constants. Values are exposed to Jinja via `cef_header.*`
    and can be overridden per-dispatch via `cef_header_overrides`."""

    device_vendor:  Optional[str] = None
    device_product: Optional[str] = None
    device_version: Optional[str] = None
    signature_id:   Optional[str] = None
    name:           Optional[str] = None
    severity:       Optional[int] = None


class CefMappingEntry(BaseModel):
    """One PA-field → CEF-extension-key pair. Order in the catalog list
    determines order in the rendered CEF extensions body."""

    pa_field: str          # must reference a `fields[].name` in same spec
    cef_key:  str          # default CEF extension key (per vendor admin guide)


class CatalogSpec(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    vendor: str
    product: str
    version: str
    log_type: str
    description: Optional[str] = None
    format: str
    transport: list[str] = Field(default_factory=list)
    ocsf: Optional[OcsfSpec] = None
    params: dict[str, ParamSpec] = Field(default_factory=dict)
    fields: list[FieldSpec] = Field(default_factory=list)
    template: str

    # v2 additions (all optional, catalogs without these continue to work)
    detections: Optional[DetectionSpec] = None
    mythos_alignment: Optional[MythosAlignmentSpec] = None
    regression: Optional[RegressionSpec] = None

    # v3 additions (CTI + VulnOps reverse-lookup, both optional)
    cti: Optional[CtiSpec] = None
    vulnops: Optional[VulnOpsSpec] = None

    # v4 additions (CEF customizable mapping, both optional)
    # When `cef_mapping` is present, engine renders {{cef_extensions}} as a
    # `k=v k=v` body composed from this list (with optional per-dispatch
    # overrides). `cef_header` is exposed to Jinja as {{cef_header.X}}.
    cef_header:  Optional[CefHeader]              = None
    cef_mapping: Optional[list[CefMappingEntry]]  = None

    def default_params(self) -> dict[str, Any]:
        return {k: v.default for k, v in self.params.items()}
