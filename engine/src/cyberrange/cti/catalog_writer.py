"""LLM-assisted catalog YAML drafter.

Phase 4.5 子系統 4/3 (catalog_writer) — closes the CTI ingest line:
``advisory → IOC bundle → catalog draft → SOC engineer review → commit``.

The drafter is **offline-first**: with no LLM client injected, it
emits a deterministic stub catalog that already validates against
schema v3 and can be `cyberrange gen`-rendered. With an `LlmClient`
injected, it asks the model to refine the description, template, and
field set — but the structural backbone (vendor/product/log_type,
cti/vulnops blocks, IOC mapping) stays heuristic so model drift never
breaks the YAML shape.

Public API:

- ``LlmClient`` Protocol — inject your provider (Ollama, Anthropic,
  OpenAI, custom). Tests use ``NoOpLlmClient`` (zero network).
- ``DetectionSurface`` enum — endpoint network / host FS / host process
  / k8s control plane / cloud control plane / network perimeter.
- ``draft_catalog(advisory_md, ingested_at, *, llm=None, ...)`` →
  ``CatalogDraft`` containing a validated ``CatalogSpec`` + warnings.
- ``CatalogDraft.to_yaml()`` → YAML string ready to write into
  ``catalog/<vendor>/<product>/<version>/<filename>.yaml``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol

import yaml

from ..schema import (
    AffectsSpec,
    CatalogSpec,
    CtiSpec,
    FieldSpec,
    IocBundle,
    OcsfSpec,
    ParamSpec,
    PackageVersionIoc,
    VulnOpsSpec,
)
from .ioc_extractor import ExtractionResult, IocExtractor


# ──────────────── LLM client (offline-first) ────────────────


class LlmClient(Protocol):
    """Minimal LLM interface.

    Catalog_writer never instantiates a client itself — callers pass one
    in. Tests pass ``NoOpLlmClient``; production CLI can wire Ollama,
    Anthropic, OpenAI, or a custom wrapper.
    """

    def complete(self, system: str, user: str, max_tokens: int = 2000) -> str:
        ...


class NoOpLlmClient:
    """Returns empty refinement — drafter falls back to heuristic
    template/description. Used in tests and in offline ``draft`` runs."""

    def complete(
        self, system: str, user: str, max_tokens: int = 2000
    ) -> str:
        return ""


# ──────────────── detection surface heuristic ────────────────


class DetectionSurface(str, Enum):
    ENDPOINT_NETWORK = "endpoint_network"
    HOST_FS = "host_fs"
    HOST_PROCESS = "host_process"
    K8S_CONTROL_PLANE = "k8s_control_plane"
    CLOUD_CONTROL_PLANE = "cloud_control_plane"
    NETWORK_PERIMETER = "network_perimeter"


# Keyword → surface hints. Lowercased, matched against advisory markdown.
# Order matters within a tuple: first match wins per surface keyword group.
_SURFACE_KEYWORDS: dict[DetectionSurface, tuple[str, ...]] = {
    DetectionSurface.CLOUD_CONTROL_PLANE: (
        "cloudtrail", "aws cli", "iam:", "sts:", "boto3",
        "assumerole", "getcalleridentity", "s3 bucket",
        "azure ad", "azuread", "gcp audit", "google cloud audit",
    ),
    DetectionSurface.K8S_CONTROL_PLANE: (
        "kubernetes audit", "k8s audit", "kube-apiserver",
        "daemonset", "serviceaccount", "kubelet",
    ),
    DetectionSurface.NETWORK_PERIMETER: (
        "fortigate", "fortios", "palo alto", "panos",
        "checkpoint", "cisco asa", "sonicwall", "firewall",
        "proxy log", "web filter", "webfilter",
    ),
    DetectionSurface.HOST_FS: (
        "file create", "file_create", "auditd path",
        "syscheck", "fim", "persistence file",
    ),
    DetectionSurface.HOST_PROCESS: (
        "pip install", "execve", "process create",
        "argv", "command-line",
    ),
    DetectionSurface.ENDPOINT_NETWORK: (
        "sysmon eid 3", "network connection", "outbound c2",
        "outbound https", "outbound http", "exfiltration",
    ),
}


# Vendor / product / version / format presets per surface. These are
# the "obvious" first-pass choices a SOC engineer would reach for —
# operators are expected to post-edit if their environment differs.
@dataclass(frozen=True)
class _SurfacePreset:
    vendor: str
    product: str
    version: str
    format: str
    transport: tuple[str, ...]
    log_type_prefix: str
    ocsf_category_uid: int
    ocsf_class_uid: int
    ocsf_class: str


_SURFACE_PRESETS: dict[DetectionSurface, _SurfacePreset] = {
    DetectionSurface.ENDPOINT_NETWORK: _SurfacePreset(
        vendor="microsoft", product="windows", version="2022",
        format="json", transport=("tcp_syslog", "beats", "file"),
        log_type_prefix="sysmon.network_connect",
        ocsf_category_uid=4, ocsf_class_uid=4001,
        ocsf_class="network_activity",
    ),
    DetectionSurface.HOST_FS: _SurfacePreset(
        vendor="linux", product="auditd", version="3.x",
        format="auditd_raw", transport=("file", "tcp_syslog", "beats"),
        log_type_prefix="auditd.file_create",
        ocsf_category_uid=1, ocsf_class_uid=1001,
        ocsf_class="file_activity",
    ),
    DetectionSurface.HOST_PROCESS: _SurfacePreset(
        vendor="linux", product="auditd", version="3.x",
        format="auditd_raw", transport=("file", "tcp_syslog", "beats"),
        log_type_prefix="auditd.execve",
        ocsf_category_uid=1, ocsf_class_uid=1007,
        ocsf_class="process_activity",
    ),
    DetectionSurface.K8S_CONTROL_PLANE: _SurfacePreset(
        vendor="kubernetes", product="k8s-audit", version="1.x",
        format="json", transport=("beats", "file"),
        log_type_prefix="k8s.audit",
        ocsf_category_uid=6, ocsf_class_uid=6003,
        ocsf_class="api_activity",
    ),
    DetectionSurface.CLOUD_CONTROL_PLANE: _SurfacePreset(
        vendor="aws", product="cloudtrail", version="2.0",
        format="json", transport=("beats", "file"),
        log_type_prefix="cloudtrail",
        ocsf_category_uid=6, ocsf_class_uid=6003,
        ocsf_class="api_activity",
    ),
    DetectionSurface.NETWORK_PERIMETER: _SurfacePreset(
        vendor="fortinet", product="fortios", version="7.4",
        format="key_value", transport=("udp_syslog", "tcp_syslog", "file"),
        log_type_prefix="fortios.utm.webfilter",
        ocsf_category_uid=4, ocsf_class_uid=4002,
        ocsf_class="http_activity",
    ),
}


def infer_surface(advisory_md: str, iocs: IocBundle) -> DetectionSurface:
    """Pick the best-fit detection surface for a fresh advisory.

    Strategy: prose keywords first (strongest signal — vendors literally
    name the surface), fall back to IOC-axis dominance (which IOC type
    has the most entries).
    """
    text = advisory_md.lower()

    # Phase 1: keyword vote
    keyword_scores: dict[DetectionSurface, int] = {}
    for surface, keywords in _SURFACE_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text)
        if score > 0:
            keyword_scores[surface] = score

    if keyword_scores:
        return max(keyword_scores.items(), key=lambda kv: kv[1])[0]

    # Phase 2: IOC-axis dominance
    axis_scores: dict[DetectionSurface, int] = {
        DetectionSurface.ENDPOINT_NETWORK: len(iocs.domains) + len(iocs.ips),
        DetectionSurface.HOST_FS: len(iocs.file_paths) + len(iocs.file_hashes),
        DetectionSurface.NETWORK_PERIMETER: len(iocs.http_fingerprints),
        DetectionSurface.HOST_PROCESS: len(iocs.package_versions),
    }
    nonzero = {k: v for k, v in axis_scores.items() if v > 0}
    if nonzero:
        return max(nonzero.items(), key=lambda kv: kv[1])[0]

    # Default: endpoint-network — broadest applicability when nothing else
    return DetectionSurface.ENDPOINT_NETWORK


# ──────────────── stub templates per surface ────────────────


# Minimal, generate-able templates. SOC engineer is expected to refine
# them — but offline these still produce non-empty events so the catalog
# survives `cyberrange gen` smoke immediately after drafting.
_STUB_TEMPLATES: dict[DetectionSurface, str] = {
    DetectionSurface.ENDPOINT_NETWORK: (
        '<{{pri}}>{{rfc3164_ts}} {{hostname}} '
        '{"@timestamp":"{{ts_iso}}","event":{"code":3,'
        '"provider":"Microsoft-Windows-Sysmon"},'
        '"source":{"ip":"{{src_ip}}","port":{{src_port}}},'
        '"destination":{"ip":"{{dst_ip}}","port":443,'
        '"domain":"{{dst_domain}}"},"network":{"protocol":"tcp"}}'
    ),
    DetectionSurface.HOST_FS: (
        "<{{pri}}>{{rfc3164_ts}} {{hostname}} kernel: type=PATH "
        "msg=audit({{epoch}}:{{audit_serial}}): item=0 "
        'name="{{target_path}}" inode=0 dev=fd:00 mode=0100644 '
        "ouid={{uid}} ogid={{uid}} rdev=00:00 nametype=CREATE"
    ),
    DetectionSurface.HOST_PROCESS: (
        "<{{pri}}>{{rfc3164_ts}} {{hostname}} kernel: type=EXECVE "
        "msg=audit({{epoch}}:{{audit_serial}}): argc=3 "
        'a0="pip" a1="install" a2="{{package_spec}}"'
    ),
    DetectionSurface.K8S_CONTROL_PLANE: (
        '{"kind":"Event","apiVersion":"audit.k8s.io/v1",'
        '"level":"RequestResponse","auditID":"{{audit_id}}",'
        '"verb":"create","user":{"username":"{{username}}"},'
        '"sourceIPs":["{{source_ip}}"],"userAgent":"{{user_agent}}",'
        '"requestReceivedTimestamp":"{{ts_iso}}",'
        '"stageTimestamp":"{{ts_iso}}"}'
    ),
    DetectionSurface.CLOUD_CONTROL_PLANE: (
        '{"eventVersion":"1.09","eventTime":"{{ts_iso}}",'
        '"eventSource":"sts.amazonaws.com","eventName":"GetCallerIdentity",'
        '"awsRegion":"us-west-2","sourceIPAddress":"{{source_ip}}",'
        '"userAgent":"{{user_agent}}","requestID":"{{request_id}}",'
        '"eventID":"{{event_id}}","eventType":"AwsApiCall"}'
    ),
    DetectionSurface.NETWORK_PERIMETER: (
        '<{{pri}}>{{rfc3164_ts}} {{fw_devname}} date={{date_iso}} '
        'time={{time_24h}} devname="{{fw_devname}}" '
        'logid="0317013312" type="utm" subtype="webfilter" '
        'srcip={{src_ip}} dstip={{dst_ip}} hostname="{{dst_domain}}" '
        'action="blocked" url="https://{{dst_domain}}/" '
        'method="GET" agent="{{user_agent}}"'
    ),
}


# Field sets per surface — enough variables to satisfy the stub
# templates above. Generators are deliberately simple (datetime, fixed,
# faker uuid4, cidr, weighted_choice, param) — all covered by engine.
def _stub_fields(surface: DetectionSurface, iocs: IocBundle) -> list[FieldSpec]:
    common_time: list[dict[str, Any]] = [
        {"name": "ts_iso", "type": "datetime",
         "format": "%Y-%m-%dT%H:%M:%S.%fZ"},
        {"name": "rfc3164_ts", "type": "datetime",
         "format": "%b %d %H:%M:%S"},
        {"name": "epoch", "type": "datetime", "format": "epoch"},
        {"name": "pri", "type": "fixed", "value": 134},
    ]

    if surface == DetectionSurface.ENDPOINT_NETWORK:
        domains_choices = (
            {d: round(1.0 / len(iocs.domains), 4) for d in iocs.domains}
            if iocs.domains else {"example.invalid": 1.0}
        )
        ips_choices = (
            {ip: round(1.0 / len(iocs.ips), 4) for ip in iocs.ips}
            if iocs.ips else {"203.0.113.10": 1.0}
        )
        extra: list[dict[str, Any]] = [
            {"name": "hostname", "type": "param", "param": "hostname"},
            {"name": "src_ip", "type": "cidr", "cidr": "${params.src_cidr}"},
            {"name": "src_port", "type": "int_range",
             "min": 49152, "max": 65535},
            {"name": "dst_domain", "type": "weighted_choice",
             "choices": domains_choices},
            {"name": "dst_ip", "type": "weighted_choice",
             "choices": ips_choices},
        ]
    elif surface == DetectionSurface.HOST_FS:
        path_choices = (
            {p: round(1.0 / len(iocs.file_paths), 4) for p in iocs.file_paths}
            if iocs.file_paths else {"/tmp/placeholder": 1.0}
        )
        extra = [
            {"name": "hostname", "type": "param", "param": "hostname"},
            {"name": "uid", "type": "param", "param": "victim_uid"},
            {"name": "audit_serial", "type": "int_range",
             "min": 100, "max": 999999},
            {"name": "target_path", "type": "weighted_choice",
             "choices": path_choices},
        ]
    elif surface == DetectionSurface.HOST_PROCESS:
        pkg_specs: dict[str, float] = {}
        for pv in iocs.package_versions:
            for v in pv.versions:
                pkg_specs[f"{pv.name}=={v}"] = 0.0
        if pkg_specs:
            weight = round(1.0 / len(pkg_specs), 4)
            pkg_specs = {k: weight for k in pkg_specs}
        else:
            pkg_specs = {"placeholder==0.0.0": 1.0}
        extra = [
            {"name": "hostname", "type": "param", "param": "hostname"},
            {"name": "audit_serial", "type": "int_range",
             "min": 100, "max": 999999},
            {"name": "package_spec", "type": "weighted_choice",
             "choices": pkg_specs},
        ]
    elif surface == DetectionSurface.K8S_CONTROL_PLANE:
        ua_choices = _ua_choices_from_iocs(iocs)
        extra = [
            {"name": "audit_id", "type": "faker", "method": "uuid4"},
            {"name": "username", "type": "param", "param": "victim_user"},
            {"name": "source_ip", "type": "cidr",
             "cidr": "${params.pod_cidr}"},
            {"name": "user_agent", "type": "weighted_choice",
             "choices": ua_choices},
        ]
    elif surface == DetectionSurface.CLOUD_CONTROL_PLANE:
        ip_choices = (
            {ip: round(1.0 / len(iocs.ips), 4) for ip in iocs.ips}
            if iocs.ips else {"203.0.113.10": 1.0}
        )
        ua_choices = _ua_choices_from_iocs(iocs)
        extra = [
            {"name": "request_id", "type": "faker", "method": "uuid4"},
            {"name": "event_id", "type": "faker", "method": "uuid4"},
            {"name": "source_ip", "type": "weighted_choice",
             "choices": ip_choices},
            {"name": "user_agent", "type": "weighted_choice",
             "choices": ua_choices},
        ]
    else:  # NETWORK_PERIMETER
        domain_choices = (
            {d: round(1.0 / len(iocs.domains), 4) for d in iocs.domains}
            if iocs.domains else {"example.invalid": 1.0}
        )
        ip_choices = (
            {ip: round(1.0 / len(iocs.ips), 4) for ip in iocs.ips}
            if iocs.ips else {"203.0.113.10": 1.0}
        )
        ua_choices = _ua_choices_from_iocs(iocs)
        extra = [
            {"name": "fw_devname", "type": "param", "param": "fw_devname"},
            {"name": "date_iso", "type": "datetime", "format": "%Y-%m-%d"},
            {"name": "time_24h", "type": "datetime", "format": "%H:%M:%S"},
            {"name": "src_ip", "type": "cidr", "cidr": "${params.src_cidr}"},
            {"name": "dst_ip", "type": "weighted_choice",
             "choices": ip_choices},
            {"name": "dst_domain", "type": "weighted_choice",
             "choices": domain_choices},
            {"name": "user_agent", "type": "weighted_choice",
             "choices": ua_choices},
        ]

    return [FieldSpec.model_validate(f) for f in common_time + extra]


def _ua_choices_from_iocs(iocs: IocBundle) -> dict[str, float]:
    """Pull User-Agent values from http_fingerprints if present."""
    uas = [
        fp.value for fp in iocs.http_fingerprints
        if fp.header.lower() in ("user-agent", "user_agent", "ua")
    ]
    if not uas:
        return {"Python-urllib/3.12": 1.0}
    weight = round(1.0 / len(uas), 4)
    return {ua: weight for ua in uas}


def _stub_params(surface: DetectionSurface) -> dict[str, ParamSpec]:
    if surface == DetectionSurface.ENDPOINT_NETWORK:
        return {
            "hostname": ParamSpec(default="DEV-LAPTOP-04"),
            "src_cidr": ParamSpec(default="10.42.0.0/24"),
        }
    if surface in (DetectionSurface.HOST_FS, DetectionSurface.HOST_PROCESS):
        return {
            "hostname": ParamSpec(default="ml-dev-04"),
            "victim_user": ParamSpec(default="dev01"),
            "victim_uid": ParamSpec(default=1000),
        }
    if surface == DetectionSurface.K8S_CONTROL_PLANE:
        return {
            "victim_user": ParamSpec(
                default="system:serviceaccount:default:compromised-sa"
            ),
            "pod_cidr": ParamSpec(default="10.244.0.0/16"),
        }
    if surface == DetectionSurface.CLOUD_CONTROL_PLANE:
        return {
            "aws_account_id": ParamSpec(default="123456789012"),
            "aws_region": ParamSpec(default="us-west-2"),
        }
    # NETWORK_PERIMETER
    return {
        "fw_devname": ParamSpec(default="FGT-LAB-01"),
        "src_cidr": ParamSpec(default="10.42.0.0/24"),
    }


# ──────────────── campaign-id / log_type slug ────────────────


_CAMPAIGN_RE = re.compile(
    r"\b(?:campaign|operation|cluster)\s+(?:named|called|"
    r"dubbed|tracked\s+as)?\s*[\"`']?([a-zA-Z][a-zA-Z0-9_-]{2,40})",
    re.IGNORECASE,
)
_TEAMPCP_RE = re.compile(r"\bteam\W?pcp\b", re.IGNORECASE)


def infer_campaign_id(advisory_md: str, fallback: str = "advisory") -> str:
    """Pull a campaign slug. Special-case TeamPCP (most common pattern).
    Otherwise looks for explicit ``campaign named X`` prose. Returns
    a lowercase slug suitable for log_type suffixing."""
    if _TEAMPCP_RE.search(advisory_md):
        return "teampcp"

    m = _CAMPAIGN_RE.search(advisory_md)
    if m:
        return m.group(1).lower().replace("_", "-")

    return fallback.lower()


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s or "advisory"


# ──────────────── drafter ────────────────


@dataclass
class CatalogDraft:
    """Output of ``draft_catalog``. Holds a validated CatalogSpec plus
    drafter-side metadata (chosen surface, warnings for SOC review,
    suggested filename relative to ``catalog/``)."""

    spec: CatalogSpec
    surface: DetectionSurface
    suggested_path: str          # e.g. "fortinet/fortios/7.4/foo.yaml"
    warnings: list[str] = field(default_factory=list)

    def to_yaml(self) -> str:
        """Serialize the spec to YAML, dropping None / default fields
        so the draft stays readable (SOC engineer can fill in detections,
        mythos_alignment, regression by hand if desired)."""
        data = self.spec.model_dump(
            mode="json", by_alias=True, exclude_none=True,
        )
        # exclude_none misses empty lists/dicts — strip those too for a
        # tighter draft.
        cleaned = _strip_empty(data)
        return yaml.safe_dump(
            cleaned, sort_keys=False, default_flow_style=False,
            allow_unicode=True, width=100,
        )


def _strip_empty(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            stripped = _strip_empty(v)
            if stripped in ([], {}, None):
                continue
            out[k] = stripped
        return out
    if isinstance(obj, list):
        return [_strip_empty(x) for x in obj]
    return obj


def draft_catalog(
    advisory_md: str,
    *,
    ingested_at: str,
    source: Optional[str] = None,
    source_url: Optional[str] = None,
    advisory_id: Optional[str] = None,
    cve_refs: Optional[list[str]] = None,
    llm: Optional[LlmClient] = None,
    surface_override: Optional[DetectionSurface] = None,
    extractor: Optional[IocExtractor] = None,
) -> CatalogDraft:
    """Produce a schema-v3 catalog draft from an advisory markdown body.

    Args:
        advisory_md: Advisory text in markdown form (extractor input).
        ingested_at: ISO date string for ``cti.ingested_at``. Caller is
            responsible for "now" — the drafter is deterministic given
            its inputs.
        source: e.g. ``"datadog-security-labs"``. Used in ``cti.source``.
        source_url: Advisory permalink. Used in ``cti.source_url``.
        advisory_id: e.g. ``"PYSEC-2026-2"``. Used in ``cti.advisory_id``.
        cve_refs: Optional CVE list to seed ``cti.cve_refs`` +
            ``vulnops.cve_refs``.
        llm: Optional LLM client for description / template refinement.
            Default ``NoOpLlmClient`` keeps everything offline.
        surface_override: Force a specific detection surface (bypasses
            heuristic).
        extractor: Optional pre-configured IOC extractor (e.g. with
            ``include_clean=True`` for debugging).

    Returns:
        CatalogDraft: ``.spec`` is a validated CatalogSpec; ``.to_yaml()``
        gives the writable YAML string; ``.warnings`` lists advisory
        completeness issues for SOC review.
    """
    extractor = extractor or IocExtractor()
    extraction: ExtractionResult = extractor.extract(advisory_md)
    iocs = extraction.iocs

    surface = surface_override or infer_surface(advisory_md, iocs)
    preset = _SURFACE_PRESETS[surface]
    campaign = infer_campaign_id(advisory_md)

    warnings = _collect_warnings(extraction, advisory_id, source_url)

    log_type = f"{preset.log_type_prefix}.{_slugify(campaign)}"

    description = _draft_description(
        advisory_md, campaign, surface, iocs, llm or NoOpLlmClient(),
    )

    template = _STUB_TEMPLATES[surface]
    fields = _stub_fields(surface, iocs)
    params = _stub_params(surface)

    cti = CtiSpec(
        source=source,
        source_url=source_url,
        advisory_id=advisory_id,
        ingested_at=ingested_at,
        related_campaign=campaign,
        cve_refs=cve_refs or [],
        iocs=_filter_iocs_by_axis_ownership(iocs, surface),
    )

    vulnops = VulnOpsSpec(
        cve_refs=cve_refs or [],
        affects=_affects_from_packages(iocs.package_versions),
        patch_signal=_patch_signals_from_packages(iocs.package_versions),
        regression_critical=False,
    )

    spec = CatalogSpec.model_validate({
        "vendor": preset.vendor,
        "product": preset.product,
        "version": preset.version,
        "log_type": log_type,
        "description": description,
        "format": preset.format,
        "transport": list(preset.transport),
        "ocsf": OcsfSpec.model_validate({
            "class": preset.ocsf_class,
            "category_uid": preset.ocsf_category_uid,
            "class_uid": preset.ocsf_class_uid,
        }).model_dump(by_alias=True),
        "params": {k: {"default": v.default} for k, v in params.items()},
        "fields": [f.model_dump() for f in fields],
        "template": template,
        "cti": cti.model_dump(exclude_none=True),
        "vulnops": vulnops.model_dump(),
    })

    filename = f"{_slugify(campaign)}-{_slugify(surface.value)}.yaml"
    suggested_path = (
        f"{preset.vendor}/{preset.product}/{preset.version}/{filename}"
    )

    return CatalogDraft(
        spec=spec,
        surface=surface,
        suggested_path=suggested_path,
        warnings=warnings,
    )


# ──────────────── axis-ownership filter ────────────────


# Per-surface IOC axes the drafter is willing to claim: each catalog
# only owns the IOC types its template actually renders. Reviewer can
# hand-edit the YAML if they want a sibling catalog to instead own the axis.
_AXIS_OWNERSHIP: dict[DetectionSurface, frozenset[str]] = {
    DetectionSurface.ENDPOINT_NETWORK: frozenset({
        "domains", "ips", "package_versions",
    }),
    DetectionSurface.HOST_FS: frozenset({
        "file_paths", "file_hashes", "package_versions",
    }),
    DetectionSurface.HOST_PROCESS: frozenset({
        "package_versions",
    }),
    DetectionSurface.K8S_CONTROL_PLANE: frozenset({
        "http_fingerprints", "package_versions",
    }),
    DetectionSurface.CLOUD_CONTROL_PLANE: frozenset({
        "ips", "http_fingerprints", "package_versions",
    }),
    DetectionSurface.NETWORK_PERIMETER: frozenset({
        "http_fingerprints", "package_versions",
    }),
}


def _filter_iocs_by_axis_ownership(
    iocs: IocBundle, surface: DetectionSurface,
) -> IocBundle:
    """Keep only IOC axes this surface naturally renders. Reviewer can
    re-add others via post-edit if a sibling catalog is missing."""
    allowed = _AXIS_OWNERSHIP[surface]
    return IocBundle(
        domains=iocs.domains if "domains" in allowed else [],
        ips=iocs.ips if "ips" in allowed else [],
        file_paths=iocs.file_paths if "file_paths" in allowed else [],
        file_hashes=iocs.file_hashes if "file_hashes" in allowed else [],
        package_versions=(
            iocs.package_versions
            if "package_versions" in allowed else []
        ),
        http_fingerprints=(
            iocs.http_fingerprints
            if "http_fingerprints" in allowed else []
        ),
    )


# ──────────────── vulnops helpers ────────────────


def _affects_from_packages(
    pkgs: list[PackageVersionIoc],
) -> list[AffectsSpec]:
    return [
        AffectsSpec(
            vendor=pv.ecosystem,
            product=pv.name,
            version_range=",".join(pv.versions),
        )
        for pv in pkgs
    ]


def _patch_signals_from_packages(
    pkgs: list[PackageVersionIoc],
) -> list[str]:
    """Suggest patch-availability sentinels per ecosystem norms.
    Reviewer should refine with actual quarantine/yanked status."""
    if not pkgs:
        return []
    return [
        f"{pv.name} {' / '.join(pv.versions)} quarantined on "
        f"{_registry_name(pv.ecosystem)}"
        for pv in pkgs
    ]


def _registry_name(ecosystem: str) -> str:
    return {
        "pypi": "PyPI", "npm": "npmjs", "maven": "Maven Central",
        "gem": "RubyGems", "cargo": "crates.io",
        "nuget": "NuGet", "go": "pkg.go.dev",
    }.get(ecosystem, ecosystem)


# ──────────────── description (LLM or heuristic) ────────────────


def _draft_description(
    advisory_md: str,
    campaign: str,
    surface: DetectionSurface,
    iocs: IocBundle,
    llm: LlmClient,
) -> str:
    """Compose the catalog description. Try LLM first; fall back to a
    deterministic heuristic so the field is never empty."""
    refined = llm.complete(
        system=(
            "You are a SOC detection engineer. Write a 4-6 sentence "
            "catalog description in English explaining what attacker "
            "behavior this log models, which advisory IOCs it covers, "
            "and which sibling detection surfaces (endpoint/host/k8s/"
            "cloud/network) complement it. Be terse and concrete. "
            "Output the description text only — no headers, no quotes."
        ),
        user=(
            f"Campaign: {campaign}\n"
            f"Detection surface: {surface.value}\n"
            f"IOC summary: domains={len(iocs.domains)} ips={len(iocs.ips)} "
            f"file_paths={len(iocs.file_paths)} "
            f"package_versions={len(iocs.package_versions)} "
            f"http_fingerprints={len(iocs.http_fingerprints)}\n\n"
            f"Advisory excerpt (first 3000 chars):\n{advisory_md[:3000]}"
        ),
        max_tokens=600,
    ).strip()

    if refined:
        return refined

    # Heuristic fallback — facts-only, no fabrication
    parts = [
        f"Catalog draft auto-generated by cti.catalog_writer for the "
        f"`{campaign}` advisory campaign. Detection surface: "
        f"{surface.value.replace('_', ' ')}.",
    ]
    axes_present = []
    if iocs.domains:
        axes_present.append(f"{len(iocs.domains)} domains")
    if iocs.ips:
        axes_present.append(f"{len(iocs.ips)} IPs")
    if iocs.file_paths:
        axes_present.append(f"{len(iocs.file_paths)} file paths")
    if iocs.package_versions:
        pkg_names = ", ".join(p.name for p in iocs.package_versions)
        axes_present.append(f"package versions ({pkg_names})")
    if iocs.http_fingerprints:
        axes_present.append(
            f"{len(iocs.http_fingerprints)} HTTP fingerprints"
        )
    if axes_present:
        parts.append(
            "IOC bundle: " + ", ".join(axes_present) + "."
        )
    parts.append(
        "Template is a generate-able stub — review and refine to match "
        "the vendor's real log shape before production use."
    )
    return " ".join(parts)


# ──────────────── warnings ────────────────


def _collect_warnings(
    extraction: ExtractionResult,
    advisory_id: Optional[str],
    source_url: Optional[str],
) -> list[str]:
    out: list[str] = []
    if not extraction.defang_seen:
        out.append(
            "no defanging markers in source; IOCs may be over-collected"
        )
    total = sum(extraction.match_counts.values())
    if total == 0:
        out.append(
            "extractor matched 0 IOCs — draft contains placeholder data only"
        )
    if not advisory_id:
        out.append("advisory_id not provided; cti.advisory_id left blank")
    if not source_url:
        out.append("source_url not provided; cti.source_url left blank")
    return out
