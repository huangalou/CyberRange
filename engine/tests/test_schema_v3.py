"""Schema v3 tests: cti + vulnops blocks for CTI integration & VulnOps reverse-lookup.

v1 / v2 catalogs (without these fields) MUST continue to load — covered by
`test_smoke.py::test_every_spec_in_catalog_renders_without_error`.

The first canonical v3 catalog is the TeamPCP outbound C2 Sysmon EID 3
example, sourced from Datadog Security Labs advisory (PYSEC-2026-2).
"""
from __future__ import annotations

import json
import re

import pytest

from cyberrange import find_spec, load_spec, render_many, render_one
from cyberrange.schema import (
    CtiSpec,
    IocBundle,
    PackageVersionIoc,
    VulnOpsSpec,
)


@pytest.mark.unit
def test_teampcp_catalog_loads_with_network_axis_iocs():
    """The Sysmon EID 3 catalog owns the network egress axis — its IOC
    bundle carries domains + ips (what the template emits) plus the
    campaign-shared package_versions reference. file_paths and
    http_fingerprints belong to sibling catalogs whose templates emit
    those axes."""
    path = find_spec(
        "microsoft", "windows", "2022", "sysmon.network_connect.teampcp"
    )
    spec = load_spec(path)

    # cti block fully populated
    assert isinstance(spec.cti, CtiSpec)
    assert spec.cti.source == "datadog-security-labs"
    assert spec.cti.advisory_id == "PYSEC-2026-2"
    assert spec.cti.related_campaign == "teampcp"
    assert spec.cti.ingested_at == "2026-05-07"

    # Network axis IOCs present
    assert isinstance(spec.cti.iocs, IocBundle)
    assert "models.litellm.cloud" in spec.cti.iocs.domains
    assert "checkmarx.zone" in spec.cti.iocs.domains
    assert "83.142.209.203" in spec.cti.iocs.ips

    # Other axes deliberately empty — owned by sibling catalogs
    assert spec.cti.iocs.file_paths == []
    assert spec.cti.iocs.http_fingerprints == []


@pytest.mark.unit
def test_teampcp_package_version_iocs_match_advisory():
    path = find_spec(
        "microsoft", "windows", "2022", "sysmon.network_connect.teampcp"
    )
    spec = load_spec(path)

    pkgs = spec.cti.iocs.package_versions
    assert len(pkgs) == 2
    by_name = {p.name: p for p in pkgs}

    litellm = by_name["litellm"]
    assert isinstance(litellm, PackageVersionIoc)
    assert litellm.ecosystem == "pypi"
    assert set(litellm.versions) == {"1.82.7", "1.82.8"}

    telnyx = by_name["telnyx"]
    assert telnyx.ecosystem == "pypi"
    assert set(telnyx.versions) == {"4.87.1", "4.87.2"}


@pytest.mark.unit
def test_teampcp_vulnops_marked_regression_critical():
    """P0 priority — supply-chain compromise must trigger highest-tier
    regression run on every patch event."""
    path = find_spec(
        "microsoft", "windows", "2022", "sysmon.network_connect.teampcp"
    )
    spec = load_spec(path)

    assert isinstance(spec.vulnops, VulnOpsSpec)
    assert spec.vulnops.regression_critical is True

    # affects block names both compromised packages
    affected_products = {a.product for a in spec.vulnops.affects}
    assert affected_products == {"litellm", "telnyx"}


@pytest.mark.unit
def test_teampcp_renders_with_teampcp_ioc_in_destination():
    """Sample render should yield a destination matching one of the CTI IOCs
    (domain or IP). 25 samples covers the weighted_choice distribution."""
    path = find_spec(
        "microsoft", "windows", "2022", "sysmon.network_connect.teampcp"
    )
    spec = load_spec(path)

    ioc_domains = set(spec.cti.iocs.domains)
    ioc_ips = set(spec.cti.iocs.ips)

    hits = 0
    for _ in range(25):
        line = render_one(spec)
        json_start = line.index("{")
        parsed = json.loads(line[json_start:])
        dst = parsed["destination"]
        if dst["domain"] in ioc_domains or dst["ip"] in ioc_ips:
            hits += 1

    # Expect at least 50% of samples hit a known TeamPCP IOC. Three weighted
    # branches (exfil_litellm + beacon_checkmarx + wav_stage_telnyx +
    # related_infra_a + related_infra_b) → 100% by design, but allow margin
    # for the 2 cloudflare-style fallback IPs that aren't in the IOC list.
    # Only `wav_stage_telnyx` (0.20) + `related_infra_a` (0.10) +
    # `related_infra_b` (0.05) deterministically hit IPs in the IOC set;
    # the two HTTPS branches resolve to non-IOC cloudflare IPs by design.
    # Domain-side: exfil_litellm + beacon_checkmarx (0.65) hit IOC domains.
    # Combined IOC-hit rate ≈ 0.65 + 0.35 = 1.00 by domain OR ip match.
    assert hits >= 18, f"expected ≥18/25 IOC hits, got {hits}"


@pytest.mark.unit
def test_teampcp_event_id_3_shape_parses():
    path = find_spec(
        "microsoft", "windows", "2022", "sysmon.network_connect.teampcp"
    )
    spec = load_spec(path)
    line = render_one(spec)

    # PRI prefix + RFC3164 + JSON envelope
    assert re.match(r"^<\d+>", line), f"missing PRI: {line!r}"
    json_start = line.index("{")
    parsed = json.loads(line[json_start:])

    assert parsed["event"]["code"] == 3
    assert parsed["winlog"]["event_id"] == 3
    assert parsed["network"]["direction"] == "egress"
    assert parsed["winlog"]["event_data"]["Image"].endswith("python.exe")


@pytest.mark.unit
def test_teampcp_mythos_alignment_targets_r1_r10():
    """R1 + R10 — accelerated threat + lagging intelligence. This is the
    canonical CTI integration catalog, must be tagged accordingly."""
    path = find_spec(
        "microsoft", "windows", "2022", "sysmon.network_connect.teampcp"
    )
    spec = load_spec(path)
    assert spec.mythos_alignment is not None
    assert "R1" in spec.mythos_alignment.risk_refs
    assert "R10" in spec.mythos_alignment.risk_refs
    assert spec.mythos_alignment.ttx_class == "rapid"


@pytest.mark.unit
def test_existing_v2_catalogs_have_no_v3_blocks():
    """openssh + apache + fortinet etc. don't carry v3 metadata yet — schema
    must keep these catalogs loading cleanly with cti/vulnops as None."""
    for vendor, product, version, log_type in [
        ("linux", "openssh", "9.x", "auth.failure"),
        ("apache", "httpd", "2.4", "access.combined"),
        ("fortinet", "fortios", "7.4", "traffic.forward"),
    ]:
        path = find_spec(vendor, product, version, log_type)
        spec = load_spec(path)
        assert spec.cti is None, f"{log_type} unexpectedly has cti block"
        assert spec.vulnops is None, f"{log_type} unexpectedly has vulnops block"


# ──────────────── auditd file_create TeamPCP (Linux side) ────────────────


AUDITD_TEAMPCP = ("linux", "auditd", "3.x", "auditd.file_create.teampcp")


@pytest.mark.unit
def test_auditd_teampcp_loads_with_filesystem_iocs_only():
    """The auditd catalog covers the FS axis only — domains/ips deliberately
    empty since the Sysmon EID 3 sibling owns the network axis."""
    path = find_spec(*AUDITD_TEAMPCP)
    spec = load_spec(path)

    assert spec.cti is not None
    assert spec.cti.related_campaign == "teampcp"
    assert spec.cti.iocs is not None
    # FS axis — file_paths populated, domains/ips empty
    assert len(spec.cti.iocs.file_paths) == 5
    assert spec.cti.iocs.domains == []
    assert spec.cti.iocs.ips == []
    # but package_versions still mirrors the campaign root cause
    assert {p.name for p in spec.cti.iocs.package_versions} == {"litellm", "telnyx"}


def _extract_create_path_name(sample: str) -> str | None:
    """auditd file-create event emits two PATH records — PARENT
    (item=0, nametype=PARENT) and CREATE (item=1, nametype=CREATE).
    The CREATE record's name= is the actual target IOC path.
    (Wave 4 audit 2026-05-15 rewrote auditd catalog from 2-record
    to 5-record real auditd format — see catalog description block.)"""
    for line in sample.split("\n"):
        if "nametype=CREATE" in line:
            m = re.search(r'name="([^"]+)"', line)
            if m:
                return m.group(1)
    return None


@pytest.mark.unit
def test_auditd_teampcp_renders_path_syscall_pair():
    """Real auditd file-create event emits 5 records sharing one
    msg=audit(timestamp:serial): PATH(PARENT) + PATH(CREATE) + CWD +
    SYSCALL + PROCTITLE. Wazuh decoder correlates on serial — every
    record line MUST share it.

    Wave 4 audit (2026-05-15) rewrote catalog from 2-line to full
    5-record set per Red Hat audit reference + audit-userspace
    source; see the Linux auditd upstream documentation for
    record-by-record semantics."""
    path = find_spec(*AUDITD_TEAMPCP)
    spec = load_spec(path)
    sample = render_one(spec)

    lines = sample.strip().split("\n")
    assert len(lines) == 5, f"expected 5-record set, got {len(lines)} lines"
    assert "type=PATH" in lines[0] and "nametype=PARENT" in lines[0]
    assert "type=PATH" in lines[1] and "nametype=CREATE" in lines[1]
    assert "type=CWD" in lines[2]
    assert "type=SYSCALL" in lines[3]
    assert "type=PROCTITLE" in lines[4]

    # All 5 lines must share the same audit serial for SOC correlation.
    serial_re = re.compile(r"msg=audit\(\d+\.\d+:(\d+)\):")
    serials = [serial_re.search(line).group(1) for line in lines]
    assert len(set(serials)) == 1, (
        f"serial mismatch across 5 records: {serials}"
    )


@pytest.mark.unit
def test_auditd_teampcp_paths_always_hit_an_ioc():
    """Every render's CREATE PATH record (nametype=CREATE, item=1)
    targets one of 5 IOC paths by design. 25 samples should hit
    100% IOC match on that target path.

    NOTE: the PARENT PATH record (item=0) carries the parent dir
    (e.g. `/tmp`, `/home/dev01/.config/sysmon`) — must NOT be
    matched against IOC list. See `_extract_create_path_name`."""
    path = find_spec(*AUDITD_TEAMPCP)
    spec = load_spec(path)

    suffixes = [
        "/litellm_init.pth",
        "/.config/sysmon/sysmon.py",
        "/.config/systemd/user/sysmon.service",
    ]
    exact = {"/tmp/pglog", "/tmp/.pg_state"}

    hits = 0
    for sample in render_many(spec, 25):
        observed = _extract_create_path_name(sample)
        assert observed, f"no nametype=CREATE PATH record in: {sample!r}"
        if observed in exact or any(observed.endswith(s) for s in suffixes):
            hits += 1
    assert hits == 25, f"expected 25/25 IOC hits, got {hits}"


@pytest.mark.unit
def test_auditd_teampcp_audit_key_tags_persistence_vs_tmp():
    """The audit key field discriminates malicious_persistence (the 3
    home-dir paths) from tmp_drop (/tmp/* paths). Detection rules can pivot
    on key alone — no path parsing needed.

    (Wave 4 audit fix: extract CREATE PATH record specifically;
    pre-fix the test pulled first name= which was the PARENT dir
    and silently bypassed both branches.)"""
    path = find_spec(*AUDITD_TEAMPCP)
    spec = load_spec(path)

    key_re = re.compile(r'key="([^"]+)"')
    persistence_paths = (
        "/.config/sysmon/sysmon.py",
        "/.config/systemd/user/sysmon.service",
        "/litellm_init.pth",
    )
    tmp_paths = ("/tmp/pglog", "/tmp/.pg_state")

    for sample in render_many(spec, 30):
        observed_path = _extract_create_path_name(sample)
        key_match = key_re.search(sample)
        assert observed_path and key_match
        observed_key = key_match.group(1)

        if any(observed_path.endswith(p) for p in persistence_paths):
            assert observed_key == "malicious_persistence", (
                f"persistence path {observed_path} should tag "
                f"malicious_persistence, got {observed_key}"
            )
        elif observed_path in tmp_paths:
            assert observed_key == "tmp_drop", (
                f"tmp path {observed_path} should tag tmp_drop, "
                f"got {observed_key}"
            )


# ──────────────── k8s audit DaemonSet TeamPCP (cluster lateral) ────────────────


K8S_TEAMPCP = (
    "kubernetes", "k8s-audit", "1.x", "k8s.audit.daemonset_create.teampcp"
)


@pytest.mark.unit
def test_k8s_teampcp_loads_with_k8s_axis_iocs_only():
    """The k8s catalog encodes IOCs structurally (privileged DaemonSet
    pattern in the template) and via http_fingerprints; domains/ips/
    file_paths are owned by the sibling Sysmon/auditd catalogs."""
    path = find_spec(*K8S_TEAMPCP)
    spec = load_spec(path)

    assert spec.cti is not None
    assert spec.cti.iocs is not None
    assert spec.cti.iocs.domains == []
    assert spec.cti.iocs.ips == []
    assert spec.cti.iocs.file_paths == []
    # http_fingerprints carries the User-Agent IOC matching real TeamPCP
    assert any(
        fp.header == "User-Agent" and fp.value == "Python-urllib*"
        for fp in spec.cti.iocs.http_fingerprints
    )
    assert {p.name for p in spec.cti.iocs.package_versions} == {"litellm", "telnyx"}


def _split_k8s_dual_emit(sample: str) -> tuple[dict, dict]:
    """Sibling 4 dual-emit: line 1 = DaemonSet create (attacker-direct),
    line 2 = Pod create (controller-spawn). Split + JSON-parse both."""
    import json as _json

    lines = sample.split("\n")
    assert len(lines) == 2, f"expected 2-line dual-emit, got {len(lines)}"
    return _json.loads(lines[0]), _json.loads(lines[1])


@pytest.mark.unit
def test_k8s_teampcp_pod_name_matches_node_setup_pattern():
    """Per advisory: privileged DaemonSet follows `node-setup-{8hex}`
    naming; K8s controller-spawned Pod adds 5-char hash suffix.
    Both lines must encode the IOC pod-name pattern."""
    path = find_spec(*K8S_TEAMPCP)
    spec = load_spec(path)
    ds_re = re.compile(r"^node-setup-[0-9a-f]{8}$")
    pod_re = re.compile(r"^node-setup-[0-9a-f]{8}-[0-9a-f]{5}$")

    for sample in render_many(spec, 25):
        ds_event, pod_event = _split_k8s_dual_emit(sample)

        # Line 1: DaemonSet axis
        ds_name = ds_event["objectRef"]["name"]
        assert ds_re.match(ds_name), f"DS name {ds_name!r} doesn't match IOC"
        assert ds_event["objectRef"]["resource"] == "daemonsets"

        # Line 2: Pod axis (controller-spawn, name + 5-char suffix)
        pod_name = pod_event["objectRef"]["name"]
        assert pod_re.match(pod_name), f"pod name {pod_name!r} doesn't match IOC"
        assert pod_event["objectRef"]["resource"] == "pods"


@pytest.mark.unit
def test_k8s_teampcp_creates_privileged_daemonset_with_hostpath():
    """Structural IOC: privileged=true + hostPath / mount + hostNetwork
    + hostPID. Both audit lines must carry this PodSpec (line 1 inside
    DaemonSet `spec.template.spec`; line 2 inside Pod `spec` directly)."""
    path = find_spec(*K8S_TEAMPCP)
    spec = load_spec(path)

    sample = render_one(spec)
    ds_event, pod_event = _split_k8s_dual_emit(sample)

    # Line 1: DaemonSet → PodSpec nested under spec.template.spec
    ds_pod_spec = ds_event["requestObject"]["spec"]["template"]["spec"]
    assert ds_pod_spec["hostNetwork"] is True
    assert ds_pod_spec["hostPID"] is True
    ds_container = ds_pod_spec["containers"][0]
    assert ds_container["securityContext"]["privileged"] is True
    assert "SYS_ADMIN" in ds_container["securityContext"]["capabilities"]["add"]
    assert ds_event["verb"] == "create"
    assert ds_event["objectRef"]["resource"] == "daemonsets"

    # Line 2: Pod → PodSpec is requestObject.spec directly
    pod_spec = pod_event["requestObject"]["spec"]
    assert pod_spec["hostNetwork"] is True
    assert pod_spec["hostPID"] is True
    pod_container = pod_spec["containers"][0]
    assert pod_container["securityContext"]["privileged"] is True
    assert "SYS_ADMIN" in pod_container["securityContext"]["capabilities"]["add"]
    assert pod_event["verb"] == "create"
    assert pod_event["objectRef"]["resource"] == "pods"
    # Pod inherits serviceAccountName from DaemonSet (smoking gun on pod axis)
    assert pod_spec["serviceAccountName"] == "compromised-sa"
    # ownerReferences pin Pod to its parent DaemonSet
    owner_refs = pod_event["requestObject"]["metadata"]["ownerReferences"]
    assert owner_refs[0]["kind"] == "DaemonSet"


@pytest.mark.unit
def test_k8s_teampcp_container_names_only_in_ioc_set():
    """Container names per advisory: `kamikaze` or `provisioner`. 30
    samples should exhibit both on both emit lines (lines share name)."""
    path = find_spec(*K8S_TEAMPCP)
    spec = load_spec(path)

    ds_seen: set[str] = set()
    pod_seen: set[str] = set()
    for sample in render_many(spec, 30):
        ds_event, pod_event = _split_k8s_dual_emit(sample)
        ds_seen.add(
            ds_event["requestObject"]["spec"]["template"]["spec"]["containers"][0]["name"]
        )
        pod_seen.add(
            pod_event["requestObject"]["spec"]["containers"][0]["name"]
        )

    expected = {"kamikaze", "provisioner"}
    assert ds_seen <= expected, f"unexpected DS container names: {ds_seen - expected}"
    assert pod_seen <= expected, f"unexpected Pod container names: {pod_seen - expected}"
    assert ds_seen == expected, f"DS only saw {ds_seen} in 30 samples"
    assert pod_seen == expected, f"Pod only saw {pod_seen} in 30 samples"


@pytest.mark.unit
def test_k8s_teampcp_user_agent_matches_http_fingerprint():
    """The catalog's cti.iocs.http_fingerprints declares
    User-Agent: Python-urllib*. The attacker-direct DaemonSet create
    (line 1) must satisfy that fingerprint. The controller-spawn Pod
    create (line 2) carries kube-controller-manager UA — that's
    structural truth, not a fingerprint violation."""
    path = find_spec(*K8S_TEAMPCP)
    spec = load_spec(path)

    ua_pattern = re.compile(r"^Python-urllib/.+")
    controller_ua_pattern = re.compile(r"^kube-controller-manager/")
    for sample in render_many(spec, 15):
        ds_event, pod_event = _split_k8s_dual_emit(sample)

        ds_ua = ds_event["userAgent"]
        assert ua_pattern.match(ds_ua), (
            f"DS userAgent {ds_ua!r} doesn't match Python-urllib* fingerprint"
        )

        pod_ua = pod_event["userAgent"]
        assert controller_ua_pattern.match(pod_ua), (
            f"Pod userAgent {pod_ua!r} doesn't look like kube-controller-manager"
        )


# ──────────────── pip install execve TeamPCP (process axis) ────────────────


PIP_INSTALL_TEAMPCP = (
    "linux", "auditd", "3.x", "auditd.execve.pip_install.teampcp"
)


@pytest.mark.unit
def test_pip_install_teampcp_carries_process_axis_only():
    """The pip-install catalog represents the process/entry-point axis.
    Its cti.iocs carries only package_versions (campaign metadata) —
    no dedicated `command_patterns` IOC type exists yet, so the IOC
    list is intentionally minimal. The detection-relevant patterns
    live in the template's argv tokens."""
    path = find_spec(*PIP_INSTALL_TEAMPCP)
    spec = load_spec(path)

    assert spec.cti is not None
    assert spec.cti.iocs is not None
    # Process axis: only package_versions populated
    assert spec.cti.iocs.domains == []
    assert spec.cti.iocs.ips == []
    assert spec.cti.iocs.file_paths == []
    assert spec.cti.iocs.http_fingerprints == []
    # Campaign root cause shared with siblings
    pkgs = {p.name for p in spec.cti.iocs.package_versions}
    assert pkgs == {"litellm", "telnyx"}


@pytest.mark.unit
def test_pip_install_teampcp_renders_4record_execve_set():
    """Real auditd execve syscall emits 4 records sharing one
    msg=audit(timestamp:serial): SYSCALL + EXECVE + CWD + PROCTITLE.
    Wazuh decoder correlates on serial — every record line MUST share it.

    Wave 6 audit (2026-05-15) rewrote catalog from 2-line (EXECVE+SYSCALL)
    to full 4-record set per audit-userspace `src/auparse/normalize.c`
    emit order. execve produces zero PATH records (items=0) — that's the
    distinguishing shape from file-create's 5-record (which has PATH×2)."""
    path = find_spec(*PIP_INSTALL_TEAMPCP)
    spec = load_spec(path)
    sample = render_one(spec)

    lines = sample.strip().split("\n")
    assert len(lines) == 4, f"expected 4-record set, got {len(lines)} lines"
    assert "type=SYSCALL" in lines[0]
    assert "type=EXECVE" in lines[1]
    assert "type=CWD" in lines[2]
    assert "type=PROCTITLE" in lines[3]

    # All 4 lines must share the same audit serial for SOC correlation.
    serial_re = re.compile(r"msg=audit\(\d+\.\d+:(\d+)\):")
    serials = [serial_re.search(line).group(1) for line in lines]
    assert len(set(serials)) == 1, (
        f"serial mismatch across 4 records: {serials}"
    )


@pytest.mark.unit
def test_pip_install_teampcp_argv_always_targets_compromised_version():
    """Every render must reconstruct an argv that pins a TeamPCP-
    compromised package@version OR uses `-U` to auto-grab latest of a
    compromised package. 50 samples — 100% must satisfy."""
    path = find_spec(*PIP_INSTALL_TEAMPCP)
    spec = load_spec(path)

    compromised_pins = {
        "litellm==1.82.7", "litellm==1.82.8",
        "telnyx==4.87.1", "telnyx==4.87.2",
    }
    # `-U <pkg>` form: any of these names with `-U` in argv counts as a
    # latest-grab that would have hit the compromised version at the time.
    auto_grab_names = {"litellm", "telnyx"}

    argv_re = re.compile(
        r'a0="([^"]+)" a1="([^"]+)" a2="([^"]+)"'
        r'(?: a3="([^"]+)")?(?: a4="([^"]+)")?'
    )

    for sample in render_many(spec, 50):
        m = argv_re.search(sample)
        assert m, f"no argv in: {sample!r}"
        argv = [g for g in m.groups() if g]
        argv_str = " ".join(argv)
        # Direct pin somewhere in argv
        if any(pin in argv for pin in compromised_pins):
            continue
        # `-U <name>` form
        if "-U" in argv:
            idx = argv.index("-U")
            if idx + 1 < len(argv) and argv[idx + 1] in auto_grab_names:
                continue
        raise AssertionError(
            f"argv {argv!r} doesn't target a compromised package@version"
        )


@pytest.mark.unit
def test_pip_install_teampcp_argc_matches_argv_shape():
    """argc declares the argv length. python3 -m pip install <pkg>
    has 5 tokens (argc=5); direct pip install <pkg> has 3 (argc=3);
    pip install -U <name> has 4 (argc=4). Mismatch breaks Wazuh's argv
    reconstruction.

    Wave 6 audit (2026-05-15) added the `-U` branch — previous catalog
    declared argc=3 for the dashU scenario contradicting its own 4-token argv."""
    path = find_spec(*PIP_INSTALL_TEAMPCP)
    spec = load_spec(path)

    argc_re = re.compile(r"argc=(\d+)")
    a0_re = re.compile(r'a0="([^"]+)"')
    argv_re = re.compile(
        r'a0="([^"]+)" a1="([^"]+)" a2="([^"]+)"'
        r'(?: a3="([^"]+)")?(?: a4="([^"]+)")?'
    )

    for sample in render_many(spec, 30):
        argc = int(argc_re.search(sample).group(1))
        a0 = a0_re.search(sample).group(1)
        argv = [g for g in argv_re.search(sample).groups() if g]

        if a0 == "python3":
            assert argc == 5, f"python3 -m pip should be argc=5, got {argc}"
        elif a0 == "pip" and "-U" in argv:
            assert argc == 4, f"pip install -U <name> should be argc=4, got {argc}"
        elif a0 == "pip":
            assert argc == 3, f"pip <verb> <pkg> should be argc=3, got {argc}"
        else:
            raise AssertionError(f"unexpected argv0: {a0!r}")


# ──────────────── cross-catalog campaign consistency ────────────────


# ──────────────── TeamPCP 6-surface coverage invariant ────────────────
#
# Phase 4.5 backfilled 6 catalogs from the single PYSEC-2026-2 advisory,
# one per detection surface. The matrix below is the canonical
# axis-ownership table the chain playbook (Phase 6.5) will join against.
# Each row encodes:
#   - the (vendor, product, version, log_type) tuple find_spec uses
#   - the IOC axes that catalog MUST own (non-empty)
#   - the IOC axes that catalog MUST NOT own (empty — sibling owns)
#   - package_versions is always shared (campaign through-line)


_TEAMPCP_SURFACE_MATRIX = (
    # (surface_label, find_spec_key, must_own, must_not_own)
    (
        "endpoint_network",
        ("microsoft", "windows", "2022", "sysmon.network_connect.teampcp"),
        ("domains", "ips"),
        ("file_paths", "file_hashes"),
    ),
    (
        "host_fs",
        ("linux", "auditd", "3.x", "auditd.file_create.teampcp"),
        ("file_paths",),
        ("domains", "ips", "file_hashes"),
    ),
    (
        "host_process",
        ("linux", "auditd", "3.x", "auditd.execve.pip_install.teampcp"),
        (),  # process axis is encoded in template argv, not in IOC bundle
        ("domains", "ips", "file_paths", "file_hashes"),
    ),
    (
        "k8s_control_plane",
        ("kubernetes", "k8s-audit", "1.x", "k8s.audit.daemonset_create.teampcp"),
        ("http_fingerprints",),
        ("domains", "ips", "file_paths", "file_hashes"),
    ),
    (
        "network_perimeter",
        ("fortinet", "fortios", "7.4", "fortios.utm.webfilter.litellm_c2.teampcp"),
        ("http_fingerprints",),
        ("domains", "ips", "file_paths", "file_hashes"),
    ),
    (
        "cloud_control_plane",
        ("aws", "cloudtrail", "2.0", "cloudtrail.credential_abuse.teampcp"),
        ("ips", "http_fingerprints"),
        ("domains", "file_paths", "file_hashes"),
    ),
)


@pytest.mark.unit
@pytest.mark.parametrize(
    "surface_label,find_key,must_own,must_not_own",
    _TEAMPCP_SURFACE_MATRIX,
    ids=[row[0] for row in _TEAMPCP_SURFACE_MATRIX],
)
def test_teampcp_catalog_shares_campaign_metadata(
    surface_label, find_key, must_own, must_not_own
):
    """Every TeamPCP backfill catalog MUST tag the campaign metadata
    consistently — advisory_id, related_campaign, regression_critical —
    so a chain playbook (or VulnOps query) can reverse-discover the
    catalog set from any single entry."""
    spec = load_spec(find_spec(*find_key))

    assert spec.cti is not None, f"{surface_label}: cti block missing"
    assert spec.cti.related_campaign == "teampcp", (
        f"{surface_label}: related_campaign must be 'teampcp'"
    )
    assert spec.cti.advisory_id == "PYSEC-2026-2", (
        f"{surface_label}: advisory_id must be 'PYSEC-2026-2'"
    )
    assert spec.cti.ingested_at, (
        f"{surface_label}: ingested_at required for Time-to-Catalog metric"
    )
    assert spec.vulnops is not None
    assert spec.vulnops.regression_critical is True, (
        f"{surface_label}: must be regression_critical=true (P0 triage)"
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "surface_label,find_key,must_own,must_not_own",
    _TEAMPCP_SURFACE_MATRIX,
    ids=[row[0] for row in _TEAMPCP_SURFACE_MATRIX],
)
def test_teampcp_catalog_axis_ownership(
    surface_label, find_key, must_own, must_not_own
):
    """Each TeamPCP catalog owns exactly the IOC axes its template
    naturally renders — no more, no less. The 6 catalogs together span
    endpoint network / host FS / host process / k8s / cloud / network-
    perimeter without IOC-axis overlap (except the shared
    package_versions campaign through-line).

    Why this matters: a SOC engineer reading one catalog's cti.iocs
    should be able to derive a detection rule whose every IOC field
    actually appears in the rendered log. If the bundle contains an
    IOC type the template never emits, the rule becomes a broken
    field-reference."""
    spec = load_spec(find_spec(*find_key))
    assert spec.cti is not None and spec.cti.iocs is not None
    iocs = spec.cti.iocs

    for axis in must_own:
        assert getattr(iocs, axis), (
            f"{surface_label}: must own non-empty {axis!r} IOC axis"
        )
    for axis in must_not_own:
        assert getattr(iocs, axis) == [], (
            f"{surface_label}: must not own {axis!r} "
            f"(sibling catalog should hold it)"
        )

    # package_versions is always shared — every TeamPCP catalog references
    # the same litellm + telnyx root cause for cross-catalog joins.
    names = {p.name for p in iocs.package_versions}
    assert names == {"litellm", "telnyx"}, (
        f"{surface_label}: package_versions {names} != "
        f"expected {{litellm, telnyx}}"
    )


@pytest.mark.unit
def test_teampcp_six_surfaces_span_all_log_types_uniquely():
    """The 6 TeamPCP catalogs each have a distinct log_type and live at
    a distinct vendor/product/version path. No accidental duplicates."""
    log_types = []
    vpv_tuples = []
    for _, find_key, *_ in _TEAMPCP_SURFACE_MATRIX:
        spec = load_spec(find_spec(*find_key))
        log_types.append(spec.log_type)
        vpv_tuples.append((spec.vendor, spec.product, spec.version))

    assert len(set(log_types)) == 6, (
        f"duplicate log_type among TeamPCP catalogs: {log_types}"
    )
    # vendor/product/version can repeat (e.g. two auditd catalogs), but
    # never the (vendor, product, version, log_type) 4-tuple — already
    # implied by distinct log_types above, just being explicit.


# ──────────────── FortiBleed S3 — SSL VPN tunnel-up ────────────────


@pytest.mark.unit
def test_sslvpn_auth_fortibleed_generates_tunnel_up_success():
    """FortiBleed S3 stage: valid account auth to SSL VPN using infostealer
    credentials. Anomaly signal is remip from unexpected geo origin.

    Wire format aligned to Wazuh OOTB FortiGate decoder sample:
      logid=0101039947 type=event subtype=vpn action=tunnel-up
    Note: real tunnel-up wire format has no `status` field — tunnel-up
    itself signals success. Assertions target real wire fields only.
    """
    path = find_spec(
        "fortinet", "fortios", "7.4",
        "fortios.event.vpn.sslvpn_auth.fortibleed",
    )
    spec = load_spec(path)
    line = render_one(spec, params={
        "user_pool": ["jchen"],
        "remip_pool": ["203.0.113.50"],   # 異常 geo 來源
    })
    assert "subtype=vpn" in line or 'subtype="vpn"' in line
    assert "action=tunnel-up" in line or 'action="tunnel-up"' in line
    assert "logid=0101039947" in line or 'logid="0101039947"' in line
    assert "user=" in line and "jchen" in line
    assert "remip=203.0.113.50" in line
