"""ArcSight SmartConnector parse-compat regression axis (env-gated).

Runs every catalog's rendered samples through the offline simulator in
`arcsight_sim.py` and checks that no catalog parses *worse* than the
baseline recorded in EXPECT. The parser bundle is proprietary and never
committed: set `ARCSIGHT_PARSERS=/path/to/extracted/bundle` locally to
enable; CI (no env) skips the whole module.

Baseline vocabulary (best → worst): OK > WARN > PARTIAL > CATCH-ALL > FAIL.
N/A = no parser in the 8.5.2 bundle for that wire (documented limitation).
Every non-OK entry carries the reason so a future maintainer can tell an
ArcSight limitation from a catalog bug without re-deriving it.
"""
from __future__ import annotations

import os
import zlib
from pathlib import Path

import pytest

import arcsight_sim as sim
from cyberrange.loader import CATALOG_ROOT, list_specs

pytestmark = pytest.mark.skipif(
    not sim.parsers_available(),
    reason="ARCSIGHT_PARSERS unset or not an extracted SmartConnector parser bundle",
)

# Baseline 2026-09-07 (post audit #1–#6). (expected verdict, reason)
EXPECT: dict[str, tuple[str, str]] = {
    # ── WARN: ArcSight limitation or sample-dependent field presence ──
    "aws/cloudtrail/2.0/credential-abuse-teampcp": ("WARN", "errorCode/errorMessage only exist on failure events; `original`/`additionalEventData` are ArcSight-side synthesized tokens"),
    # ── PARTIAL: some samples land on a specific pattern, the rest fall through ──
    "cisco/firepower/7.x/intrusion-event": ("PARTIAL", "only the fmc_unified wire variant carries the InstanceID prefix ArcSight 430001 requires; ftd_device/sfims_legacy are real wires ArcSight 8.5.2 lacks"),
    "citrix/netscaler/13.x/waf-violation-native": ("PARTIAL", "check-class violations with the leading URL token hit specific patterns; a minority falls to pattern 77"),
    "linux/openssh/9.x/auth-failure": ("PARTIAL", "ArcSight syslog pattern 84 hard-codes `port (65140|33346|57104)` — `Invalid user X from IP port N` with any other port cannot fullmatch (parser defect)"),
    "symantec/endpoint-protection/14.x/sonar-detect": ("PARTIAL", "long-label sibling (14.3 RU) hits pattern #66; short-label sibling (Elastic fixture) only has catch-all #90"),
    # ── CATCH-ALL / FAIL: vendor wire is newer than the 8.5.2 parser ──
    "symantec/endpoint-protection/14.x/av-detect": ("CATCH-ALL", "SEP 14 Risk Log emits positional file path; ArcSight patterns 60/87 require a `File path:` label (parser lags SEP 14 wire)"),
    "f-secure/policy-manager/15.x/av-detect-native": ("FAIL", "bundle only ships the Policy Manager *file* format (TrapNumber=…); syslog `F-Secure: Virus Alert!` has no parser"),
    "sophos/endpoint/xg/av-detect": ("FAIL", "Sophos Central SIEM natively emits `severity=medium` + underscore keys; ArcSight `severity` is Integer-typed"),
    "sophos/endpoint/xg/hmpa-prevent": ("FAIL", "same Sophos Central native wire as av-detect"),
}
DEFAULT_EXPECT = ("OK", "")


def _catalogs() -> list[tuple[str, Path]]:
    return [(sim.catalog_key(p, CATALOG_ROOT), p) for p, _ in list_specs(CATALOG_ROOT)]


@pytest.mark.parametrize(("key", "path"), _catalogs(), ids=lambda v: v if isinstance(v, str) else "")
def test_catalog_parses_no_worse_than_baseline(key: str, path: Path):
    from cyberrange import load_spec

    spec = load_spec(path)
    lines = sim.render_samples(spec, seed=zlib.crc32(key.encode()))
    result = sim.audit_catalog(key, lines)
    expected, reason = EXPECT.get(key, DEFAULT_EXPECT)
    if result.verdict == "N/A":
        assert "unmapped" not in result.summary, f"{key}: add a SPEC entry (or an N/A note) in arcsight_sim.py — {result.summary}"
        return
    assert sim.VERDICT_RANK[result.verdict] <= sim.VERDICT_RANK[expected], (
        f"{key}: regressed to {result.verdict} (baseline {expected}: {reason or 'clean parse'})\n  {result.summary}\n  "
        + "\n  ".join(result.trace)
    )


def test_baseline_totals_do_not_regress():
    results = sim.audit_all()
    counts = {v: sum(1 for r in results if r.verdict == v) for v in sim.VERDICT_RANK}
    # 2026-09-07 baseline: OK 30 / WARN 1 / PARTIAL 4 / CATCH-ALL 1 / FAIL 3 / N/A 18 (57 catalogs)
    assert counts["FAIL"] <= 3, counts
    assert counts["CATCH-ALL"] <= 1, counts
    assert counts["OK"] >= 30, counts
    assert sum(counts.values()) == len(_catalogs()), counts
