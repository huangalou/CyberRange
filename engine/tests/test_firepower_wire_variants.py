"""Cisco FTD 430001 — three verbatim-anchored wire variants.

Audit 2026-08-21: the catalog rendered only the IBM/QRadar `SFIMS` sample
(Protocol first). Elastic, Rapid7 and the ArcSight 430001 pattern all put
SrcIP first and Protocol after DstPort; FMC unified adds an
EventPriority/DeviceUUID/InstanceID/FirstPacketSecond/ConnectionID prefix.
"""
from __future__ import annotations

import re
from collections import Counter

from cyberrange import find_spec, load_spec, render_one

KEY = ("cisco", "firepower", "7.x", "intrusion-event")
HEAD = re.compile(r"^<\d+>\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} (\S+) (SFIMS : )?%FTD-(\d)-430001( : |: )(.*)$")


def _lines(n: int) -> list[tuple[str, str, list[str]]]:
    spec = load_spec(find_spec(*KEY))
    out = []
    for _ in range(n):
        line = render_one(spec, {})
        m = HEAD.match(line)
        assert m, line
        body = m.group(5)
        keys = re.findall(r"(?:^|, )([A-Za-z]+): ", body)
        variant = "sfims_legacy" if m.group(2) else ("fmc_unified" if keys[0] == "EventPriority" else "ftd_device")
        out.append((variant, body, keys))
    return out


def test_all_three_variants_are_emitted():
    seen = Counter(v for v, _, _ in _lines(200))
    assert set(seen) == {"ftd_device", "fmc_unified", "sfims_legacy"}, seen
    assert seen["ftd_device"] > seen["fmc_unified"] > seen["sfims_legacy"], seen


def test_device_and_unified_put_protocol_after_dstport():
    for variant, body, keys in _lines(200):
        core = keys[5:] if variant == "fmc_unified" else keys
        if variant == "sfims_legacy":
            assert keys[:5] == ["Protocol", "SrcIP", "DstIP", "SrcPort", "DstPort"], keys
            assert re.search(r'Message: ".+?", Classification:', body), body
            continue
        assert core[:9] == ["SrcIP", "DstIP", "SrcPort", "DstPort", "Protocol", "IngressInterface", "EgressInterface", "IngressZone", "EgressZone"], keys
        assert core[9:13] == ["Priority", "GID", "SID", "Revision"], keys
        assert 'Message: "' not in body, body  # unquoted in device/unified form
        assert keys[-1] == "MitreAttack", keys


def test_unified_prefix_matches_arcsight_430001_pattern():
    arcsight = re.compile(
        r".*InstanceID: (\d+), .* SrcIP: (\d+.\d+.\d+.\d+), DstIP: (\d+.\d+.\d+.\d+), SrcPort: (\d+), DstPort: (\d+), Protocol: (\S+),"
        r".* Priority: (\S+), .* Message: (.*), Classification: (.*),.*"
    )
    unified = [b for v, b, _ in _lines(300) if v == "fmc_unified"]
    assert unified
    for body in unified:
        assert arcsight.fullmatch(body), body
        assert re.match(r"EventPriority: (High|Medium|Low), DeviceUUID: [0-9a-f-]{36}, InstanceID: \d+, FirstPacketSecond: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z, ConnectionID: \d+, SrcIP:", body), body
