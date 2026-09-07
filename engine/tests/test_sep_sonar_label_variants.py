"""SEP 14.x SONAR — two real label sets on the SEPM syslog wire.

Audit 2026-08-21 (#6): the catalog emitted only the short-label set
(`Inserted:` / `End:` / `Domain:` …, Elastic 14.x fixture). 14.3 RU-era
builds emit the long-label set (`Event Insert Time:` / `End Time:` /
`Domain Name:` … + trailing `Location:`), which is the only shape the
ArcSight SmartConnector 8.5.2 SEP parser pattern #66 recognises. Both are
real; the catalog now emits both as weighted siblings.
"""
from __future__ import annotations

import re
from collections import Counter

from cyberrange import find_spec, load_spec, render_one

KEY = ("symantec", "endpoint-protection", "14.x", "sonar-detect")
BODY = re.compile(r"^<\d+>\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} \S+ SymantecServer: (.*)$")

SHORT_TAIL = ",Inserted: {ts},End: {ts},Domain: Default,Group: {grp},Server: SEPM-PROD-01,User: {user},Source computer: ,Source IP: ,Intensive Protection Level: "
LONG_TAIL = ",Event Insert Time: {ts},End Time: {ts},Domain Name: Default,Group Name: {grp},Server Name: SEPM-PROD-01,User Name: {user},Source Computer Name: ,Source Computer IP: ,Location: {loc},Intensive Protection Level: "

# ArcSight 8.5.2 symantecendpointprotection_regex submessage[0].pattern[66]
# (Java regex, properties-unescaped; fullmatch semantics).
ARCSIGHT_66 = re.compile(
    r".*?((Virus found|Security risk found|Potential risk found)),Computer name:\s*[^,]*,IP Address: (.*?),"
    r"Detection type: .*?,First Seen: .*?\.\,Application name: (.*?),Application type: (.*?),\"?Application version: (.*?),"
    r"Hash type: (\S+),Application hash: (.*?),\"?Company name: .*?,File size \(bytes\): (\d+).*Occurrences: (\d+),"
    r".*?Actual action: (.*?),.*,Event time: (.*?),Event Insert Time: (.*?),End Time: (.*?),Domain Name: (.*?),"
    r"Group Name: (.*?),Server Name: (.*?),User Name: (.*?),Source Computer Name: (.*?),Source Computer IP: (.*?),"
    r"Location: (.*?),.*",
    re.S,
)


def _bodies(n: int) -> list[tuple[str, str]]:
    spec = load_spec(find_spec(*KEY))
    out = []
    for _ in range(n):
        line = render_one(spec, {})
        m = BODY.match(line)
        assert m, line
        body = m.group(1)
        variant = "long" if ",Event Insert Time: " in body else "short"
        out.append((variant, body))
    return out


def test_both_label_sets_are_emitted_short_majority():
    seen = Counter(v for v, _ in _bodies(300))
    assert set(seen) == {"short", "long"}, seen
    assert seen["short"] > seen["long"], seen


def test_short_variant_keeps_elastic_fixture_labels():
    for variant, body in _bodies(200):
        if variant != "short":
            continue
        assert re.search(r",Event time: \S+ \S+,Inserted: \S+ \S+,End: \S+ \S+,Domain: Default,Group: .+?,Server: SEPM-PROD-01,User: \w+,Source computer: ,Source IP: ,Intensive Protection Level: \d,", body), body
        assert "Location:" not in body, body
        assert "Event Insert Time" not in body and "Domain Name" not in body, body


def test_long_variant_fullmatches_arcsight_pattern_66():
    longs = [b for v, b in _bodies(300) if v == "long"]
    assert longs
    for body in longs:
        m = ARCSIGHT_66.fullmatch(body)
        assert m, body
        # ArcSight maps $15 → destinationNtDomain, $16 → cs3 (Group), $21 → cs5 (Location)
        assert m.group(15) == "Default", body
        assert m.group(16).startswith("My Company"), body
        assert m.group(21).endswith("Managed Client - Online"), body
        assert "Inserted:" not in body and ",Domain: " not in body, body
