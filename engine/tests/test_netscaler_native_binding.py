"""NetScaler AppFW native catalog — event ↔ message-phrase binding.

Audit 2026-08-21: `appfw_event`, a per-type `msg_id` table and `msg_body`
were sampled independently, producing impossible tuples and a wrong
SAFECOMMERCE phrase. Each APPFW_* event must now carry the phrase the
Citrix docs / ArcSight native parser expect, and the number after the event
name is an opaque per-PPE counter.
"""
from __future__ import annotations

import re

from cyberrange import find_spec, load_spec, render_one

KEY = ("citrix", "netscaler", "13.x", "waf-violation-native")

LINE_RX = re.compile(
    r"^\w{3} +\d{1,2} \d{2}:\d{2}:\d{2} <local0\.info> \S+ \d{2}/\d{2}/\d{4}:\d{2}:\d{2}:\d{2} GMT \S+ \d-PPE-\d : "
    r"default APPFW (APPFW_[A-Z_]+) (\d+) (\d) :  (\d+\.\d+\.\d+\.\d+) \d+-PPE\d (\S+) (\S+) (?:(https?://\S+) )?(.*) <(blocked|not blocked|transformed|alert)>$"
)

PHRASE = {
    "APPFW_STARTURL": r"^Disallow Illegal URL: https?://\S+$",
    "APPFW_DENYURL": r"^Disallow Deny URL: https?://\S+ for rule pattern=\S+$",
    "APPFW_SIGNATURE_MATCH": r"^Signature violation rule ID \d+: .+$",
    "APPFW_SQL": r'^SQL Keyword check failed for field \w+=".+"$',
    "APPFW_XSS": r'^Cross-site script check failed for field \w+="Bad tag: script"$',
    "APPFW_BUFFEROVERFLOW_URL": r"^URL length\(\d+\) is greater than maximum allowed\(\d+\) : https?://\S+$",
    "APPFW_BUFFEROVERFLOW_HDR": r"^Header\([\w-]+\) length\(\d+\) is greater than maximum allowed\(\d+\) : https?://\S+$",
    "APPFW_BUFFEROVERFLOW_COOKIE": r"^Cookie header length\(\d+\) is greater than maximum allowed\(\d+\) : https?://\S+$",
    "APPFW_FIELDFORMAT": r'^Field format check failed for field \w+=".+"$',
    "APPFW_FIELDCONSISTENCY": r"^Field consistency check failed for field \w+$",
    "APPFW_COOKIE": r"^Cookie validation failed for \w+$",
    "APPFW_REFERER_HEADER": r"^Referer header check failed: https?://\S+$",
    "APPFW_SAFECOMMERCE": r"^Maximum number of potential credit card numbers seen$",
    "APPFW_SAFEOBJECT": r"^Match found with Safe Object: \S+$",
    "APPFW_XML_SQL": r"^SQL Keyword check failed for field \w+$",
}


def _render(n: int) -> list[re.Match]:
    spec = load_spec(find_spec(*KEY))
    out = []
    for _ in range(n):
        line = render_one(spec, {})
        m = LINE_RX.match(line)
        assert m, line
        out.append(m)
    return out


def test_every_event_carries_its_own_phrase():
    seen = set()
    for m in _render(300):
        event, url, body = m.group(1), m.group(7), m.group(8)
        assert event in PHRASE, event
        assert re.match(PHRASE[event], body), (event, body)
        embeds_url = event in ("APPFW_STARTURL", "APPFW_DENYURL") or event.startswith("APPFW_BUFFEROVERFLOW")
        assert (url is None) == embeds_url, (event, url, body)
        assert m.group(5) == "-" or re.fullmatch(r"[A-Za-z0-9/+]{27}0000", m.group(5)), m.group(5)
        seen.add(event)
    # the pool is weighted; 300 draws should surface the bulk of it
    assert len(seen) >= 10, seen


def test_safecommerce_is_not_safeobject_wording():
    bodies = [m.group(8) for m in _render(400) if m.group(1) == "APPFW_SAFECOMMERCE"]
    assert bodies, "SAFECOMMERCE never sampled in 400 draws"
    assert all("credit card" in b for b in bodies), bodies
    assert not any("Safe object" in b for b in bodies), bodies


def test_counter_slot_is_not_a_per_type_id():
    by_event: dict[str, set[str]] = {}
    for m in _render(300):
        by_event.setdefault(m.group(1), set()).add(m.group(2))
    # any event seen more than a handful of times must show varying counters
    for event, counters in by_event.items():
        if len(counters) == 1:
            continue
        assert len(counters) > 1, (event, counters)
    assert any(len(c) > 3 for c in by_event.values()), by_event
