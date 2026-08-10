"""Smoke tests for owasp/modsecurity-crs/4.x/audit-json catalog.

驗 3 模式 + JSON validity + ruleId 路由正確性。
"""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from cyberrange import find_spec, load_spec, render_many, render_one


VENDOR = "owasp"
PRODUCT = "modsecurity-crs"
VERSION = "4.x"
LOG_TYPE = "audit-json"


@pytest.fixture
def spec():
    path = find_spec(VENDOR, PRODUCT, VERSION, LOG_TYPE)
    return load_spec(path)


def _parse(line: str) -> dict:
    """Parse a rendered line and assert it's valid JSON."""
    return json.loads(line)


def test_spec_loads(spec):
    assert spec.vendor == VENDOR
    assert spec.format == "json"
    assert "udp_syslog" in spec.transport


def test_realistic_renders_valid_json(spec):
    for line in render_many(spec, 5):
        obj = _parse(line)
        assert "transaction" in obj
        assert obj["transaction"]["request"]["method"]
        msgs = obj["transaction"]["messages"]
        assert isinstance(msgs, list) and len(msgs) >= 1


def test_realistic_messages_contain_anomaly_meta(spec):
    """每筆 attack 都該帶 949110 anomaly score(對齊 production 行為)。"""
    line = render_one(spec)
    obj = _parse(line)
    msgs = obj["transaction"]["messages"]
    primary = msgs[0]["details"]["ruleId"]
    if primary in ("949110", "980130"):
        # anomaly meta-rule as primary,只有一條 message
        assert len(msgs) == 1
    else:
        # attack rule + 949110 meta = 2 conditions
        assert len(msgs) == 2
        assert msgs[1]["details"]["ruleId"] == "949110"


def test_realistic_distribution_top_rules_dominate(spec):
    """1000 樣本內,920350 + 930130 應佔 > 50%(production 是 ~72%)。"""
    counter: Counter[str] = Counter()
    for line in render_many(spec, 1000):
        obj = _parse(line)
        primary = obj["transaction"]["messages"][0]["details"]["ruleId"]
        counter[primary] += 1
    top_two_share = (counter["920350"] + counter["930130"]) / 1000
    assert top_two_share > 0.5, f"top-two share {top_two_share:.2f} too low"


def test_coverage_mode_hits_most_rule_ids(spec):
    """coverage 跑 500 樣本,期望 60 attack + 2 anomaly 全打到。"""
    seen: set[str] = set()
    for line in render_many(spec, 500, params={"mode": "coverage"}):
        obj = _parse(line)
        for m in obj["transaction"]["messages"]:
            seen.add(m["details"]["ruleId"])
    attack_seen = seen - {"949110", "980130"}
    anomaly_seen = seen & {"949110", "980130"}
    assert len(attack_seen) >= 58, f"only {len(attack_seen)}/60 attack ruleIds covered"
    assert anomaly_seen == {"949110", "980130"}, f"anomaly meta missing: {anomaly_seen}"


def test_single_mode_pins_rule_id(spec):
    line = render_one(spec, params={"mode": "single", "rule_id": "942550"})
    obj = _parse(line)
    primary = obj["transaction"]["messages"][0]["details"]["ruleId"]
    assert primary == "942550"


def test_single_mode_anomaly_only_branch(spec):
    """rule_id=949110 in single mode 只產 1 條 message(沒有 attack rule)。"""
    line = render_one(spec, params={"mode": "single", "rule_id": "949110"})
    obj = _parse(line)
    msgs = obj["transaction"]["messages"]
    assert len(msgs) == 1
    assert msgs[0]["details"]["ruleId"] == "949110"


def test_audit_json_shape_matches_real(spec):
    """Required keys aligned to a real production audit.log shape."""
    line = render_one(spec, params={"mode": "single", "rule_id": "942100"})
    obj = _parse(line)
    t = obj["transaction"]
    assert "client_ip" in t
    assert "time_stamp" in t
    assert "unique_id" in t
    assert "host_ip" in t
    assert "host_port" in t
    assert "request" in t
    assert "response" in t
    assert "producer" in t
    assert t["producer"]["modsecurity"].startswith("ModSecurity v3")
    assert t["producer"]["secrules_engine"] in ("DetectionOnly", "On")
    msg = t["messages"][0]
    assert msg["details"]["ruleId"] == "942100"
    assert msg["details"]["file"].startswith("/etc/modsecurity.d/owasp-crs/rules/REQUEST-942-")
    assert "attack-sqli" in msg["details"]["tags"]


def test_data_excerpt_renders_per_family(spec):
    """sqli ruleId 抽出的 data 該帶 SQL 攻擊樣態(quote / UNION / etc.)。"""
    line = render_one(spec, params={"mode": "single", "rule_id": "942100"})
    obj = _parse(line)
    data = obj["transaction"]["messages"][0]["details"]["data"]
    assert "Matched Data:" in data
    payload = data.replace("Matched Data: ", "")
    assert any(tok in payload for tok in ["'", "UNION", "OR"]), (
        f"sqli payload pattern not detected: {payload!r}"
    )


def test_no_unrendered_jinja_placeholders(spec):
    placeholder = re.compile(r"\{\{\s*\w+\s*\}\}")
    for line in render_many(spec, 50, params={"mode": "coverage"}):
        assert not placeholder.search(line), f"unrendered placeholder: {line!r}"


def test_single_line_per_transaction(spec):
    """每筆 transaction 必須是單行(syslog UDP 友善)。"""
    for line in render_many(spec, 20):
        assert "\n" not in line.rstrip("\n"), f"multiline output: {line!r}"
