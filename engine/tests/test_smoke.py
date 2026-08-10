"""Smoke tests: catalog loads, every spec renders one sample without error."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from cyberrange import (
    CATALOG_ROOT,
    find_spec,
    list_specs,
    load_spec,
    render_many,
    render_one,
)


def test_catalog_root_exists():
    assert CATALOG_ROOT.exists(), f"catalog root missing: {CATALOG_ROOT}"


def test_list_specs_finds_at_least_two():
    specs = list(list_specs())
    assert len(specs) >= 2, f"expected ≥2 specs, found {len(specs)}"


def test_every_spec_in_catalog_renders_without_error():
    """Walk every catalog YAML, render 3 samples, ensure no exceptions
    and no leftover Jinja placeholders."""
    specs = list(list_specs())
    assert specs, "catalog is empty"
    placeholder = re.compile(r"\{\{\s*\w+\s*\}\}")
    for path, spec in specs:
        try:
            samples = list(render_many(spec, 3))
        except Exception as e:
            raise AssertionError(f"render failed for {path}: {e}") from e
        assert len(samples) == 3
        for s in samples:
            assert s, f"empty sample from {path}"
            assert not placeholder.search(s), (
                f"unrendered placeholder in {path}: {s!r}"
            )


@pytest.mark.parametrize(
    "vendor,product,version,log_type",
    [
        ("fortinet", "fortios", "7.4", "traffic.forward"),
        ("microsoft", "windows", "2022", "sysmon.event_id_1"),
    ],
)
def test_each_spec_renders(vendor, product, version, log_type):
    path = find_spec(vendor, product, version, log_type)
    spec = load_spec(path)
    line = render_one(spec)
    assert line, f"empty render for {log_type}"
    # detect leftover Jinja2 placeholders like {{ var }} or {{var}}
    assert not re.search(r"\{\{\s*\w+\s*\}\}", line), (
        f"unrendered Jinja placeholder in {log_type}: {line!r}"
    )


def test_fortinet_traffic_shape():
    path = find_spec("fortinet", "fortios", "7.4", "traffic.forward")
    spec = load_spec(path)
    line = render_one(spec)
    # PRI prefix
    assert re.match(r"^<\d+>", line), f"missing PRI: {line!r}"
    # Required Fortinet keys
    for key in ("logid=", "type=\"traffic\"", "subtype=\"forward\"", "srcip=", "dstip=", "action="):
        assert key in line, f"missing {key!r} in: {line!r}"


def test_sysmon_json_parses():
    path = find_spec("microsoft", "windows", "2022", "sysmon.event_id_1")
    spec = load_spec(path)
    line = render_one(spec)
    # Strip syslog PRI + RFC3164 ts + host prefix to expose JSON
    json_start = line.index("{")
    payload = line[json_start:]
    parsed = json.loads(payload)
    assert parsed["event"]["code"] == 1
    assert parsed["winlog"]["event_id"] == 1
    assert parsed["winlog"]["event_data"]["Image"].startswith("C:\\")


def test_render_many_count():
    path = find_spec("fortinet", "fortios", "7.4", "traffic.forward")
    spec = load_spec(path)
    lines = list(render_many(spec, 5))
    assert len(lines) == 5
    # Each line independent: srcip / sessionid likely differ across 5 samples
    sessionids = {re.search(r"sessionid=(\d+)", l).group(1) for l in lines}
    assert len(sessionids) > 1, "expected variance across 5 samples"


def test_param_override():
    path = find_spec("fortinet", "fortios", "7.4", "traffic.forward")
    spec = load_spec(path)
    line = render_one(spec, params={"src_cidr": "192.168.99.0/24"})
    srcip = re.search(r"srcip=(\d+\.\d+\.\d+\.\d+)", line).group(1)
    assert srcip.startswith("192.168.99."), f"param override failed, got {srcip}"
