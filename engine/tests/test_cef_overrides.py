"""CEF customizable mapping — v4 schema tests.

Covers:
  1. Backward compat — every existing catalog still renders without
     touching the new code path (cef_mapping is None)
  2. PA traffic-cef default render — required keys present
  3. Override cef_key only (relocate value to a different CEF extension)
  4. Override value only (pin literal, generator bypassed)
  5. Override both (relocate + pin)
  6. Ad-hoc — pa_field not in cef_mapping, but override provides both
     cef_key + value → appended to body end
  7. Header override (CEF v0 header section)
  8. CEF escape rules — `=` / `\\` / `\\n` in values
  9. Duplicate cef_key — two pa_fields remap to same key, both emitted
"""
from __future__ import annotations

import re

import pytest

from cyberrange import find_spec, list_specs, load_spec, render_one


PA_TRAFFIC_CEF = ("paloalto", "panos", "10.0", "traffic-cef")


def _load_pa_traffic_cef():
    path = find_spec(*PA_TRAFFIC_CEF)
    return load_spec(path)


# ──────────────── #1 backward compat ────────────────


def test_existing_catalogs_unaffected_by_cef_path():
    """Every spec without cef_mapping must render exactly as before —
    no spurious `cef_extensions=` / `cef_header=` leakage, no Jinja
    placeholder leftovers, no exceptions."""
    placeholder = re.compile(r"\{\{\s*\w+\s*\}\}")
    skipped_pa_cef = False
    for path, spec in list_specs():
        if spec.cef_mapping is not None:
            # PA traffic-cef is the only one (so far) — leave it for test #2
            skipped_pa_cef = True
            continue
        line = render_one(spec)
        assert line, f"empty render for {path}"
        assert not placeholder.search(line), (
            f"unrendered Jinja in {path}: {line!r}"
        )
    assert skipped_pa_cef, "expected PA traffic-cef to exist as a v4 catalog"


# ──────────────── #2 PA traffic-cef default ────────────────


def test_pa_traffic_cef_default_render():
    spec = _load_pa_traffic_cef()
    line = render_one(spec)
    # PRI + RFC3164 header
    assert line.startswith("<134>")
    # CEF v0 header (pipe-separated, 7 fields after CEF:0)
    assert "CEF:0|Palo Alto Networks|PAN-OS|10.0.0|" in line
    assert "|TRAFFIC|3|" in line
    # Required PA-10.0 default extension keys
    for key in ("rt=", "src=", "dst=", "spt=", "dpt=", "app=", "act=", "proto="):
        assert key in line, f"missing {key!r} in default render: {line!r}"


# ──────────────── #3 override cef_key only ────────────────


def test_override_cef_key_only_relocates_value():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={"application": {"cef_key": "cs1"}},
    )
    # `app=...` must vanish, replaced by `cs1=...`
    assert "cs1=" in line
    assert " app=" not in line, "default `app=` slot should be gone"


# ──────────────── #4 override value only ────────────────


def test_override_value_only_pins_literal():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={"dst_ip": {"value": "8.8.4.4"}},
    )
    assert "dst=8.8.4.4" in line


# ──────────────── #5 override both ────────────────


def test_override_both_relocates_and_pins():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={
            "action": {"cef_key": "cs2", "value": "drop"},
        },
    )
    assert "cs2=drop" in line
    assert " act=" not in line, "default `act=` slot should be gone"


# ──────────────── #6 ad-hoc extension (not in cef_mapping) ────────────────


def test_adhoc_extension_appended():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={
            "custom_field": {"cef_key": "cs10", "value": "hello"},
        },
    )
    assert "cs10=hello" in line


def test_adhoc_extension_missing_cef_key_is_skipped():
    """An override targeting an unknown pa_field without BOTH key+value
    is silently dropped (logged warning, no exception)."""
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={
            "ghost": {"value": "x"},  # no cef_key → skip
        },
    )
    # No crash, output rendered
    assert line


# ──────────────── #7 CEF header override ────────────────


def test_cef_header_override_changes_version_and_name():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_header_overrides={
            "device_version": "11.2.0",
            "name": "TRAFFIC-CUSTOM",
        },
    )
    assert "|11.2.0|" in line
    assert "|TRAFFIC-CUSTOM|" in line
    assert "CEF:0|Palo Alto Networks|PAN-OS|11.2.0|" in line


# ──────────────── #8 CEF escape ────────────────


def test_cef_escape_handles_special_chars():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={
            "application": {"value": "weird=app\\name\nwith-newline"},
        },
    )
    # `=` → `\=`, `\` → `\\`, `\n` → `\\n`
    assert "app=weird\\=app\\\\name\\nwith-newline" in line, (
        f"escape failed in: {line!r}"
    )


# ──────────────── #9 duplicate cef_key ────────────────


def test_duplicate_cef_key_emits_both():
    spec = _load_pa_traffic_cef()
    line = render_one(
        spec,
        cef_extension_overrides={
            "src_ip": {"cef_key": "cs1"},
            "dst_ip": {"cef_key": "cs1"},
        },
    )
    # Both should be present; count of "cs1=" should be 2
    cs1_count = line.count(" cs1=") + (1 if line.startswith("cs1=") else 0)
    assert cs1_count == 2, f"expected 2x cs1= in body: {line!r}"
    # Original src= / dst= slots gone
    assert " src=" not in line
    assert " dst=" not in line
