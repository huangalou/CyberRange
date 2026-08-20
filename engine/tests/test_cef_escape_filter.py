"""`cef_escape` Jinja filter + the catalogs that must use it.

ArcSight parse-compat audit (2026-08-21) found three hand-written CEF
templates emitting `request=` values with bare `=` inside (query strings),
which a CEF key=value tokenizer splits into a bogus key. The filter lets a
template escape any single value without going through `cef_mapping`.
"""
from __future__ import annotations

import re

import pytest

from cyberrange import find_spec, load_spec, render_one
from cyberrange.generator import JINJA_ENV

# catalogs whose template carries a URL-ish value via `request=`
REQUEST_CATALOGS = [
    ("f5", "asm", "16.x", "violation-cef"),
    ("citrix", "netscaler", "13.x", "waf-violation"),
    ("trendmicro", "apex-one", "14.x", "web-reputation"),
]

CEF_KEY_RX = re.compile(r"(?:^|\s)([A-Za-z_][\w.]*)=((?:(?!\s[A-Za-z_][\w.]*=).)*)")


def _ext_tokens(line: str) -> dict[str, str]:
    ext = line.split("|", 8)[-1]
    return {m.group(1): m.group(2) for m in CEF_KEY_RX.finditer(ext)}


def test_filter_escapes_equals_backslash_newline():
    out = JINJA_ENV.from_string("{{ v | cef_escape }}").render(v="a=b\\c\nd")
    assert out == "a\\=b\\\\c\\nd"


def test_filter_is_idempotent_on_plain_values():
    assert JINJA_ENV.from_string("{{ v | cef_escape }}").render(v="/health") == "/health"


@pytest.mark.parametrize("key", REQUEST_CATALOGS, ids=lambda k: "/".join(k))
def test_request_value_has_no_bare_equals(key):
    spec = load_spec(find_spec(*key))
    for _ in range(40):
        line = render_one(spec, {})
        tokens = _ext_tokens(line)
        assert "request" in tokens, line
        # a bare `=` inside the value means the tokenizer would have split it
        assert not re.search(r"(?<!\\)=", tokens["request"]), tokens["request"]
        # and no bogus key that looks like a URL fragment survived
        assert not any("/" in k or "?" in k for k in tokens), list(tokens)


def test_f5_cn3_is_numeric_device_id():
    spec = load_spec(find_spec("f5", "asm", "16.x", "violation-cef"))
    line = render_one(spec, {})
    cn3 = _ext_tokens(line)["cn3"]
    assert re.fullmatch(r"-?\d+", cn3), cn3


def test_cloudtrail_cef_header_has_seven_fields():
    spec = load_spec(find_spec("aws", "cloudtrail", "2.0", "credential-abuse-teampcp-cef"))
    for _ in range(20):
        line = render_one(spec, {})
        body = line.split("CEF:", 1)[1]
        fields = re.split(r"(?<!\\)\|", body)
        # version + vendor + product + devVersion + sigId + name + severity + extension
        assert len(fields) == 8, fields[:8]
        assert re.fullmatch(r"\d{1,2}", fields[6]), fields[6]
        assert "\\|" in fields[4], fields[4]  # sigId keeps ArcSight's `<eventName>|<Outcome>` shape, escaped
