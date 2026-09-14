"""McAfee ePO av-detect siblings — backslash fidelity on the wire.

Phase 1 (2026-08) flagged the av-detect pair: the native XML sibling was
emitting `DOMAIN\\\\alice` (two backslashes) while the byte-fetched Sekoia
XML samples and the Wazuh PR #467 forwarder line both carry a single
backslash (XML has no backslash escaping). The CEF sibling had the
opposite bug: path values went out with a bare `\\`, which the CEF spec
requires to be escaped as `\\\\`. exploit-prevent.yaml already got this
right; these tests pin all three to the same rule.
"""
from __future__ import annotations

import re

import pytest

from cyberrange import find_spec, load_spec, render_one

XML_KEY = ("mcafee", "epo", "5.10", "av-detect")
CEF_KEY = ("mcafee", "epo", "5.10", "av-detect-cef")
EXP_KEY = ("mcafee", "epo", "5.10", "exploit-prevent")

CEF_KEY_RX = re.compile(r"(?:^|\s)([A-Za-z_][\w.]*)=((?:(?!\s[A-Za-z_][\w.]*=).)*)")
WIN_PATH_RX = re.compile(r"^[A-Z]:\\(?:[^\\]+\\)*[^\\]+$")


def _xml_tag(line: str, tag: str) -> str:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", line)
    assert m, (tag, line)
    return m.group(1)


def _ext_tokens(line: str) -> dict[str, str]:
    ext = line.split("|", 8)[-1]
    return {m.group(1): m.group(2) for m in CEF_KEY_RX.finditer(ext)}


def _cef_unescape(v: str) -> str:
    return re.sub(r"\\([\\=|\n])", r"\1", v.replace("\\n", "\n"))


@pytest.fixture(scope="module")
def xml_lines():
    spec = load_spec(find_spec(*XML_KEY))
    return [render_one(spec, {}) for _ in range(60)]


@pytest.fixture(scope="module")
def cef_lines():
    spec = load_spec(find_spec(*CEF_KEY))
    return [render_one(spec, {}) for _ in range(60)]


def test_xml_sibling_never_doubles_backslashes(xml_lines):
    for line in xml_lines:
        assert "\\\\" not in line, line


@pytest.mark.parametrize("tag", ["TargetUserName", "TargetFileName", "SourceProcessName"])
def test_xml_sibling_backslash_fields_are_single(xml_lines, tag):
    for line in xml_lines:
        val = _xml_tag(line, tag)
        assert "\\" in val, (tag, val)
        if tag == "TargetUserName":
            assert re.fullmatch(r"[A-Z0-9_-]+\\[A-Za-z0-9_.-]+", val), val
        else:
            assert WIN_PATH_RX.match(val), val


def test_xml_sibling_matches_exploit_prevent_domain_user_shape(xml_lines):
    exp = load_spec(find_spec(*EXP_KEY))
    exp_user = next(
        _xml_tag(l, "SourceUserName")
        for l in (render_one(exp, {}) for _ in range(200))
        if "<SourceUserName>" in l
    )
    ref = _xml_tag(xml_lines[0], "TargetUserName")
    assert exp_user.count("\\") == ref.count("\\") == 1, (exp_user, ref)


@pytest.mark.parametrize("key", ["duser", "suser", "filePath", "sproc"])
def test_cef_sibling_escapes_every_backslash(cef_lines, key):
    for line in cef_lines:
        val = _ext_tokens(line)[key]
        # every backslash on the wire must be part of an escape pair
        assert not re.search(r"(?<!\\)\\(?!\\)", val.replace("\\\\", "")), (key, val)
        assert "\\\\" in val, (key, val)


@pytest.mark.parametrize("key", ["filePath", "sproc"])
def test_cef_sibling_unescapes_to_windows_path(cef_lines, key):
    for line in cef_lines:
        raw = _cef_unescape(_ext_tokens(line)[key])
        assert WIN_PATH_RX.match(raw), (key, raw)


def test_cef_fname_is_basename_of_filepath(cef_lines):
    for line in cef_lines:
        t = _ext_tokens(line)
        assert t["fname"] == _cef_unescape(t["filePath"]).rsplit("\\", 1)[-1], t["filePath"]


def test_cef_and_xml_siblings_share_path_pools(xml_lines, cef_lines):
    xml_paths = {_xml_tag(l, "TargetFileName") for l in xml_lines}
    cef_paths = {_cef_unescape(_ext_tokens(l)["filePath"]) for l in cef_lines}
    assert cef_paths <= xml_paths | cef_paths and xml_paths & cef_paths, (xml_paths, cef_paths)
