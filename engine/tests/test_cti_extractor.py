"""Tests for `cyberrange.cti.ioc_extractor` — regex-based IOC extraction."""
from __future__ import annotations

from pathlib import Path

import pytest

from cyberrange.cti import IocExtractor, extract_iocs
from cyberrange.cti.ioc_extractor import _refang
from cyberrange.schema import HttpFingerprintIoc, PackageVersionIoc


FIXTURE = Path(__file__).parent / "fixtures" / "teampcp-advisory-excerpt.md"


@pytest.fixture(scope="module")
def teampcp_text() -> str:
    return FIXTURE.read_text(encoding="utf-8")


# ──────────────── _refang ────────────────


@pytest.mark.unit
def test_refang_dot_brackets():
    assert _refang("models.litellm[.]cloud") == "models.litellm.cloud"
    assert _refang("83.142.209[.]203") == "83.142.209.203"


@pytest.mark.unit
def test_refang_hxxp_scheme():
    assert _refang("hxxp://attacker.example") == "http://attacker.example"
    assert _refang("hxxps://attacker.example") == "https://attacker.example"


@pytest.mark.unit
def test_refang_paren_dots_and_colon_brackets():
    assert _refang("foo(.)bar") == "foo.bar"
    assert _refang("foo[:]443") == "foo:443"


@pytest.mark.unit
def test_refang_idempotent():
    """Running refang twice on already-clean text shouldn't damage it."""
    clean = "https://example.com:443/path"
    assert _refang(_refang(clean)) == clean


# ──────────────── domain extraction ────────────────


@pytest.mark.unit
def test_extract_teampcp_domains_complete(teampcp_text):
    result = extract_iocs(teampcp_text)
    assert "models.litellm.cloud" in result.iocs.domains
    assert "checkmarx.zone" in result.iocs.domains
    assert "aquasecurtiy.org" in result.iocs.domains
    assert "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io" in result.iocs.domains


@pytest.mark.unit
def test_extract_filters_clean_reference_domains(teampcp_text):
    """github.com / anchore.com / pypa.org are reference mentions, not
    IOCs — must be filtered by the built-in clean-domain list."""
    result = extract_iocs(teampcp_text)
    for clean in ("github.com", "anchore.com", "pypa.org",
                  "securitylabs.datadoghq.com"):
        assert clean not in result.iocs.domains, (
            f"{clean} should be filtered as clean reference"
        )


@pytest.mark.unit
def test_domain_filter_rejects_version_strings():
    """Version strings (`1.82.7`, `4.87.2`) syntactically look like
    multi-label domains. The extractor must reject them."""
    text = "Backdoored versions are 1.82.7, 1.82.8, and 4.87.1."
    result = extract_iocs(text)
    assert "1.82.7" not in result.iocs.domains
    assert "1.82.8" not in result.iocs.domains
    assert "4.87.1" not in result.iocs.domains


@pytest.mark.unit
def test_domain_filter_rejects_filenames():
    """File paths in backticks like `sysmon.py`, `tpcp.tar.gz` would
    syntactically pass the domain regex but the right-most label is a
    file extension. Must be filtered."""
    text = "Drops `sysmon.py`, `sysmon.service`, `tpcp.tar.gz`, `ringtone.wav`."
    result = extract_iocs(text)
    for fname in ("sysmon.py", "sysmon.service", "tpcp.tar.gz",
                  "ringtone.wav", "tar.gz", "report.pdf"):
        assert fname not in result.iocs.domains


@pytest.mark.unit
def test_extracted_domains_are_clean_for_teampcp(teampcp_text):
    """Sanity check: post-filter, every extracted domain looks like a
    real C2/exfil endpoint — no version, no filename, no reference."""
    result = extract_iocs(teampcp_text)
    assert len(result.iocs.domains) >= 3
    for d in result.iocs.domains:
        # No purely-numeric labels
        assert not all(lbl.isdigit() for lbl in d.split("."))
        # No filename-style suffix
        assert not d.endswith((".py", ".service", ".gz", ".wav", ".pth"))


@pytest.mark.unit
def test_include_clean_disables_filter(teampcp_text):
    """include_clean=True → emit raw matches, including reference URLs.
    The fixture mentions `anchore.com` as a reference, which the default
    filter strips but include_clean=True must let through."""
    default_result = extract_iocs(teampcp_text)
    raw_result = IocExtractor(include_clean=True).extract(teampcp_text)
    assert "anchore.com" not in default_result.iocs.domains
    assert "anchore.com" in raw_result.iocs.domains


# ──────────────── IP extraction ────────────────


@pytest.mark.unit
def test_extract_teampcp_ips_complete(teampcp_text):
    result = extract_iocs(teampcp_text)
    expected = {"83.142.209.203", "83.142.209.11", "46.151.182.203"}
    assert expected.issubset(set(result.iocs.ips))


@pytest.mark.unit
def test_ip_extractor_validates_octets():
    """999.999.999.999 must NOT be accepted as an IP."""
    text = "Contact us at 999.999.999.999 if needed."
    result = extract_iocs(text)
    assert "999.999.999.999" not in result.iocs.ips


@pytest.mark.unit
def test_ip_extractor_filters_loopback_and_zero():
    text = "Server bound to 127.0.0.1 or 0.0.0.0 by default."
    result = extract_iocs(text)
    assert "127.0.0.1" not in result.iocs.ips
    assert "0.0.0.0" not in result.iocs.ips


# ──────────────── file path extraction ────────────────


@pytest.mark.unit
def test_extract_teampcp_file_paths(teampcp_text):
    result = extract_iocs(teampcp_text)
    expected = {
        "*/litellm_init.pth",
        "*/.config/sysmon/sysmon.py",
        "*/.config/systemd/user/sysmon.service",
        "/tmp/pglog",
        "/tmp/.pg_state",
    }
    assert expected.issubset(set(result.iocs.file_paths))


@pytest.mark.unit
def test_file_path_requires_path_prefix():
    """Bare filenames (no `/`, `~/`, or `*/` prefix) shouldn't match."""
    text = "The malware drops `litellm_init.pth` somewhere."
    result = extract_iocs(text)
    assert result.iocs.file_paths == []


# ──────────────── HTTP fingerprint extraction ────────────────


@pytest.mark.unit
def test_extract_teampcp_http_fingerprints(teampcp_text):
    result = extract_iocs(teampcp_text)
    assert HttpFingerprintIoc(
        header="X-Filename", value="tpcp.tar.gz"
    ) in result.iocs.http_fingerprints


@pytest.mark.unit
def test_http_fingerprint_dedupe():
    """Same Header:value declared twice → emit once."""
    text = (
        "Look for `X-Filename: tpcp.tar.gz`. Repeat: `X-Filename: tpcp.tar.gz`."
    )
    result = extract_iocs(text)
    assert len(result.iocs.http_fingerprints) == 1


# ──────────────── package version extraction ────────────────


@pytest.mark.unit
def test_extract_teampcp_package_versions_table_form(teampcp_text):
    result = extract_iocs(teampcp_text)
    by_name = {p.name: p for p in result.iocs.package_versions}
    assert "litellm" in by_name
    assert set(by_name["litellm"].versions) == {"1.82.7", "1.82.8"}
    assert by_name["litellm"].ecosystem == "pypi"
    assert "telnyx" in by_name
    assert set(by_name["telnyx"].versions) == {"4.87.1", "4.87.2"}


@pytest.mark.unit
def test_extract_package_versions_prose_form():
    """Prose form `name` (versions A and B) must also extract."""
    text = (
        "Backdoored releases of `nasty-pkg` (versions 1.0.1 and 1.0.2) "
        "were published."
    )
    result = extract_iocs(text)
    pkgs = {p.name: p for p in result.iocs.package_versions}
    assert "nasty-pkg" in pkgs
    assert set(pkgs["nasty-pkg"].versions) == {"1.0.1", "1.0.2"}


@pytest.mark.unit
def test_package_version_dedupe_unions_versions():
    """Same package referenced twice with different versions → versions
    union, single PackageVersionIoc emitted."""
    text = (
        "First mention: ``| `pkg` | 1.0, 1.1 | yes |`` and later prose:\n"
        "`pkg` (versions 1.1 and 1.2)."
    )
    result = extract_iocs(text)
    pkgs = [p for p in result.iocs.package_versions if p.name == "pkg"]
    assert len(pkgs) == 1
    assert set(pkgs[0].versions) == {"1.0", "1.1", "1.2"}


# ──────────────── ExtractionResult metadata ────────────────


@pytest.mark.unit
def test_extraction_result_match_counts(teampcp_text):
    result = extract_iocs(teampcp_text)
    assert result.match_counts["ips"] >= 3
    assert result.match_counts["file_paths"] >= 5
    assert result.match_counts["domains"] >= 4


@pytest.mark.unit
def test_extraction_result_defang_seen_true_for_advisory(teampcp_text):
    """TeamPCP advisory is heavily defanged ([.] and hxxp://) — flag must trip."""
    result = extract_iocs(teampcp_text)
    assert result.defang_seen is True


@pytest.mark.unit
def test_extraction_result_defang_seen_false_for_clean_text():
    text = "No IOCs here, just plain text and https://example.com."
    result = extract_iocs(text)
    assert result.defang_seen is False


# ──────────────── output is schema v3 IocBundle ────────────────


@pytest.mark.unit
def test_extracted_iocs_can_be_dropped_into_catalog_block(teampcp_text):
    """The extractor's IocBundle must be the same type as the schema v3
    cti.iocs field — operators copy-paste extractor output into a new
    catalog YAML's cti.iocs block."""
    from cyberrange.schema import IocBundle  # local import to avoid cycle

    result = extract_iocs(teampcp_text)
    assert isinstance(result.iocs, IocBundle)
    # Round-trip via dict (what YAML serialization would do)
    bundle_dict = result.iocs.model_dump()
    rebuilt = IocBundle.model_validate(bundle_dict)
    assert rebuilt == result.iocs


@pytest.mark.unit
def test_extracted_package_version_uses_pypi_ecosystem_default(teampcp_text):
    """Advisory text doesn't carry ecosystem metadata — extractor
    defaults to pypi (the dominant ecosystem in TeamPCP-style PyPI
    compromise advisories)."""
    result = extract_iocs(teampcp_text)
    for pkg in result.iocs.package_versions:
        assert isinstance(pkg, PackageVersionIoc)
        assert pkg.ecosystem == "pypi"
