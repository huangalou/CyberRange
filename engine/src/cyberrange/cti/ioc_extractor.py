"""Regex-based IOC extraction from CTI advisory markdown.

Strategy: target high-precision patterns that match the conventions
vendors typically use in advisories — defanged domains/IPs, backticked
file paths, table-formatted package@version IOCs, header:value
fingerprints. Loose prose mentions are intentionally not extracted —
that's a job for the LLM-assisted `catalog_writer` (Phase 4.5 backlog).

Defanging conventions handled:
- ``foo[.]bar`` → ``foo.bar``
- ``1.2.3[.]4`` → ``1.2.3.4``
- ``foo(.)bar`` → ``foo.bar``
- ``foo[:]443`` → ``foo:443``
- ``hxxp://`` → ``http://`` (and ``hxxps://`` → ``https://``)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from ..schema import HttpFingerprintIoc, IocBundle, PackageVersionIoc

# ──────────────── defang patterns ────────────────

_DEFANG_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("[.]", "."),
    ("(.)", "."),
    ("[:]", ":"),
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
)


def _refang(text: str) -> str:
    """Reverse common defanging conventions."""
    for needle, replacement in _DEFANG_REPLACEMENTS:
        text = text.replace(needle, replacement)
    return text


# ──────────────── element regexes ────────────────

# Markers that flag a token as IOC (not legit reference). Defanging
# itself is the strongest marker — vendors only defang malicious
# indicators. Track which tokens were defanged in source.
_DEFANG_MARKER_RE = re.compile(r"\[\.\]|\(\.\)|\[:\]|hxxps?://", re.IGNORECASE)

_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

# Domain regex: lowercase ASCII labels, optional leading wildcard,
# at least one dot, TLD 2-24 chars. Excludes pure-IP matches.
_DOMAIN_RE = re.compile(
    r"\b(\*?\.?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)+)\b",
    re.IGNORECASE,
)

# File path inside backticks: must start with `/`, `~/`, or `*/`. The
# `*/` glob form is the canonical IOC representation in catalog YAML.
_FILE_PATH_RE = re.compile(r"`((?:[~*]?/)[^\s`]*)`")

# HTTP header inside backticks: `Header-Name: value`. Headers start
# with uppercase, contain letters/digits/hyphen.
_HTTP_FP_RE = re.compile(r"`([A-Z][A-Za-z0-9-]+):\s+([^\s`]+)`")

# Package@version table form (the most reliable): a Markdown table row
# with backticked package name in column 1 and comma-separated version
# list in column 2. e.g.:  `| `litellm` | 1.82.7, 1.82.8 | description |`
_PKG_VERSION_TABLE_RE = re.compile(
    r"\|\s*`([a-z0-9][\w.-]*)`\s*\|\s*"
    r"((?:\d+(?:\.\d+)+)(?:\s*,\s*\d+(?:\.\d+)+)*)\s*\|",
    re.IGNORECASE,
)

# Prose form fallback: ``backticked-name`` followed shortly by
# parenthesized "(version[s] X.Y.Z and A.B.C)". Less precise but covers
# common advisory phrasing.
_PKG_VERSION_PROSE_RE = re.compile(
    r"`([a-z0-9][\w.-]*)`\s*\(versions?\s+"
    r"(\d+(?:\.\d+)+(?:\s+(?:and|,)\s+\d+(?:\.\d+)+)*)\s*\)",
    re.IGNORECASE,
)


# Domains that are almost always references / sources / non-IOC. The
# extractor filters these out by default — operators can re-add via
# IocExtractor(include_clean=True) if they want raw output.
_CLEAN_DOMAINS_BUILTIN: frozenset[str] = frozenset(
    {
        "github.com",
        "pypi.org",
        "pypa.org",
        "anchore.com",
        "anthropic.com",
        "datadoghq.com",
        "securitylabs.datadoghq.com",
        "openai.com",
        "google.com",
        "microsoft.com",
        "wikipedia.org",
        "python.org",
        "docs.python.org",
        "ietf.org",
        "rfc-editor.org",
        "example.com",
        "example.org",
    }
)

# Right-most label that means "this is a filename, not a domain" —
# blocks `sysmon.service`, `ringtone.wav`, `tpcp.tar.gz` (gz catches
# the inner `.tar.gz`), etc. from polluting the domain list.
_FILE_EXTENSION_BLOCKLIST: frozenset[str] = frozenset(
    {
        # Python / config / persistence
        "py", "pth", "pyc", "pyo", "egg", "whl",
        "yaml", "yml", "json", "toml", "ini", "conf", "cfg",
        "md", "txt", "log", "csv", "tsv", "xml",
        # Shell / build
        "sh", "bash", "zsh", "fish", "ps1",
        # Archives / binaries
        "gz", "tar", "tgz", "bz2", "xz", "zip", "rar", "7z",
        "exe", "dll", "so", "dylib", "o", "a", "lib",
        "deb", "rpm", "apk", "iso", "img", "vmdk", "ova",
        # Systemd / services
        "service", "socket", "timer", "target", "mount",
        # Office / documents
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        # Web / source
        "html", "htm", "css", "js", "ts", "jsx", "tsx", "vue", "svg",
        "rs", "go", "java", "c", "cpp", "cc", "h", "hpp", "kt",
        # Media
        "png", "jpg", "jpeg", "gif", "ico", "webp", "bmp", "tiff",
        "mp3", "mp4", "avi", "mov", "webm", "ogg", "wav", "flac",
        # DB / data
        "db", "sqlite", "sqlite3", "sql", "dump",
    }
)


def _is_version_string(d: str) -> bool:
    """All labels purely numeric → it's a version, not a domain."""
    return all(label.isdigit() for label in d.split("."))


def _looks_like_filename(d: str) -> bool:
    """Right-most label is a known file extension → it's a filename."""
    last = d.rsplit(".", 1)[-1].lower()
    return last in _FILE_EXTENSION_BLOCKLIST


@dataclass(frozen=True)
class ExtractionResult:
    """Outcome of running the extractor over a markdown advisory.

    Attributes:
        iocs: schema v3 IocBundle ready to drop into a catalog's
            `cti.iocs` block.
        match_counts: per-IOC-type count of matches before deduplication.
            Useful for "Time-to-Catalog" telemetry — tells you how rich
            an advisory is before catalog drafting.
        defang_seen: True if any defanging marker (`[.]`, `(.)`,
            `hxxp://`) appeared in the text. Defanging is a strong
            signal that the document genuinely contains IOCs (vs a
            generic blog post mentioning domains).
    """

    iocs: IocBundle
    match_counts: dict[str, int] = field(default_factory=dict)
    defang_seen: bool = False


class IocExtractor:
    """Stateless extractor: text in, IocBundle out.

    Two knobs:
        clean_domains: domains to filter out (sources / references).
            Defaults to a built-in list of common references.
        include_clean: when True, skip the clean-domain filter entirely
            and emit every domain match. Useful for debugging.
    """

    def __init__(
        self,
        clean_domains: Iterable[str] | None = None,
        include_clean: bool = False,
    ) -> None:
        self._clean = (
            frozenset()
            if include_clean
            else (frozenset(d.lower() for d in clean_domains)
                  if clean_domains is not None
                  else _CLEAN_DOMAINS_BUILTIN)
        )

    def extract(self, markdown: str) -> ExtractionResult:
        defang_seen = bool(_DEFANG_MARKER_RE.search(markdown))
        refanged = _refang(markdown)

        domain_matches = self._extract_domains(refanged)
        ip_matches = self._extract_ips(refanged)
        file_path_matches = self._extract_file_paths(refanged)
        http_fp_matches = self._extract_http_fingerprints(refanged)
        pkg_ver_matches = self._extract_package_versions(refanged)

        return ExtractionResult(
            iocs=IocBundle(
                domains=sorted(set(domain_matches)),
                ips=sorted(set(ip_matches)),
                file_paths=sorted(set(file_path_matches)),
                http_fingerprints=_dedupe_http_fps(http_fp_matches),
                package_versions=_dedupe_packages(pkg_ver_matches),
            ),
            match_counts={
                "domains": len(domain_matches),
                "ips": len(ip_matches),
                "file_paths": len(file_path_matches),
                "http_fingerprints": len(http_fp_matches),
                "package_versions": len(pkg_ver_matches),
            },
            defang_seen=defang_seen,
        )

    # ──────────────── per-type extraction ────────────────

    def _extract_domains(self, text: str) -> list[str]:
        out: list[str] = []
        for m in _DOMAIN_RE.finditer(text):
            d = m.group(1).lower().rstrip(".")
            # Reject pure-numeric (IP) matches and TLD-only strings.
            if _IPV4_RE.fullmatch(d):
                continue
            if d.count(".") < 1:
                continue
            # Reject version strings (1.2.3) and filenames (foo.py).
            if _is_version_string(d):
                continue
            if _looks_like_filename(d):
                continue
            # Apex domain (last 2 labels) — used for clean filter.
            apex = ".".join(d.split(".")[-2:])
            if apex in self._clean:
                continue
            out.append(d)
        return out

    def _extract_ips(self, text: str) -> list[str]:
        return [
            ip for ip in _IPV4_RE.findall(text)
            if all(0 <= int(o) <= 255 for o in ip.split("."))
            and ip != "0.0.0.0"
            and not ip.startswith("127.")
        ]

    def _extract_file_paths(self, text: str) -> list[str]:
        return [m.group(1) for m in _FILE_PATH_RE.finditer(text)]

    def _extract_http_fingerprints(
        self, text: str
    ) -> list[tuple[str, str]]:
        return [(m.group(1), m.group(2)) for m in _HTTP_FP_RE.finditer(text)]

    def _extract_package_versions(
        self, text: str
    ) -> list[tuple[str, list[str]]]:
        out: list[tuple[str, list[str]]] = []

        # Table form (highest precision)
        for m in _PKG_VERSION_TABLE_RE.finditer(text):
            name = m.group(1).lower()
            versions = [v.strip() for v in m.group(2).split(",") if v.strip()]
            if versions:
                out.append((name, versions))

        # Prose form fallback — `name` (versions A and B)
        for m in _PKG_VERSION_PROSE_RE.finditer(text):
            name = m.group(1).lower()
            # Split on " and " or "," and clean
            raw = re.split(r"\s+and\s+|,\s*", m.group(2))
            versions = [v.strip() for v in raw if v.strip()]
            if versions:
                out.append((name, versions))

        return out


# ──────────────── helpers ────────────────


def _dedupe_http_fps(
    pairs: list[tuple[str, str]],
) -> list[HttpFingerprintIoc]:
    seen: set[tuple[str, str]] = set()
    result: list[HttpFingerprintIoc] = []
    for header, value in pairs:
        key = (header, value)
        if key in seen:
            continue
        seen.add(key)
        result.append(HttpFingerprintIoc(header=header, value=value))
    return result


def _dedupe_packages(
    pairs: list[tuple[str, list[str]]],
) -> list[PackageVersionIoc]:
    """Merge duplicate package names by union of versions, ecosystem
    defaults to pypi (the only ecosystem extractable from generic prose
    advisory text). Operators can post-edit YAML for npm/cargo/etc."""
    by_name: dict[str, set[str]] = {}
    for name, versions in pairs:
        by_name.setdefault(name, set()).update(versions)
    return [
        PackageVersionIoc(ecosystem="pypi", name=name, versions=sorted(vs))
        for name, vs in sorted(by_name.items())
    ]


# ──────────────── module-level convenience ────────────────


def extract_iocs(markdown: str) -> ExtractionResult:
    """Default-config extraction — built-in clean-domain filter."""
    return IocExtractor().extract(markdown)
