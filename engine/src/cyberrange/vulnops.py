"""VulnOps × DetectOps reverse-lookup.

Phase 5.5 entry point. Maps "X has been patched / quarantined / KEV-
listed → which catalogs (and therefore which detection rules) must I
re-run for regression?"

Backed by schema-v3 ``vulnops`` + ``cti`` blocks:

- ``vulnops.cve_refs``           — CVE ids this catalog covers
- ``vulnops.affects[]``          — (ecosystem, product, version_range) tuples
- ``vulnops.regression_critical``— P0 triage flag
- ``cti.advisory_id``            — PYSEC / GHSA / CVE id of source advisory
- ``cti.related_campaign``       — campaign slug for chain-playbook joins

Public API:

- ``query(*, cve, advisory_id, package, campaign, specs=None)``
  → ``list[CatalogMatch]``
- ``PackageQuery`` for parsing the ``"eco:name[:version]"`` CLI shape.

Multiple query keywords are **union**ed — a catalog matches if any
single keyword hits — so SOC operators get the widest possible
regression surface from one invocation. The ``matched_by`` field on
``CatalogMatch`` records which keyword(s) each catalog matched, so it
is clear *why* a catalog landed in the result set.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional, Union

from .loader import CATALOG_ROOT, list_specs
from .schema import AffectsSpec, CatalogSpec


# ──────────────── package-spec parsing ────────────────


@dataclass(frozen=True)
class PackageQuery:
    """Parsed ``ecosystem:name[:version]`` query token."""

    ecosystem: str
    name: str
    version: Optional[str] = None

    @classmethod
    def parse(cls, raw: str) -> "PackageQuery":
        parts = raw.split(":")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError(
                f"package query must be 'ecosystem:name[:version]', "
                f"got {raw!r}"
            )
        if len(parts) > 3:
            raise ValueError(
                f"package query has too many colons (max 3 parts): {raw!r}"
            )
        return cls(
            ecosystem=parts[0].lower(),
            name=parts[1].lower(),
            version=parts[2] if len(parts) == 3 else None,
        )

    def token(self) -> str:
        """Stable string token used in ``CatalogMatch.matched_by``."""
        v = f":{self.version}" if self.version else ""
        return f"package:{self.ecosystem}:{self.name}{v}"


# ──────────────── result type ────────────────


@dataclass(frozen=True)
class CatalogMatch:
    """One catalog matched by a vulnops query."""

    path: str                              # rel to catalog root
    log_type: str
    vendor: str
    product: str
    version: str
    advisory_id: Optional[str]
    related_campaign: Optional[str]
    regression_critical: bool
    matched_by: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# ──────────────── version match ────────────────


def _version_matches(range_str: str, target: Optional[str]) -> bool:
    """Match a target version against the comma-separated exact-version
    list catalogs currently use.

    Conventions:
      - ``target is None``  → True (callers querying without a version
        pin want any version of the package to count)
      - ``range_str == '*'`` → True (catalog author asserts every
        version is affected; semver-range syntax is a future hook)
      - otherwise: split on commas, exact string match
    """
    if target is None:
        return True
    if range_str.strip() == "*":
        return True
    versions = {v.strip() for v in range_str.split(",") if v.strip()}
    return target in versions


def _affect_matches(
    affect: AffectsSpec, pq: PackageQuery,
) -> bool:
    return (
        affect.vendor.lower() == pq.ecosystem
        and affect.product.lower() == pq.name
        and _version_matches(affect.version_range, pq.version)
    )


# ──────────────── single-spec match ────────────────


def _match_one(
    catalog_path: Path,
    spec: CatalogSpec,
    *,
    cves: list[str],
    advisory_ids: list[str],
    packages: list[PackageQuery],
    campaigns: list[str],
    catalog_root: Path,
) -> Optional[CatalogMatch]:
    matched: list[str] = []

    if cves:
        spec_cves: set[str] = set()
        if spec.vulnops:
            spec_cves.update(spec.vulnops.cve_refs)
        if spec.cti:
            spec_cves.update(spec.cti.cve_refs)
        for cve in cves:
            if cve in spec_cves:
                matched.append(f"cve:{cve}")

    if advisory_ids and spec.cti and spec.cti.advisory_id:
        for adv in advisory_ids:
            if adv == spec.cti.advisory_id:
                matched.append(f"advisory:{adv}")

    if packages and spec.vulnops:
        for pq in packages:
            if any(_affect_matches(a, pq) for a in spec.vulnops.affects):
                matched.append(pq.token())

    if campaigns and spec.cti and spec.cti.related_campaign:
        for camp in campaigns:
            if camp == spec.cti.related_campaign:
                matched.append(f"campaign:{camp}")

    if not matched:
        return None

    try:
        rel = catalog_path.relative_to(catalog_root).as_posix()
    except ValueError:
        rel = catalog_path.as_posix()

    return CatalogMatch(
        path=rel,
        log_type=spec.log_type,
        vendor=spec.vendor,
        product=spec.product,
        version=spec.version,
        advisory_id=spec.cti.advisory_id if spec.cti else None,
        related_campaign=(
            spec.cti.related_campaign if spec.cti else None
        ),
        regression_critical=(
            bool(spec.vulnops and spec.vulnops.regression_critical)
        ),
        matched_by=tuple(matched),
    )


# ──────────────── public query ────────────────


def query(
    *,
    cve: Optional[Iterable[str]] = None,
    advisory_id: Optional[Iterable[str]] = None,
    package: Optional[Iterable[Union[str, PackageQuery]]] = None,
    campaign: Optional[Iterable[str]] = None,
    catalog_root: Path = CATALOG_ROOT,
    specs: Optional[Iterable[tuple[Path, CatalogSpec]]] = None,
) -> list[CatalogMatch]:
    """Reverse-lookup catalogs from VulnOps / CTI keywords.

    All keyword args accept an iterable for repeatability. Match
    semantics are **union** across keywords: a catalog appears if it
    matches any single keyword. ``matched_by`` on the result records
    which keyword(s) hit.

    Returns ``[]`` when every keyword is empty/None — refusing to
    enumerate the entire catalog with no filter is intentional, so an
    unbounded SOC dashboard query doesn't shadow a real reverse-lookup.
    """
    cves = list(cve or [])
    advisory_ids = list(advisory_id or [])
    campaigns = list(campaign or [])
    packages: list[PackageQuery] = []
    for p in package or []:
        packages.append(p if isinstance(p, PackageQuery)
                        else PackageQuery.parse(p))

    if not (cves or advisory_ids or campaigns or packages):
        return []

    if specs is None:
        specs = list_specs(catalog_root)

    matches: list[CatalogMatch] = []
    for path, spec in specs:
        m = _match_one(
            path, spec,
            cves=cves, advisory_ids=advisory_ids,
            packages=packages, campaigns=campaigns,
            catalog_root=catalog_root,
        )
        if m is not None:
            matches.append(m)

    # P0 first, then advisory_id then path for stable output
    return sorted(
        matches,
        key=lambda m: (
            not m.regression_critical,
            m.advisory_id or "",
            m.path,
        ),
    )


# ──────────────── summary ────────────────


@dataclass(frozen=True)
class QuerySummary:
    """Aggregate stats over a query result for at-a-glance triage."""

    catalog_count: int
    p0_count: int
    by_advisory: dict[str, int] = field(default_factory=dict)
    by_campaign: dict[str, int] = field(default_factory=dict)
    by_vendor_product: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def summarize(matches: list[CatalogMatch]) -> QuerySummary:
    by_adv: dict[str, int] = {}
    by_camp: dict[str, int] = {}
    by_vp: dict[str, int] = {}
    p0 = 0
    for m in matches:
        if m.regression_critical:
            p0 += 1
        if m.advisory_id:
            by_adv[m.advisory_id] = by_adv.get(m.advisory_id, 0) + 1
        if m.related_campaign:
            by_camp[m.related_campaign] = (
                by_camp.get(m.related_campaign, 0) + 1
            )
        vp = f"{m.vendor}/{m.product}"
        by_vp[vp] = by_vp.get(vp, 0) + 1

    return QuerySummary(
        catalog_count=len(matches),
        p0_count=p0,
        by_advisory=by_adv,
        by_campaign=by_camp,
        by_vendor_product=by_vp,
    )


# ──────────────── formatting ────────────────


def format_table(matches: list[CatalogMatch]) -> str:
    """Pretty-print matches as a fixed-width table.

    Columns: pri | matched_by | catalog
    """
    if not matches:
        return "(no catalogs match the query)\n"

    rows: list[tuple[str, ...]] = [
        (
            "P0" if m.regression_critical else "  ",
            " ".join(m.matched_by),
            m.path,
        )
        for m in matches
    ]
    headers = ("pri", "matched_by", "catalog")
    widths = [
        max(len(h), *(len(r[i]) for r in rows))
        for i, h in enumerate(headers)
    ]

    def fmt(parts: tuple[str, ...]) -> str:
        return "  ".join(p.ljust(widths[i]) for i, p in enumerate(parts))

    lines = [fmt(headers), fmt(tuple("-" * w for w in widths))]
    lines.extend(fmt(r) for r in rows)
    return "\n".join(lines) + "\n"


def to_json(
    matches: list[CatalogMatch], summary: QuerySummary,
) -> str:
    return json.dumps(
        {
            "summary": summary.to_dict(),
            "matches": [m.to_dict() for m in matches],
        },
        indent=2, sort_keys=True,
    )
