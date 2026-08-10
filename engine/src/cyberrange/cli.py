"""CLI entry: `cyberrange list` / `cyberrange gen ...`."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import yaml

from .cti import DetectionSurface, IocExtractor, draft_catalog, extract_iocs
from .cti.feeds import (
    FEED_SOURCES,
    StateStore,
    fetch as feeds_fetch,
    get_source as feeds_get_source,
)
from .cti.metrics import (
    collect_metrics,
    format_table as metrics_format_table,
    summarize as metrics_summarize,
    to_json as metrics_to_json,
)
from .vulnops import (
    PackageQuery,
    format_table as vulnops_format_table,
    query as vulnops_query,
    summarize as vulnops_summarize,
    to_json as vulnops_to_json,
)
from .generator import render_many
from .loader import CATALOG_ROOT, find_spec, list_specs, load_spec
from .sinks import open_sink

# Default feed-state location: ~/.cyberrange/feed-state.json, overridable.
_DEFAULT_FEED_STATE = Path(
    os.environ.get(
        "CYBERRANGE_FEED_STATE",
        str(Path.home() / ".cyberrange" / "feed-state.json"),
    )
)


def cmd_list(args: argparse.Namespace) -> int:
    root = Path(args.catalog_root)
    found = False
    for path, spec in list_specs(root):
        rel = path.relative_to(root)
        print(
            f"{spec.vendor}/{spec.product}/{spec.version}/{spec.log_type}"
            f"  format={spec.format}  ({rel})"
        )
        found = True
    if not found:
        print(f"No catalog specs under {root}", file=sys.stderr)
        return 1
    return 0


def cmd_detection_list(args: argparse.Namespace) -> int:
    """List detection-rule mappings declared by each catalog (v2 metadata).

    DetectOps Harness entry point: print catalog × Wazuh/Sigma/ELK detection
    rule × Mythos-ready risk/PA so an SOC operator can see coverage at a glance.
    """
    root = Path(args.catalog_root)
    rows = 0
    for path, spec in list_specs(root):
        det = spec.detections
        align = spec.mythos_alignment
        slug = f"{spec.vendor}/{spec.product}/{spec.version}/{spec.log_type}"

        wazuh_str = "—"
        sigma_str = "—"
        elk_str = "—"
        if det is not None:
            if det.wazuh:
                wazuh_str = ",".join(
                    f"{w.rule_id or '-'}({w.decoder or '?'})" for w in det.wazuh
                )
            if det.sigma:
                sigma_str = ",".join(s.rule for s in det.sigma)
            if det.elk_detection:
                elk_str = ",".join(
                    e.kibana_rule_id or "?" for e in det.elk_detection
                )

        align_str = "—"
        if align is not None:
            risks = ",".join(align.risk_refs) or "—"
            pas = ",".join(align.pa_refs) or "—"
            ttx = align.ttx_class or "—"
            align_str = f"R={risks} PA={pas} ttx={ttx}"

        print(f"{slug}")
        print(f"  wazuh : {wazuh_str}")
        print(f"  sigma : {sigma_str}")
        print(f"  elk   : {elk_str}")
        print(f"  mythos: {align_str}")
        print()
        rows += 1

    if rows == 0:
        print(f"No catalog specs under {root}", file=sys.stderr)
        return 1
    return 0


def _parse_param(items: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"--param expects key=value, got {item!r}")
        k, v = item.split("=", 1)
        out[k] = v
    return out


def cmd_cti_extract(args: argparse.Namespace) -> int:
    """Extract IOCs from an advisory markdown file → print as schema v3
    cti.iocs YAML block, ready to paste into a new catalog."""
    src = Path(args.path)
    if not src.exists():
        print(f"advisory not found: {src}", file=sys.stderr)
        return 2
    text = src.read_text(encoding="utf-8")

    extractor = (
        IocExtractor(include_clean=True)
        if args.include_clean
        else IocExtractor()
    )
    result = extractor.extract(text)

    # match_counts + defang_seen go to stderr so the YAML on stdout
    # remains directly pipeable into a YAML editor.
    print(
        f"# defang_seen={result.defang_seen}  match_counts="
        + ",".join(f"{k}={v}" for k, v in result.match_counts.items()),
        file=sys.stderr,
    )

    bundle_dict = result.iocs.model_dump(exclude_defaults=False)
    # Drop empty top-level lists for a tighter snippet.
    bundle_dict = {k: v for k, v in bundle_dict.items() if v}

    if not bundle_dict:
        print("# (no IOCs extracted)", file=sys.stderr)
        return 0

    yaml.safe_dump(
        {"iocs": bundle_dict},
        sys.stdout,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
    )
    return 0


def cmd_cti_draft(args: argparse.Namespace) -> int:
    """Draft a schema-v3 catalog YAML from an advisory markdown file.

    Offline-first: no LLM is invoked unless a future flag wires one
    explicitly. The drafter heuristics decide vendor/product/log_type +
    stub template + IOC axis ownership; reviewer is expected to refine
    the template / detections / mythos_alignment before commit.
    """
    src = Path(args.path)
    if not src.exists():
        print(f"advisory not found: {src}", file=sys.stderr)
        return 2
    advisory_md = src.read_text(encoding="utf-8")

    surface_override = (
        DetectionSurface(args.surface) if args.surface else None
    )

    draft = draft_catalog(
        advisory_md,
        ingested_at=args.ingested_at,
        source=args.source,
        source_url=args.source_url,
        advisory_id=args.advisory_id,
        cve_refs=args.cve_ref or [],
        surface_override=surface_override,
    )

    # Stderr: drafter telemetry (chosen surface, warnings, suggested path).
    print(
        f"# surface={draft.surface.value}  "
        f"suggested_path=catalog/{draft.suggested_path}",
        file=sys.stderr,
    )
    for w in draft.warnings:
        print(f"# warning: {w}", file=sys.stderr)

    yaml_out = draft.to_yaml()
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(yaml_out, encoding="utf-8")
        print(f"# wrote {out_path}", file=sys.stderr)
    else:
        sys.stdout.write(yaml_out)

    return 0


def cmd_cti_metrics(args: argparse.Namespace) -> int:
    """Print Time-to-Catalog metrics (Mythos-ready R10 alignment).

    Default output is a table. ``--json`` dumps a machine-readable blob
    with summary + per-catalog rows for dashboards / Grafana ingest.
    """
    metrics = collect_metrics()
    summary = metrics_summarize(metrics)

    if args.json:
        sys.stdout.write(metrics_to_json(metrics, summary) + "\n")
        return 0

    sys.stdout.write(metrics_format_table(metrics))
    sys.stdout.write("\n")
    sys.stdout.write(
        f"catalogs with cti.ingested_at: {summary.catalog_count}  "
        f"measured (git commit found): {summary.measured_count}  "
        f"same-day: {summary.same_day_count}  "
        f"P0: {summary.p0_count}\n"
    )
    if summary.median_delta_days is not None:
        sys.stdout.write(
            f"delta (days)  median={summary.median_delta_days}  "
            f"p90={summary.p90_delta_days}  "
            f"max={summary.max_delta_days}\n"
        )
    if summary.by_campaign:
        campaigns = ", ".join(
            f"{name}={n}" for name, n in sorted(summary.by_campaign.items())
        )
        sys.stdout.write(f"by campaign: {campaigns}\n")
    return 0


def cmd_vulnops_query(args: argparse.Namespace) -> int:
    """Reverse-lookup catalogs from VulnOps / CTI keywords.

    Examples:
      cyberrange vulnops query --advisory PYSEC-2026-2
      cyberrange vulnops query --package pypi:litellm:1.82.8
      cyberrange vulnops query --campaign teampcp --cve CVE-2026-0001
    """
    try:
        package_queries = [PackageQuery.parse(p) for p in (args.package or [])]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    matches = vulnops_query(
        cve=args.cve or None,
        advisory_id=args.advisory or None,
        package=package_queries or None,
        campaign=args.campaign or None,
    )
    summary = vulnops_summarize(matches)

    if args.json:
        sys.stdout.write(vulnops_to_json(matches, summary) + "\n")
        return 0

    if not matches:
        # Distinguish "you queried nothing" from "no matches".
        no_inputs = not (args.cve or args.advisory or args.package
                         or args.campaign)
        if no_inputs:
            print(
                "error: at least one of --cve / --advisory / --package "
                "/ --campaign is required",
                file=sys.stderr,
            )
            return 2
        sys.stdout.write(vulnops_format_table(matches))
        return 0

    sys.stdout.write(vulnops_format_table(matches))
    sys.stdout.write("\n")
    sys.stdout.write(
        f"catalogs: {summary.catalog_count}  P0: {summary.p0_count}\n"
    )
    if summary.by_advisory:
        advs = ", ".join(
            f"{k}={v}" for k, v in sorted(summary.by_advisory.items())
        )
        sys.stdout.write(f"by advisory: {advs}\n")
    if summary.by_campaign:
        camps = ", ".join(
            f"{k}={v}" for k, v in sorted(summary.by_campaign.items())
        )
        sys.stdout.write(f"by campaign: {camps}\n")
    return 0


def cmd_cti_feeds_list(args: argparse.Namespace) -> int:
    """Print known CTI advisory feed sources."""
    for s in FEED_SOURCES:
        print(f"{s.id:<24} {s.kind:<5} {s.url}")
        print(f"  ↳ {s.name}  (verified {s.verified_at or 'unknown'})")
    return 0


def cmd_cti_feeds_fetch(args: argparse.Namespace) -> int:
    """Pull advisory feed(s) → emit new (or all) items as JSON / markdown.

    Default behaviour is "new only" — items whose GUID is already in the
    state store are skipped, mimicking ``apt update`` idempotency.
    """
    state_path = Path(args.state) if args.state else _DEFAULT_FEED_STATE
    state = StateStore(state_path)

    sources = (
        [feeds_get_source(args.source)] if args.source else list(FEED_SOURCES)
    )

    items: list = []
    for src in sources:
        try:
            items.extend(feeds_fetch(src, limit=args.limit))
        except Exception as exc:  # network / parse error per source
            print(f"# WARN: fetch {src.id!r} failed: {exc}", file=sys.stderr)

    if not args.all_items:
        items = state.filter_new(items)

    if args.format == "json":
        payload = [
            {
                "source_id": it.source_id,
                "guid": it.guid,
                "title": it.title,
                "link": it.link,
                "published": it.published.isoformat() if it.published else None,
                "summary": it.summary,
                "content": it.content,
            }
            for it in items
        ]
        json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:  # md
        for idx, it in enumerate(items):
            if idx:
                sys.stdout.write("\n---\n\n")
            sys.stdout.write(it.to_markdown())

    print(
        f"# fetched={len(items)}  sources={','.join(s.id for s in sources)}  "
        f"state={state_path}  mode={'all' if args.all_items else 'new-only'}",
        file=sys.stderr,
    )

    if args.mark_seen and items:
        state.mark_seen(items)
        state.save()
        print(f"# marked {len(items)} item(s) seen", file=sys.stderr)

    return 0


def cmd_gen(args: argparse.Namespace) -> int:
    spec_path = find_spec(
        args.vendor,
        args.product,
        args.version,
        args.log_type,
        root=Path(args.catalog_root),
    )
    spec = load_spec(spec_path)
    params = _parse_param(args.param)
    interval = (1.0 / args.rate) if args.rate > 0 else 0.0

    with open_sink(args.sink) as sink:
        for line in render_many(spec, args.count, params):
            sink.write(line)
            if interval:
                time.sleep(interval)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cyberrange",
        description="Catalog-driven log generator for SOC rule validation.",
    )
    p.add_argument(
        "--catalog-root",
        default=str(CATALOG_ROOT),
        help=f"Catalog root directory (default: {CATALOG_ROOT})",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_list = sub.add_parser("list", help="List available catalog specs")
    sp_list.set_defaults(func=cmd_list)

    sp_gen = sub.add_parser("gen", help="Generate logs from a spec")
    sp_gen.add_argument("--vendor", required=True)
    sp_gen.add_argument("--product", required=True)
    sp_gen.add_argument("--version", required=True)
    sp_gen.add_argument("--log-type", required=True, dest="log_type")
    sp_gen.add_argument("--count", type=int, default=10)
    sp_gen.add_argument(
        "--rate",
        type=float,
        default=0.0,
        help="logs/sec, 0 = as fast as possible",
    )
    sp_gen.add_argument(
        "--param",
        action="append",
        default=[],
        help="key=value param override; repeatable",
    )
    sp_gen.add_argument(
        "--sink",
        default="stdout://",
        help="stdout:// | file:///path | udp://host:port | tcp://host:port",
    )
    sp_gen.set_defaults(func=cmd_gen)

    sp_det = sub.add_parser(
        "detection",
        help="Detection-rule coverage commands (DetectOps Harness)",
    )
    det_sub = sp_det.add_subparsers(dest="det_cmd", required=True)
    sp_det_list = det_sub.add_parser(
        "list",
        help="List detection-rule mappings declared by each catalog",
    )
    sp_det_list.set_defaults(func=cmd_detection_list)

    sp_cti = sub.add_parser(
        "cti",
        help="CTI feed integration (advisory → catalog draft, R10 work line)",
    )
    cti_sub = sp_cti.add_subparsers(dest="cti_cmd", required=True)
    sp_cti_extract = cti_sub.add_parser(
        "extract",
        help="Extract IOCs from an advisory markdown file → cti.iocs YAML",
    )
    sp_cti_extract.add_argument(
        "path",
        help="Advisory markdown file path",
    )
    sp_cti_extract.add_argument(
        "--include-clean",
        action="store_true",
        help="Don't filter common reference domains (debugging only)",
    )
    sp_cti_extract.set_defaults(func=cmd_cti_extract)

    sp_cti_draft = cti_sub.add_parser(
        "draft",
        help=(
            "Draft a schema-v3 catalog YAML from an advisory markdown "
            "file (offline-first; reviewer must refine before commit)"
        ),
    )
    sp_cti_draft.add_argument("path", help="Advisory markdown file path")
    sp_cti_draft.add_argument(
        "--ingested-at",
        required=True,
        help="ISO date for cti.ingested_at, e.g. 2026-05-12",
    )
    sp_cti_draft.add_argument(
        "--source",
        default=None,
        help="cti.source slug, e.g. datadog-security-labs",
    )
    sp_cti_draft.add_argument(
        "--source-url",
        default=None,
        help="cti.source_url — advisory permalink",
    )
    sp_cti_draft.add_argument(
        "--advisory-id",
        default=None,
        help="cti.advisory_id, e.g. PYSEC-2026-2 / GHSA-xxxx",
    )
    sp_cti_draft.add_argument(
        "--cve-ref",
        action="append",
        default=[],
        help="CVE id (repeatable) for both cti.cve_refs and vulnops.cve_refs",
    )
    sp_cti_draft.add_argument(
        "--surface",
        choices=[s.value for s in DetectionSurface],
        default=None,
        help="Force a specific detection surface (bypass heuristic)",
    )
    sp_cti_draft.add_argument(
        "--output", "-o",
        default=None,
        help=(
            "Write draft to this path instead of stdout. Parent dirs "
            "are created."
        ),
    )
    sp_cti_draft.set_defaults(func=cmd_cti_draft)

    sp_cti_metrics = cti_sub.add_parser(
        "metrics",
        help=(
            "Time-to-Catalog metrics (advisory.ingested_at → catalog "
            "first git commit) — Mythos-ready R10 alignment"
        ),
    )
    sp_cti_metrics.add_argument(
        "--json",
        action="store_true",
        help="Output JSON (summary + per-catalog) for dashboards",
    )
    sp_cti_metrics.set_defaults(func=cmd_cti_metrics)

    sp_cti_feeds = cti_sub.add_parser(
        "feeds",
        help="Manage vendor-advisory RSS feed sources",
    )
    feeds_sub = sp_cti_feeds.add_subparsers(dest="feeds_cmd", required=True)

    sp_feeds_list = feeds_sub.add_parser(
        "list", help="List known feed sources"
    )
    sp_feeds_list.set_defaults(func=cmd_cti_feeds_list)

    sp_feeds_fetch = feeds_sub.add_parser(
        "fetch",
        help=(
            "Pull advisory feed(s), filter against state, emit JSON or "
            "markdown (pipeable into `cti extract`)"
        ),
    )
    sp_feeds_fetch.add_argument(
        "--source",
        help=(
            "Source id (e.g. datadog-securitylabs); omit to fetch all"
        ),
    )
    sp_feeds_fetch.add_argument(
        "--state",
        help=(
            "State file path (default: $CYBERRANGE_FEED_STATE or "
            "~/.cyberrange/feed-state.json)"
        ),
    )
    sp_feeds_fetch.add_argument(
        "--all",
        dest="all_items",
        action="store_true",
        help="Emit all items, not just new since last seen",
    )
    sp_feeds_fetch.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Max items per source (default: unlimited)",
    )
    sp_feeds_fetch.add_argument(
        "--format",
        choices=("json", "md"),
        default="md",
        help="Output format (default: md, pipeable into `cti extract`)",
    )
    sp_feeds_fetch.add_argument(
        "--mark-seen",
        dest="mark_seen",
        action="store_true",
        help="Update state file: mark emitted items as seen",
    )
    sp_feeds_fetch.set_defaults(func=cmd_cti_feeds_fetch)

    # ──────────────── vulnops (Phase 5.5) ────────────────
    sp_vulnops = sub.add_parser(
        "vulnops",
        help=(
            "VulnOps × DetectOps reverse-lookup (PA11 work line) — "
            "find catalogs by CVE / advisory / package / campaign"
        ),
    )
    vulnops_sub = sp_vulnops.add_subparsers(
        dest="vulnops_cmd", required=True,
    )
    sp_vulnops_query = vulnops_sub.add_parser(
        "query",
        help=(
            "Reverse-lookup catalogs from VulnOps / CTI keywords "
            "(union semantics)"
        ),
    )
    sp_vulnops_query.add_argument(
        "--cve", action="append", default=[],
        help="CVE id (repeatable), e.g. CVE-2026-0001",
    )
    sp_vulnops_query.add_argument(
        "--advisory", action="append", default=[],
        help=(
            "Advisory id (repeatable), e.g. PYSEC-2026-2 / "
            "GHSA-xxxx-xxxx-xxxx"
        ),
    )
    sp_vulnops_query.add_argument(
        "--package", action="append", default=[],
        help=(
            "Package query (repeatable): 'ecosystem:name[:version]', "
            "e.g. pypi:litellm or pypi:litellm:1.82.8"
        ),
    )
    sp_vulnops_query.add_argument(
        "--campaign", action="append", default=[],
        help="Campaign slug (repeatable), e.g. teampcp",
    )
    sp_vulnops_query.add_argument(
        "--json", action="store_true",
        help="Output JSON (summary + per-match rows)",
    )
    sp_vulnops_query.set_defaults(func=cmd_vulnops_query)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
