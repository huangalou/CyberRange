"""CTI vendor-advisory feed fetchers.

Sub-package layout:

- ``sources``: registry of known RSS/Atom feeds (Datadog Security Labs,
  Aqua Nautilus, GitHub Security blog). URLs verified at module write
  time; operators should re-verify with ``curl`` periodically.
- ``fetcher``: pull a feed (default via ``feedparser``) and yield
  normalised ``AdvisoryItem`` records.
- ``state``: JSON-backed dedup store — track which GUIDs were already
  emitted so subsequent runs only surface new advisories.

Pipeable usage (CLI):

    cyberrange cti feeds fetch --source datadog-securitylabs --format md \\
        > /tmp/advisory.md
    cyberrange cti extract /tmp/advisory.md > /tmp/iocs.yaml
"""
from __future__ import annotations

from .fetcher import AdvisoryItem, fetch, fetch_all
from .sources import FEED_SOURCES, FeedSource, get_source
from .state import StateStore

__all__ = [
    "AdvisoryItem",
    "FEED_SOURCES",
    "FeedSource",
    "StateStore",
    "fetch",
    "fetch_all",
    "get_source",
]
