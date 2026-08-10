"""Known CTI vendor-advisory RSS sources.

The list intentionally stays small. R10 work line is biased toward
high-signal supply-chain / SOC-relevant advisory streams, not generic
infosec news. Operators extend by appending to ``FEED_SOURCES`` or
constructing ``FeedSource`` ad-hoc.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class FeedSource:
    """One RSS/Atom advisory feed."""

    id: str            # slug, e.g. "datadog-securitylabs"
    name: str          # display name
    url: str           # feed URL
    kind: str = "rss"  # "rss" | "atom"
    verified_at: str = ""  # ISO date the URL was last confirmed live


# URLs verified 2026-05-12 via WebFetch — all 3 returned RSS 2.0.
FEED_SOURCES: tuple[FeedSource, ...] = (
    FeedSource(
        id="datadog-securitylabs",
        name="Datadog Security Labs",
        url="https://securitylabs.datadoghq.com/rss/feed.xml",
        kind="rss",
        verified_at="2026-05-12",
    ),
    FeedSource(
        id="aqua-nautilus",
        name="Aqua Nautilus (blog.aquasec.com)",
        url="https://blog.aquasec.com/rss.xml",
        kind="rss",
        verified_at="2026-05-12",
    ),
    FeedSource(
        id="github-security",
        name="GitHub Blog · Security",
        url="https://github.blog/security/feed/",
        kind="rss",
        verified_at="2026-05-12",
    ),
)


def get_source(source_id: str, sources: Iterable[FeedSource] = FEED_SOURCES) -> FeedSource:
    """Look up a feed by slug; raise ``KeyError`` if unknown."""
    for s in sources:
        if s.id == source_id:
            return s
    known = ", ".join(s.id for s in sources)
    raise KeyError(f"unknown feed source {source_id!r}; known: {known}")
