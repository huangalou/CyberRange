"""Fetch a single feed → ``AdvisoryItem`` iterator.

``feedparser`` is dependency-injectable: tests pass a fixture-driven
parser so the fetch path is fully offline-testable.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

import feedparser

from .sources import FEED_SOURCES, FeedSource

# A parser is anything callable as ``parser(url_or_text) -> feedparser.FeedParserDict``.
Parser = Callable[[str], Any]


@dataclass(frozen=True)
class AdvisoryItem:
    """Normalised view of one feed entry, ready to pipe into IOC extractor."""

    source_id: str
    guid: str
    title: str
    link: str
    published: datetime | None
    summary: str
    content: str  # full content if feed exposes it, else == summary

    def to_markdown(self) -> str:
        """Render as markdown — suitable for piping into ``cti extract``."""
        pub = self.published.isoformat() if self.published else "unknown"
        return (
            f"# {self.title}\n\n"
            f"- source: {self.source_id}\n"
            f"- link: {self.link}\n"
            f"- published: {pub}\n\n"
            f"{self.content}\n"
        )


def _parse_published(entry: Any) -> datetime | None:
    """Return ``entry.published`` as tz-aware UTC datetime, or ``None``.

    feedparser exposes parsed time as ``published_parsed`` (a ``time.struct_time``).
    Falls back to ``updated_parsed`` if the entry omits ``published``.
    """
    for attr in ("published_parsed", "updated_parsed"):
        st = getattr(entry, attr, None) or (
            entry.get(attr) if isinstance(entry, dict) else None
        )
        if st is None:
            continue
        try:
            return datetime(*st[:6], tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
    return None


def _entry_guid(entry: Any, fallback: str) -> str:
    """Pick the most stable GUID: ``id``, then ``link``, then ``fallback``."""
    for attr in ("id", "guid", "link"):
        val = getattr(entry, attr, None) or (
            entry.get(attr) if isinstance(entry, dict) else None
        )
        if val:
            return str(val)
    return fallback


def _entry_text(entry: Any) -> tuple[str, str]:
    """Return ``(summary, content)`` — falls back to summary when no body."""
    summary = ""
    raw_summary = getattr(entry, "summary", None) or (
        entry.get("summary") if isinstance(entry, dict) else None
    )
    if raw_summary:
        summary = str(raw_summary).strip()

    content = summary
    raw_content = getattr(entry, "content", None) or (
        entry.get("content") if isinstance(entry, dict) else None
    )
    if raw_content:
        # feedparser exposes content as list[FeedParserDict] with .value
        try:
            parts = [str(c.get("value", "")) for c in raw_content if c]
            joined = "\n\n".join(p.strip() for p in parts if p)
            if joined:
                content = joined
        except (AttributeError, TypeError):
            pass

    return summary, content


def fetch(
    source: FeedSource,
    *,
    parser: Parser = feedparser.parse,
    limit: int | None = None,
) -> list[AdvisoryItem]:
    """Pull one feed; return parsed advisory items (newest first as feed emits)."""
    parsed = parser(source.url)
    entries = getattr(parsed, "entries", None) or parsed.get("entries", [])
    items: list[AdvisoryItem] = []
    for idx, entry in enumerate(entries):
        if limit is not None and idx >= limit:
            break
        title = (
            getattr(entry, "title", None)
            or (entry.get("title") if isinstance(entry, dict) else None)
            or "(untitled)"
        )
        link = (
            getattr(entry, "link", None)
            or (entry.get("link") if isinstance(entry, dict) else None)
            or ""
        )
        guid = _entry_guid(entry, fallback=f"{source.id}#{idx}")
        summary, content = _entry_text(entry)
        items.append(
            AdvisoryItem(
                source_id=source.id,
                guid=guid,
                title=str(title).strip(),
                link=str(link),
                published=_parse_published(entry),
                summary=summary,
                content=content,
            )
        )
    return items


def fetch_all(
    sources: Iterable[FeedSource] = FEED_SOURCES,
    *,
    parser: Parser = feedparser.parse,
    limit: int | None = None,
) -> list[AdvisoryItem]:
    """Convenience: fetch each registered feed and flatten results."""
    out: list[AdvisoryItem] = []
    for src in sources:
        out.extend(fetch(src, parser=parser, limit=limit))
    return out
