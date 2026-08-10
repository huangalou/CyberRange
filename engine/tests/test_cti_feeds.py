"""Offline tests for ``cyberrange.cti.feeds`` — fetcher / state / sources.

Network is never touched. ``feedparser.parse`` accepts raw XML strings or
local file paths, so the fixture-driven parser is just a wrapper that
loads the canned RSS file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import feedparser
import pytest

from cyberrange.cti.feeds import (
    FEED_SOURCES,
    AdvisoryItem,
    FeedSource,
    StateStore,
    fetch,
    fetch_all,
    get_source,
)

FIXTURE_RSS = Path(__file__).parent / "fixtures" / "feeds" / "datadog-sample.rss"


def _fixture_parser(_url: str):
    """Drop-in for ``feedparser.parse`` — always returns the fixture feed."""
    return feedparser.parse(str(FIXTURE_RSS))


# ──────────────── sources ────────────────


@pytest.mark.unit
def test_registered_feed_sources_have_required_metadata():
    assert len(FEED_SOURCES) >= 3
    ids = {s.id for s in FEED_SOURCES}
    assert {"datadog-securitylabs", "aqua-nautilus", "github-security"}.issubset(ids)
    for s in FEED_SOURCES:
        assert s.url.startswith(("http://", "https://"))
        assert s.kind in {"rss", "atom"}
        assert s.verified_at, f"{s.id} missing verified_at"


@pytest.mark.unit
def test_get_source_by_id():
    s = get_source("datadog-securitylabs")
    assert isinstance(s, FeedSource)
    assert "datadog" in s.url


@pytest.mark.unit
def test_get_source_unknown_raises():
    with pytest.raises(KeyError, match="unknown feed source"):
        get_source("does-not-exist")


# ──────────────── fetcher ────────────────


@pytest.mark.unit
def test_fetch_parses_fixture_into_advisory_items():
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    assert len(items) == 3
    assert all(isinstance(i, AdvisoryItem) for i in items)
    assert all(i.source_id == "test" for i in items)


@pytest.mark.unit
def test_fetch_populates_titles_and_links():
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    titles = [i.title for i in items]
    assert "Three malicious PyPI packages caught hijacking pip install" in titles
    assert items[0].link.startswith("https://securitylabs.datadoghq.com/")


@pytest.mark.unit
def test_fetch_handles_missing_pubdate_and_summary():
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    no_meta = next(i for i in items if i.title == "Untitled entry without pubDate or summary")
    assert no_meta.published is None
    assert no_meta.summary == ""
    assert no_meta.content == ""


@pytest.mark.unit
def test_fetch_parses_pubdate_to_utc_datetime():
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    teampcp = next(i for i in items if "TeamPCP" in (i.summary or i.title) or "PyPI" in i.title)
    assert teampcp.published is not None
    assert teampcp.published.tzinfo is timezone.utc
    assert teampcp.published.year == 2026 and teampcp.published.month == 5


@pytest.mark.unit
def test_fetch_respects_limit():
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser, limit=2)
    assert len(items) == 2


@pytest.mark.unit
def test_fetch_guid_falls_back_to_link_or_synthetic():
    # Last entry has no <guid> but has <link>; verify GUID = link.
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    no_meta = next(i for i in items if "no-meta" in i.link)
    assert no_meta.guid == no_meta.link


@pytest.mark.unit
def test_fetch_all_flattens_across_sources():
    src_a = FeedSource(id="a", name="a", url="ignored://a", verified_at="2026-05-12")
    src_b = FeedSource(id="b", name="b", url="ignored://b", verified_at="2026-05-12")
    items = fetch_all([src_a, src_b], parser=_fixture_parser)
    assert len(items) == 6  # 3 × 2
    assert {i.source_id for i in items} == {"a", "b"}


@pytest.mark.unit
def test_advisory_item_to_markdown_contains_metadata():
    item = AdvisoryItem(
        source_id="datadog",
        guid="g1",
        title="TeamPCP",
        link="https://example.com/a",
        published=datetime(2026, 5, 8, 14, 0, tzinfo=timezone.utc),
        summary="short",
        content="full body text",
    )
    md = item.to_markdown()
    assert "# TeamPCP" in md
    assert "datadog" in md
    assert "https://example.com/a" in md
    assert "2026-05-08T14:00:00+00:00" in md
    assert "full body text" in md


# ──────────────── state store ────────────────


@pytest.mark.unit
def test_state_store_starts_empty_when_file_missing(tmp_path: Path):
    store = StateStore(tmp_path / "state.json")
    assert store.seen_guids("anything") == set()


@pytest.mark.unit
def test_state_store_filter_new_returns_all_first_time(tmp_path: Path):
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    store = StateStore(tmp_path / "state.json")
    new = store.filter_new(items)
    assert len(new) == len(items)


@pytest.mark.unit
def test_state_store_dedup_after_mark_seen(tmp_path: Path):
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    store_path = tmp_path / "state.json"
    store = StateStore(store_path)
    store.mark_seen(items)
    store.save()

    # New instance reloads from disk.
    store2 = StateStore(store_path)
    new = store2.filter_new(items)
    assert new == []


@pytest.mark.unit
def test_state_store_filter_new_emits_only_new_guids(tmp_path: Path):
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    store = StateStore(tmp_path / "state.json")
    # Mark first one seen.
    store.mark_seen(items[:1])
    store.save()

    store2 = StateStore(tmp_path / "state.json")
    new = store2.filter_new(items)
    assert len(new) == len(items) - 1
    assert items[0] not in new


@pytest.mark.unit
def test_state_store_save_is_atomic_and_human_readable(tmp_path: Path):
    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    store_path = tmp_path / "state.json"
    store = StateStore(store_path)
    store.mark_seen(items)
    store.save()

    assert store_path.exists()
    data = json.loads(store_path.read_text("utf-8"))
    assert data["version"] == 1
    assert "test" in data["sources"]
    assert len(data["sources"]["test"]["seen_guids"]) == len(items)
    assert "last_run" in data["sources"]["test"]


@pytest.mark.unit
def test_state_store_corrupt_file_falls_back_to_empty(tmp_path: Path):
    state_path = tmp_path / "state.json"
    state_path.write_text("{not valid json", encoding="utf-8")
    store = StateStore(state_path)
    assert store.seen_guids("anything") == set()


@pytest.mark.unit
def test_state_store_wrong_version_falls_back_to_empty(tmp_path: Path):
    state_path = tmp_path / "state.json"
    state_path.write_text(json.dumps({"version": 99, "sources": {"x": {}}}), encoding="utf-8")
    store = StateStore(state_path)
    assert store.seen_guids("x") == set()


# ──────────────── integration: fetch → extract pipeline shape ────────────────


@pytest.mark.integration
def test_fetched_markdown_is_pipeable_into_ioc_extractor():
    """Round-trip: fetch fixture feed → render markdown → run IOC extractor."""
    from cyberrange.cti import extract_iocs

    src = FeedSource(id="test", name="test", url="ignored://", verified_at="2026-05-12")
    items = fetch(src, parser=_fixture_parser)
    teampcp = next(i for i in items if "PyPI" in i.title)
    md = teampcp.to_markdown()
    result = extract_iocs(md)
    # Defanged IOCs in the fixture should be extracted.
    assert result.defang_seen
    assert any("litellm-cdn" in d for d in result.iocs.domains)
    assert "41.216.183.23" in result.iocs.ips
