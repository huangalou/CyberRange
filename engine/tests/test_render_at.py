"""render_one(at=...) 時鐘注入;choice 純字串 param 防護。"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cyberrange import CatalogSpec, render_one

AT = datetime(2026, 10, 1, 8, 5, 3, 123456, tzinfo=timezone.utc)


def _spec(fmt: str) -> CatalogSpec:
    return CatalogSpec(
        vendor="t", product="t", version="1", log_type="t", format="raw",
        fields=[{"name": "ts", "type": "datetime", "format": fmt}],
        template="{{ ts }}",
    )


@pytest.mark.parametrize(
    ("fmt", "expected"),
    [
        ("epoch", "1790841903"),
        ("%b %d %H:%M:%S", "Oct 01 08:05:03"),
        ("%Y-%m-%dT%H:%M:%S.%fZ", "2026-10-01T08:05:03.123456Z"),
    ],
)
def test_render_one_uses_injected_time(fmt: str, expected: str) -> None:
    assert render_one(_spec(fmt), at=AT) == expected


def test_render_one_without_at_uses_now() -> None:
    before = int(datetime.now(timezone.utc).timestamp())
    out = int(render_one(_spec("epoch")))
    after = int(datetime.now(timezone.utc).timestamp())
    assert before <= out <= after


def test_render_one_rejects_naive_at() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        render_one(_spec("epoch"), at=datetime(2026, 10, 1))


def test_choice_param_plain_string_is_single_choice() -> None:
    spec = CatalogSpec(
        vendor="t", product="t", version="1", log_type="t", format="raw",
        params={"pool": {"default": ["198.51.100.1", "198.51.100.2"]}},
        fields=[{"name": "ip", "type": "choice", "choices": "${params.pool}"}],
        template="{{ ip }}",
    )
    outs = {render_one(spec, {"pool": "203.0.113.5"}) for _ in range(20)}
    assert outs == {"203.0.113.5"}


def test_render_one_normalizes_non_utc_at_to_utc() -> None:
    taipei = AT.astimezone(timezone(timedelta(hours=8)))
    spec = _spec("%Y-%m-%dT%H:%M:%S.%fZ")
    assert render_one(spec, at=taipei) == "2026-10-01T08:05:03.123456Z"


@pytest.mark.parametrize("bad", ["invalid_user", ["invalid_user"]])
def test_weighted_choice_non_mapping_param_is_clear_error(bad: object) -> None:
    spec = CatalogSpec(
        vendor="t", product="t", version="1", log_type="t", format="raw",
        params={"w": {"default": {"a": 1}}},
        fields=[{"name": "k", "type": "weighted_choice", "choices": "${params.w}"}],
        template="{{ k }}",
    )
    with pytest.raises(ValueError, match="must be a mapping"):
        render_one(spec, {"w": bad})
