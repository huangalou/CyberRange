"""cyberrange gen:burst 參數、互斥檢查、JSON param。"""
from __future__ import annotations

from pathlib import Path

import pytest

from cyberrange.cli import _parse_param, main

BASE = ["gen", "--vendor", "linux", "--product", "openssh",
        "--version", "9.x", "--log-type", "auth.failure"]


def _lines(p: Path) -> list[str]:
    return [l for l in p.read_text().splitlines() if l.strip()]


def test_gen_burst_writes_size_times_repeat(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    rc = main([*BASE, "--burst", "3/0.03s", "--repeat", "2", "--gap", "0.01s",
               "--sink", f"file://{out}"])
    assert rc == 0
    assert len(_lines(out)) == 6


def test_gen_default_count_unchanged(tmp_path: Path) -> None:
    out = tmp_path / "out.log"
    assert main([*BASE, "--sink", f"file://{out}"]) == 0
    assert len(_lines(out)) == 10


@pytest.mark.parametrize(
    ("extra", "needle"),
    [
        (["--burst", "3/1s", "--rate", "5"], "--burst"),
        (["--burst", "3/1s", "--count", "5"], "--burst"),
        (["--burst", "0/1s"], "burst"),
        (["--burst", "3/1s", "--repeat", "0"], "repeat"),
        # 用 `=` 形式:`--gap -1s` 會被 argparse 當成另一個選項
        (["--burst", "3/1s", "--gap=-1s"], "invalid duration"),
    ],
)
def test_gen_invalid_timing_args_exit_2(
    extra: list[str], needle: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exc:
        main([*BASE, *extra])
    assert exc.value.code == 2
    assert needle in capsys.readouterr().err


def test_gen_repeat_without_burst_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([*BASE, "--repeat", "3"])
    assert exc.value.code == 2
    assert "--burst" in capsys.readouterr().err


def test_parse_param_json_list_and_dict() -> None:
    out = _parse_param([
        'src_pool=["203.0.113.5"]',
        'kind_weights={"invalid_user": 1}',
        "hostname=web01",
        "port=514",
        "odd=[not json",
    ])
    assert out == {
        "src_pool": ["203.0.113.5"],
        "kind_weights": {"invalid_user": 1},
        "hostname": "web01",
        "port": "514",
        "odd": "[not json",
    }
