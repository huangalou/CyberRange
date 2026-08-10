"""JSON-backed dedup state for feed fetchers.

Tracks which advisory GUIDs were already emitted so subsequent runs only
surface new items. Format::

    {
      "version": 1,
      "sources": {
        "<source_id>": {
          "seen_guids": ["...", "..."],
          "last_run": "2026-05-12T08:30:00+00:00"
        }
      }
    }

Single-file JSON is enough for single-operator labs; swap for SQLite
when concurrent writers appear (none planned).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .fetcher import AdvisoryItem

_STATE_VERSION = 1


class StateStore:
    """File-backed dedup tracker. Atomic write via temp-then-rename."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._data: dict = self._load()

    # ──────────── load / save ────────────

    def _load(self) -> dict:
        if not self.path.exists():
            return {"version": _STATE_VERSION, "sources": {}}
        try:
            with self.path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"version": _STATE_VERSION, "sources": {}}
        if not isinstance(data, dict) or data.get("version") != _STATE_VERSION:
            return {"version": _STATE_VERSION, "sources": {}}
        data.setdefault("sources", {})
        return data

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)
        tmp.replace(self.path)

    # ──────────── query / mutate ────────────

    def seen_guids(self, source_id: str) -> set[str]:
        return set(self._data["sources"].get(source_id, {}).get("seen_guids", []))

    def filter_new(self, items: Iterable[AdvisoryItem]) -> list[AdvisoryItem]:
        """Return only items whose GUID is not in the store."""
        out: list[AdvisoryItem] = []
        seen_cache: dict[str, set[str]] = {}
        for item in items:
            seen = seen_cache.setdefault(item.source_id, self.seen_guids(item.source_id))
            if item.guid not in seen:
                out.append(item)
        return out

    def mark_seen(self, items: Iterable[AdvisoryItem]) -> None:
        """Record GUIDs as seen and stamp ``last_run``. Does not save automatically."""
        now = datetime.now(timezone.utc).isoformat()
        for item in items:
            entry = self._data["sources"].setdefault(
                item.source_id, {"seen_guids": [], "last_run": None}
            )
            seen = set(entry.get("seen_guids", []))
            if item.guid not in seen:
                entry.setdefault("seen_guids", []).append(item.guid)
            entry["last_run"] = now
