"""Geo lookup cache to reduce API rate limits."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from utils.settings import get_settings

CACHE_PATH = Path.home() / ".xray_analyzer" / "geo_cache.json"


class GeoCache:
    def __init__(self) -> None:
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if CACHE_PATH.exists():
            try:
                self._data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}

    def _save(self) -> None:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(self._data, indent=2), encoding="utf-8")

    def get(self, ip: str) -> Optional[dict]:
        key = ip or "__client__"
        entry = self._data.get(key)
        if not entry:
            return None
        ttl_hours = get_settings().geo_cache_hours
        if time.time() - entry.get("_ts", 0) > ttl_hours * 3600:
            return None
        return {k: v for k, v in entry.items() if k != "_ts"}

    def set(self, ip: str, data: dict) -> None:
        key = ip or "__client__"
        self._data[key] = {**data, "_ts": time.time()}
        self._save()
