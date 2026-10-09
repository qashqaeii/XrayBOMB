"""Stable non-secret fingerprint for config correlation in test runs."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.models import ParsedConfig

_SECRET_KEYS = frozenset({"uuid", "password", "public_key", "short_id", "raw_url"})


def _scrub(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _SECRET_KEYS:
                out[k] = "<redacted>"
            else:
                out[k] = _scrub(v)
        return out
    if isinstance(obj, list):
        return [_scrub(x) for x in obj]
    return obj


def config_fingerprint(config: ParsedConfig) -> str:
    payload = _scrub(config.model_dump(mode="json"))
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]
