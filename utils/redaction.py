"""Recursive redaction of secrets in analysis exports (output copies only)."""

from __future__ import annotations

import copy
import re
from typing import Any

from utils.helpers import mask_sensitive

_SECRET_FIELD_NAMES = frozenset({
    "uuid",
    "password",
    "public_key",
    "short_id",
    "private_key",
    "privateKey",
    "access_token",
    "refresh_token",
    "credential",
    "credentials",
    "raw_url",
    "subscription",
    "socks_pass",
})

_SKIP_REDACT_KEYS = frozenset({
    "run_id",
    "config_fingerprint",
    "started_at",
    "analyzed_at",
    "timestamp",
    "at",
})

_SHARE_LINK_RE = re.compile(
    r"(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s\"']+",
    re.IGNORECASE,
)


def _should_redact_key(key: str) -> bool:
    kl = key.lower()
    if kl in _SKIP_REDACT_KEYS:
        return False
    if kl in _SECRET_FIELD_NAMES:
        return True
    if kl == "id":
        return False
    return any(s in kl for s in ("password", "secret", "private", "token", "credential"))


def redact_free_text(value: str) -> str:
    if _SHARE_LINK_RE.search(value):
        return _SHARE_LINK_RE.sub("<redacted-link>", value)
    return value


def deep_redact(obj: Any) -> Any:
    """Return a copy with sensitive fields masked."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in _SKIP_REDACT_KEYS:
                out[k] = v
            elif _should_redact_key(k) and isinstance(v, str):
                out[k] = mask_sensitive(v) if v else v
            else:
                out[k] = deep_redact(v)
        return out
    if isinstance(obj, list):
        return [deep_redact(x) for x in obj]
    if isinstance(obj, str):
        return redact_free_text(obj)
    return obj


def redact_analysis_dict(data: dict[str, Any]) -> dict[str, Any]:
    return deep_redact(copy.deepcopy(data))
