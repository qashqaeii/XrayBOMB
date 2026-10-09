"""Recursive redaction of secrets in analysis exports."""

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
    "id",
    "token",
    "access_token",
    "refresh_token",
    "credential",
    "credentials",
    "raw_url",
    "subscription",
    "link",
})

_VLESS_URL_RE = re.compile(
    r"(vless|vmess|trojan|ss)://[^\s\"']+",
    re.IGNORECASE,
)


def _should_redact_key(key: str) -> bool:
    kl = key.lower()
    if kl in _SECRET_FIELD_NAMES:
        return True
    return any(s in kl for s in ("password", "secret", "private", "token", "credential"))


def redact_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, str):
        if _VLESS_URL_RE.search(value):
            return _VLESS_URL_RE.sub("<redacted-link>", value)
        if len(value) > 12 and value.count("-") >= 4:
            return mask_sensitive(value)
        return value
    return value


def deep_redact(obj: Any) -> Any:
    """Return a copy with sensitive fields masked."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if _should_redact_key(k) and isinstance(v, str):
                out[k] = mask_sensitive(v) if v else v
            else:
                out[k] = deep_redact(v)
        return out
    if isinstance(obj, list):
        return [deep_redact(x) for x in obj]
    if isinstance(obj, str):
        return redact_value(obj)
    return obj


def redact_analysis_dict(data: dict[str, Any]) -> dict[str, Any]:
    return deep_redact(copy.deepcopy(data))
