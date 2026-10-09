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
    "websocket_handshake_ws_key",
})

_SKIP_REDACT_KEYS = frozenset({
    "run_id",
    "config_fingerprint",
    "started_at",
    "analyzed_at",
    "timestamp",
})

_SKIP_LITERAL_VALUES: set[str] = set()

_SHARE_LINK_RE = re.compile(
    r"(vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic)://[^\s\"']+",
    re.IGNORECASE,
)

_UUID_STANDARD_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
)

_UUID_LABEL_RE = re.compile(
    r"(?i)(uuid\s*[:=]\s*)([0-9a-fA-F-]{36,})",
)


def _should_redact_key(key: str, *, parent_key: str | None = None) -> bool:
    kl = key.lower()
    if kl in _SKIP_REDACT_KEYS:
        return False
    if kl in _SECRET_FIELD_NAMES:
        return True
    if kl == "id" and parent_key and parent_key.lower() == "users":
        return True
    return any(s in kl for s in ("password", "secret", "private", "token", "credential"))


def _collect_secrets(obj: Any, *, parent_key: str | None = None) -> set[str]:
    found: set[str] = set()
    if isinstance(obj, dict):
        field_hint = str(obj.get("field", "")).lower()
        for k, v in obj.items():
            if k == "value" and field_hint in _SECRET_FIELD_NAMES.union({"id", "uuid"}) and isinstance(v, str):
                if v.strip():
                    found.add(v.strip())
            if _should_redact_key(k, parent_key=parent_key) and isinstance(v, str) and v.strip():
                found.add(v.strip())
            found.update(_collect_secrets(v, parent_key=k))
    elif isinstance(obj, list):
        for item in obj:
            found.update(_collect_secrets(item, parent_key=parent_key))
    elif isinstance(obj, str) and obj.strip():
        for m in _SHARE_LINK_RE.finditer(obj):
            found.add(m.group(0))
    return found


def _register_skip_literals(obj: Any) -> None:
    """Preserve non-secret identifiers during string replacement."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in _SKIP_REDACT_KEYS and isinstance(v, str) and v:
                _SKIP_LITERAL_VALUES.add(v)
            _register_skip_literals(v)
    elif isinstance(obj, list):
        for item in obj:
            _register_skip_literals(item)


def _scrub_string(text: str, secrets: set[str]) -> str:
    if not text:
        return text
    out = _SHARE_LINK_RE.sub("<redacted-link>", text)
    out = _UUID_LABEL_RE.sub(r"\1<redacted-uuid>", out)
    for secret in sorted(secrets, key=len, reverse=True):
        if secret in _SKIP_LITERAL_VALUES:
            continue
        if len(secret) >= 4:
            out = out.replace(secret, mask_sensitive(secret))
    def _mask_uuid(m: re.Match) -> str:
        u = m.group(0)
        if u in _SKIP_LITERAL_VALUES:
            return u
        return mask_sensitive(u)

    out = _UUID_STANDARD_RE.sub(_mask_uuid, out)
    return out


def deep_redact(obj: Any) -> Any:
    """Return a copy with sensitive fields and embedded secret literals masked."""
    global _SKIP_LITERAL_VALUES
    _SKIP_LITERAL_VALUES = set()
    cloned = copy.deepcopy(obj)
    _register_skip_literals(cloned)
    secrets = _collect_secrets(cloned)
    return _deep_redact_node(cloned, secrets)


def _deep_redact_node(obj: Any, secrets: set[str], *, parent_key: str | None = None) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if k in _SKIP_REDACT_KEYS:
                out[k] = v
            elif _should_redact_key(k, parent_key=parent_key) and isinstance(v, str):
                out[k] = mask_sensitive(v) if v else v
            else:
                out[k] = _deep_redact_node(v, secrets, parent_key=k)
        return out
    if isinstance(obj, list):
        return [_deep_redact_node(x, secrets, parent_key=parent_key) for x in obj]
    if isinstance(obj, str):
        return _scrub_string(obj, secrets)
    return obj


def redact_analysis_dict(data: dict[str, Any]) -> dict[str, Any]:
    redacted = deep_redact(data)
    assert isinstance(redacted, dict)
    return redacted


def redact_export_json(data: dict[str, Any]) -> dict[str, Any]:
    """Same policy for single export, batch, and cloud sync payloads."""
    return redact_analysis_dict(data)
