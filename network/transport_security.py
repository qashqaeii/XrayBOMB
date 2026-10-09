"""Map config security fields to wire scheme choices."""

from __future__ import annotations

from backend.models import ParsedConfig


def uses_tls_layer(config: ParsedConfig) -> bool:
    if config.reality:
        return True
    if config.tls:
        return True
    sec = (config.security or "").lower()
    return sec in ("tls", "reality", "xtls")


def websocket_scheme(config: ParsedConfig) -> str:
    return "wss" if uses_tls_layer(config) else "ws"


def http_scheme(config: ParsedConfig) -> str:
    return "https" if uses_tls_layer(config) else "http"
