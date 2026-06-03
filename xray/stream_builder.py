"""Build Xray streamSettings from ParsedConfig."""

from __future__ import annotations

import json
from typing import Any

from backend.models import ParsedConfig, TransportType


def _parse_nested_extra(config: ParsedConfig) -> dict[str, Any]:
    raw = config.extra.get("extra")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def build_stream_settings(config: ParsedConfig) -> dict[str, Any]:
    transport_map = {
        TransportType.TCP: "tcp",
        TransportType.WS: "ws",
        TransportType.GRPC: "grpc",
        TransportType.HTTPUPGRADE: "httpupgrade",
        TransportType.QUIC: "quic",
        TransportType.XHTTP: "xhttp",
    }
    stream: dict[str, Any] = {"network": transport_map.get(config.transport_type, "tcp")}

    if config.transport_type == TransportType.WS:
        stream["wsSettings"] = {
            "path": config.path or "/",
            "headers": {"Host": config.host or config.sni or config.address},
        }
    elif config.transport_type == TransportType.GRPC:
        stream["grpcSettings"] = {"serviceName": config.service_name or ""}
    elif config.transport_type == TransportType.XHTTP:
        xhttp: dict[str, Any] = {
            "path": config.path or "/",
            "host": config.host or config.sni or config.address,
            "mode": config.extra.get("mode", "auto"),
        }
        nested = _parse_nested_extra(config)
        if nested:
            xhttp["extra"] = nested
        stream["xhttpSettings"] = xhttp

    if config.reality:
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": config.sni or config.address,
            "publicKey": config.public_key or "",
            "shortId": config.short_id or "",
            "fingerprint": config.fingerprint or "chrome",
        }
    elif config.tls:
        stream["security"] = "tls"
        tls_settings: dict[str, Any] = {
            "serverName": config.sni or config.address,
            "allowInsecure": config.allow_insecure,
        }
        if config.alpn:
            tls_settings["alpn"] = [p.strip() for p in config.alpn.replace(" ", "").split(",") if p.strip()]
        if config.fingerprint:
            tls_settings["fingerprint"] = config.fingerprint
        stream["tlsSettings"] = tls_settings
    else:
        stream["security"] = "none"

    return stream
