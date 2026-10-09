"""Effective client-facing parameters (same rules as Xray stream builder)."""

from __future__ import annotations

from backend.models import ParsedConfig
from xray.stream_builder import build_stream_settings


def effective_client_params(config: ParsedConfig) -> dict[str, str]:
    """Values the local Xray outbound would apply (explicit + defaults)."""
    stream = build_stream_settings(config)
    network = stream.get("network", "tcp")
    security = stream.get("security", "none")

    effective_sni = config.sni or config.address
    effective_host = config.host or config.sni or config.address
    effective_path = config.path or "/"

    if network == "ws":
        ws = stream.get("wsSettings") or {}
        headers = ws.get("headers") or {}
        effective_host = headers.get("Host") or effective_host
        effective_path = ws.get("path") or effective_path
    elif network == "xhttp":
        xh = stream.get("xhttpSettings") or {}
        effective_host = xh.get("host") or effective_host
        effective_path = xh.get("path") or effective_path

    if security == "reality":
        rs = stream.get("realitySettings") or {}
        effective_sni = rs.get("serverName") or effective_sni
    elif security == "tls":
        ts = stream.get("tlsSettings") or {}
        effective_sni = ts.get("serverName") or effective_sni

    return {
        "network": str(network),
        "security": str(security),
        "connect_address": config.address,
        "connect_port": str(config.port or 443),
        "effective_sni": effective_sni,
        "effective_host": effective_host,
        "effective_path": effective_path,
        "service_name": config.service_name or "",
    }
