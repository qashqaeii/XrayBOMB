"""Build share links from ParsedConfig (for optimized blueprints)."""

from __future__ import annotations

import urllib.parse

from backend.models import ParsedConfig, ProtocolType, TransportType


def _transport_param(config: ParsedConfig) -> str:
    mapping = {
        TransportType.TCP: "tcp",
        TransportType.WS: "ws",
        TransportType.GRPC: "grpc",
        TransportType.HTTPUPGRADE: "httpupgrade",
        TransportType.XHTTP: "xhttp",
        TransportType.QUIC: "quic",
    }
    return mapping.get(config.transport_type, config.extra.get("type", "tcp"))


def build_vless_link(config: ParsedConfig, remark: str | None = None) -> str | None:
    if config.protocol != ProtocolType.VLESS or not config.uuid or not config.address:
        return None
    params: dict[str, str] = {"type": _transport_param(config)}
    if config.reality:
        params["security"] = "reality"
        if config.public_key:
            params["pbk"] = config.public_key
        if config.short_id:
            params["sid"] = config.short_id
        if config.sni:
            params["sni"] = config.sni
        if config.fingerprint:
            params["fp"] = config.fingerprint
        if config.flow:
            params["flow"] = config.flow
    elif config.tls:
        params["security"] = "tls"
        if config.sni:
            params["sni"] = config.sni
        if config.fingerprint:
            params["fp"] = config.fingerprint
        if config.alpn:
            params["alpn"] = config.alpn.replace(", ", ",")
        if config.allow_insecure:
            params["allowInsecure"] = "1"
    else:
        params["security"] = "none"

    if config.host and config.transport_type in (TransportType.WS, TransportType.HTTPUPGRADE, TransportType.XHTTP):
        params["host"] = config.host
    if config.path:
        params["path"] = config.path
    if config.service_name and config.transport_type == TransportType.GRPC:
        params["serviceName"] = config.service_name
    for k, v in config.extra.items():
        if k not in params and k not in ("type", "security") and v:
            params[k] = str(v)

    frag = remark or config.remark or ""
    user = urllib.parse.quote(config.uuid, safe="")
    query = urllib.parse.urlencode(params)
    base = f"vless://{user}@{config.address}:{config.port}?{query}"
    return f"{base}#{urllib.parse.quote(frag)}" if frag else base


def build_share_link(config: ParsedConfig, remark: str | None = None) -> str | None:
    if config.raw_url and not remark:
        return config.raw_url
    if config.protocol == ProtocolType.VLESS:
        return build_vless_link(config, remark)
    return config.raw_url
