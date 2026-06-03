"""Configuration parser for Xray/V2Ray share links and JSON configs."""

from __future__ import annotations

import json
import re
import urllib.parse
from typing import Any, Optional

import httpx

from backend.models import ParsedConfig, ProtocolType, TransportType
from utils.helpers import parse_query_params, safe_b64decode, try_parse_json
from utils.logger import get_logger

logger = get_logger(__name__)

PROTOCOL_SCHEMES = {
    "vless": ProtocolType.VLESS,
    "vmess": ProtocolType.VMESS,
    "trojan": ProtocolType.TROJAN,
    "ss": ProtocolType.SHADOWSOCKS,
    "hysteria2": ProtocolType.HYSTERIA2,
    "hy2": ProtocolType.HYSTERIA2,
    "tuic": ProtocolType.TUIC,
    "wireguard": ProtocolType.WIREGUARD,
    "wg": ProtocolType.WIREGUARD,
}


def _detect_transport(params: dict[str, str], protocol: ProtocolType) -> TransportType:
    """Detect transport type from query parameters."""
    network = params.get("type", params.get("network", "tcp")).lower()
    mapping = {
        "tcp": TransportType.TCP,
        "ws": TransportType.WS,
        "websocket": TransportType.WS,
        "grpc": TransportType.GRPC,
        "httpupgrade": TransportType.HTTPUPGRADE,
        "http": TransportType.HTTPUPGRADE,
        "xhttp": TransportType.XHTTP,
        "splithttp": TransportType.XHTTP,
        "quic": TransportType.QUIC,
        "hysteria2": TransportType.HYSTERIA2,
        "hy2": TransportType.HYSTERIA2,
        "tuic": TransportType.TUIC,
    }
    if protocol == ProtocolType.HYSTERIA2:
        return TransportType.HYSTERIA2
    if protocol == ProtocolType.TUIC:
        return TransportType.TUIC
    return mapping.get(network, TransportType.UNKNOWN)


def _parse_security(params: dict[str, str]) -> tuple[bool, bool, Optional[str]]:
    """Parse TLS/Reality security settings."""
    security = params.get("security", "").lower()
    tls = security in ("tls", "reality", "xtls")
    reality = security == "reality"
    fp = params.get("fp", params.get("fingerprint"))
    return tls, reality, fp


def parse_vless(url: str) -> ParsedConfig:
    """Parse VLESS share link."""
    parsed = urllib.parse.urlparse(url)
    params = parse_query_params(parsed.query)
    uuid = parsed.username or ""
    address = parsed.hostname or ""
    port = parsed.port or 443
    tls, reality, fp = _parse_security(params)
    alpn_raw = params.get("alpn", "")
    alpn = alpn_raw.replace(",", ", ") if alpn_raw else None
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

    return ParsedConfig(
        protocol=ProtocolType.VLESS,
        address=address,
        port=port,
        uuid=uuid,
        flow=params.get("flow"),
        security=params.get("security"),
        tls=tls,
        reality=reality,
        public_key=params.get("pbk"),
        short_id=params.get("sid"),
        sni=params.get("sni") or params.get("host"),
        host=params.get("host"),
        alpn=alpn,
        path=params.get("path"),
        service_name=params.get("serviceName"),
        transport_type=_detect_transport(params, ProtocolType.VLESS),
        fingerprint=fp,
        allow_insecure=params.get("allowInsecure", "0") == "1",
        remark=remark,
        raw_url=url,
        extra=params,
    )


def parse_vmess(url: str) -> ParsedConfig:
    """Parse VMESS share link (base64 encoded JSON)."""
    encoded = url.replace("vmess://", "").strip()
    try:
        data = json.loads(safe_b64decode(encoded).decode("utf-8"))
    except Exception as exc:
        logger.error("Failed to parse VMESS: %s", exc)
        return ParsedConfig(protocol=ProtocolType.VMESS, raw_url=url)

    network = data.get("net", data.get("type", "tcp")).lower()
    transport_map = {
        "tcp": TransportType.TCP,
        "ws": TransportType.WS,
        "grpc": TransportType.GRPC,
        "http": TransportType.HTTPUPGRADE,
        "quic": TransportType.QUIC,
    }
    tls_val = data.get("tls", "")
    tls = tls_val in ("tls", "xtls", "reality", True, "1")

    return ParsedConfig(
        protocol=ProtocolType.VMESS,
        address=data.get("add", data.get("host", "")),
        port=int(data.get("port", 443)),
        uuid=data.get("id", ""),
        encryption=data.get("scy", data.get("security", "auto")),
        flow=data.get("flow"),
        security=str(tls_val) if tls_val else None,
        tls=tls,
        sni=data.get("sni") or data.get("host"),
        host=data.get("host"),
        alpn=data.get("alpn"),
        path=data.get("path"),
        service_name=data.get("serviceName"),
        transport_type=transport_map.get(network, TransportType.UNKNOWN),
        fingerprint=data.get("fp"),
        allow_insecure=data.get("allowInsecure") in (True, "1", 1),
        remark=data.get("ps"),
        raw_url=url,
        extra=data,
    )


def parse_trojan(url: str) -> ParsedConfig:
    """Parse Trojan share link."""
    parsed = urllib.parse.urlparse(url)
    params = parse_query_params(parsed.query)
    password = parsed.username or ""
    address = parsed.hostname or ""
    port = parsed.port or 443
    tls, reality, fp = _parse_security(params)
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

    return ParsedConfig(
        protocol=ProtocolType.TROJAN,
        address=address,
        port=port,
        password=password,
        security=params.get("security", "tls"),
        tls=True,
        reality=reality,
        sni=params.get("sni") or params.get("peer") or address,
        host=params.get("host"),
        alpn=params.get("alpn"),
        path=params.get("path"),
        transport_type=_detect_transport(params, ProtocolType.TROJAN),
        fingerprint=fp,
        allow_insecure=params.get("allowInsecure", "0") == "1",
        remark=remark,
        raw_url=url,
        extra=params,
    )


def parse_shadowsocks(url: str) -> ParsedConfig:
    """Parse Shadowsocks share link."""
    body = url.replace("ss://", "").strip()
    remark = None
    if "#" in body:
        body, fragment = body.split("#", 1)
        remark = urllib.parse.unquote(fragment)

    method = password = host = ""
    port = 8388

    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        try:
            decoded = safe_b64decode(userinfo).decode("utf-8")
            method, password = decoded.split(":", 1)
        except Exception:
            parts = userinfo.split(":")
            if len(parts) >= 2:
                method, password = parts[0], parts[1]
        if ":" in hostport:
            host, port_str = hostport.rsplit(":", 1)
            port = int(port_str.split("/")[0].split("?")[0])
        else:
            host = hostport
    else:
        try:
            decoded = safe_b64decode(body).decode("utf-8")
            if "@" in decoded:
                creds, hostport = decoded.rsplit("@", 1)
                method, password = creds.split(":", 1)
                host, port_str = hostport.rsplit(":", 1)
                port = int(port_str)
        except Exception as exc:
            logger.error("Failed to parse SS: %s", exc)
            return ParsedConfig(protocol=ProtocolType.SHADOWSOCKS, raw_url=url)

    return ParsedConfig(
        protocol=ProtocolType.SHADOWSOCKS,
        address=host,
        port=port,
        password=password,
        encryption=method,
        transport_type=TransportType.TCP,
        remark=remark,
        raw_url=url,
    )


def parse_hysteria2(url: str) -> ParsedConfig:
    """Parse Hysteria2 share link."""
    parsed = urllib.parse.urlparse(url)
    params = parse_query_params(parsed.query)
    password = parsed.username or urllib.parse.unquote(parsed.password or "")
    address = parsed.hostname or ""
    port = parsed.port or 443
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

    return ParsedConfig(
        protocol=ProtocolType.HYSTERIA2,
        address=address,
        port=port,
        password=password,
        sni=params.get("sni"),
        alpn=params.get("alpn"),
        transport_type=TransportType.HYSTERIA2,
        tls=True,
        allow_insecure=params.get("insecure", "0") == "1",
        remark=remark,
        raw_url=url,
        extra=params,
    )


def parse_tuic(url: str) -> ParsedConfig:
    """Parse TUIC share link."""
    parsed = urllib.parse.urlparse(url)
    params = parse_query_params(parsed.query)
    uuid = parsed.username or ""
    password = urllib.parse.unquote(parsed.password or "")
    address = parsed.hostname or ""
    port = parsed.port or 443
    remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else None

    return ParsedConfig(
        protocol=ProtocolType.TUIC,
        address=address,
        port=port,
        uuid=uuid,
        password=password,
        sni=params.get("sni"),
        alpn=params.get("alpn"),
        transport_type=TransportType.TUIC,
        tls=True,
        allow_insecure=params.get("allow_insecure", "0") == "1",
        remark=remark,
        raw_url=url,
        extra=params,
    )


def parse_wireguard_conf(text: str) -> ParsedConfig:
    """Parse WireGuard .conf format."""
    address = port = private_key = public_key = endpoint = ""
    port_num = 51820
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        if "=" in line:
            key, val = line.split("=", 1)
            key, val = key.strip().lower(), val.strip()
            if key == "endpoint":
                endpoint = val
                if ":" in val:
                    host, p = val.rsplit(":", 1)
                    endpoint = host
                    try:
                        port_num = int(p)
                    except ValueError:
                        pass
            elif key == "privatekey":
                private_key = val
            elif key == "publickey":
                public_key = val
            elif key == "address":
                address = val.split("/")[0]
    return ParsedConfig(
        protocol=ProtocolType.WIREGUARD,
        address=endpoint or address,
        port=port_num,
        password=private_key or None,
        public_key=public_key or None,
        transport_type=TransportType.UNKNOWN,
        raw_url=text[:200],
        extra={"type": "wireguard"},
    )


def parse_openvpn(url_or_conf: str) -> ParsedConfig:
    """Parse OpenVPN config snippet or ovpn:// link."""
    text = url_or_conf.replace("openvpn://", "").strip()
    remote = port = 1194
    address = ""
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].lower() == "remote":
            address = parts[1]
            if len(parts) >= 3:
                try:
                    port = int(parts[2])
                except ValueError:
                    pass
    return ParsedConfig(
        protocol=ProtocolType.OPENVPN,
        address=address,
        port=port,
        transport_type=TransportType.TCP,
        tls=True,
        raw_url=url_or_conf[:200],
        extra={"type": "openvpn"},
    )


def parse_share_link(url: str) -> ParsedConfig:
    """Parse any supported share link."""
    url = url.strip()
    if url.lower().startswith("openvpn://") or "[openvpn]" in url.lower():
        return parse_openvpn(url)
    if "[interface]" in url.lower() and "wireguard" in url.lower() or url.strip().startswith("[Interface]"):
        return parse_wireguard_conf(url)
    for scheme, protocol in PROTOCOL_SCHEMES.items():
        if url.lower().startswith(f"{scheme}://"):
            parsers = {
                ProtocolType.VLESS: parse_vless,
                ProtocolType.VMESS: parse_vmess,
                ProtocolType.TROJAN: parse_trojan,
                ProtocolType.SHADOWSOCKS: parse_shadowsocks,
                ProtocolType.HYSTERIA2: parse_hysteria2,
                ProtocolType.TUIC: parse_tuic,
            }
            return parsers[protocol](url)

    return ParsedConfig(raw_url=url)


def parse_json_config(text: str) -> list[ParsedConfig]:
    """Parse Xray/V2Ray JSON config and extract outbound configs."""
    data = try_parse_json(text)
    if not data:
        return []

    configs: list[ParsedConfig] = []
    outbounds = data.get("outbounds", [])
    if isinstance(outbounds, dict):
        outbounds = [outbounds]

    for ob in outbounds:
        if not isinstance(ob, dict):
            continue
        protocol_str = ob.get("protocol", "").lower()
        settings = ob.get("settings", {})
        stream = ob.get("streamSettings", {})
        vnext = settings.get("vnext", [{}])
        servers = settings.get("servers", [{}])

        address, port, uuid, password = "", 443, None, None
        if vnext:
            node = vnext[0] if vnext else {}
            address = node.get("address", "")
            port = node.get("port", 443)
            users = node.get("users", [{}])
            if users:
                uuid = users[0].get("id")
                password = users[0].get("password")
        elif servers:
            srv = servers[0] if servers else {}
            address = srv.get("address", "")
            port = srv.get("port", 443)
            password = srv.get("password")

        network = stream.get("network", "tcp")
        security = stream.get("security", "none")
        tls_settings = stream.get("tlsSettings", stream.get("realitySettings", {}))
        ws_settings = stream.get("wsSettings", {})
        grpc_settings = stream.get("grpcSettings", {})

        protocol_map = {
            "vless": ProtocolType.VLESS,
            "vmess": ProtocolType.VMESS,
            "trojan": ProtocolType.TROJAN,
            "shadowsocks": ProtocolType.SHADOWSOCKS,
            "hysteria2": ProtocolType.HYSTERIA2,
            "hy2": ProtocolType.HYSTERIA2,
            "tuic": ProtocolType.TUIC,
        }

        transport_map = {
            "tcp": TransportType.TCP,
            "ws": TransportType.WS,
            "grpc": TransportType.GRPC,
            "httpupgrade": TransportType.HTTPUPGRADE,
            "quic": TransportType.QUIC,
        }

        configs.append(
            ParsedConfig(
                protocol=protocol_map.get(protocol_str, ProtocolType.UNKNOWN),
                address=address,
                port=port,
                uuid=uuid,
                password=password,
                encryption=settings.get("method"),
                security=security,
                tls=security in ("tls", "reality", "xtls"),
                reality=security == "reality",
                public_key=tls_settings.get("publicKey"),
                short_id=tls_settings.get("shortId"),
                sni=tls_settings.get("serverName"),
                host=ws_settings.get("headers", {}).get("Host"),
                path=ws_settings.get("path"),
                service_name=grpc_settings.get("serviceName"),
                transport_type=transport_map.get(network, TransportType.UNKNOWN),
                extra={"outbound": ob},
            )
        )

    return configs


async def fetch_subscription(url: str) -> list[ParsedConfig]:
    """Fetch and parse subscription link."""
    configs: list[ParsedConfig] = []
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            content = response.text.strip()

        # Try base64 decode
        try:
            from utils.helpers import safe_b64decode

            decoded = safe_b64decode(content.replace("\n", "")).decode("utf-8")
            content = decoded
        except Exception:
            pass

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("{") or line.startswith("["):
                configs.extend(parse_json_config(line))
            elif "://" in line:
                configs.append(parse_share_link(line))

    except Exception as exc:
        logger.error("Subscription fetch failed: %s", exc)
        raise ValueError(f"Subscription fetch failed: {exc}") from exc

    if not configs:
        raise ValueError("No valid configs found in subscription response.")

    return configs


def parse_input(text: str) -> list[ParsedConfig]:
    """Parse arbitrary input: share link, JSON, or multi-line subscription."""
    text = text.strip()
    if not text:
        return []

    if text.startswith("{") or text.startswith("["):
        return parse_json_config(text)

    if text.strip().startswith("[Interface]"):
        return [parse_wireguard_conf(text)]

    configs: list[ParsedConfig] = []
    for line in text.splitlines():
        line = line.strip()
        if line and "://" in line:
            configs.append(parse_share_link(line))

    if not configs and "://" in text:
        configs.append(parse_share_link(text))

    return configs
