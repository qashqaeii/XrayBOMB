"""Generate Xray client config from parsed config."""

from __future__ import annotations

import json
from typing import Any

from backend.models import ParsedConfig, ProtocolType
from xray.stream_builder import build_stream_settings


def generate_xray_client_config(config: ParsedConfig, socks_port: int = 10808) -> dict[str, Any]:
    stream = build_stream_settings(config)
    outbound = _build_outbound(config, stream)
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": socks_port, "protocol": "socks",
            "settings": {"udp": True}, "tag": "socks-in",
        }],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        "routing": {
            "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": "proxy"}],
        },
    }


def _build_outbound(config: ParsedConfig, stream: dict) -> dict:
    if config.protocol == ProtocolType.VLESS:
        return {
            "tag": "proxy", "protocol": "vless",
            "settings": {"vnext": [{"address": config.address, "port": config.port,
                "users": [{"id": config.uuid or "", "encryption": "none", "flow": config.flow or ""}]}]},
            "streamSettings": stream,
        }
    if config.protocol == ProtocolType.VMESS:
        return {
            "tag": "proxy", "protocol": "vmess",
            "settings": {"vnext": [{"address": config.address, "port": config.port,
                "users": [{"id": config.uuid or "", "alterId": 0, "security": config.encryption or "auto"}]}]},
            "streamSettings": stream,
        }
    if config.protocol == ProtocolType.TROJAN:
        return {
            "tag": "proxy", "protocol": "trojan",
            "settings": {"servers": [{"address": config.address, "port": config.port, "password": config.password or ""}]},
            "streamSettings": stream,
        }
    if config.protocol == ProtocolType.SHADOWSOCKS:
        return {
            "tag": "proxy", "protocol": "shadowsocks",
            "settings": {"servers": [{"address": config.address, "port": config.port,
                "method": config.encryption or "aes-256-gcm", "password": config.password or ""}]},
        }
    return {"tag": "proxy", "protocol": "freedom"}


def generate_client_config_json(config: ParsedConfig, indent: int = 2) -> str:
    return json.dumps(generate_xray_client_config(config), indent=indent)
