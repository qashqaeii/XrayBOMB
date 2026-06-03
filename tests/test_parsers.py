"""Unit tests for config parsers and security scoring."""

from __future__ import annotations

import pytest

from backend.config_parser import parse_share_link, parse_vless, parse_input
from backend.config_validator import validate_config
from backend.security import analyze_security
from backend.models import ConnectivityResult, ParsedConfig, ProtocolType, TLSAnalysis


VLESS_SAMPLE = (
    "vless://7bf723e1-ab1e-4a1e-9e17-0dfb78521c8c@vip.20cloud.ir:80"
    "?encryption=none&security=none&type=ws&host=vip.20cloud.ir&path=%2F#Users-VIP"
)


def test_parse_vless():
    cfg = parse_vless(VLESS_SAMPLE)
    assert cfg.protocol == ProtocolType.VLESS
    assert cfg.address == "vip.20cloud.ir"
    assert cfg.port == 80
    assert cfg.uuid == "7bf723e1-ab1e-4a1e-9e17-0dfb78521c8c"
    assert cfg.transport_type.value == "WebSocket"


def test_validate_config_ok():
    cfg = parse_vless(VLESS_SAMPLE)
    v = validate_config(cfg)
    assert v.valid is True


def test_validate_missing_uuid():
    cfg = ParsedConfig(protocol=ProtocolType.VLESS, address="example.com", port=443)
    v = validate_config(cfg)
    assert any(i.code == "MISSING_UUID" for i in v.issues)


def test_security_no_tls():
    cfg = parse_vless(VLESS_SAMPLE)
    report = analyze_security(cfg, TLSAnalysis(), ConnectivityResult(), [])
    assert report.score < 100
    assert any(f.title == "No TLS" for f in report.findings)
    assert len(report.recommendations) > 0


def test_parse_multi_line():
    text = VLESS_SAMPLE + "\n" + VLESS_SAMPLE
    configs = parse_input(text)
    assert len(configs) == 2
