"""Tests for share link builder."""

from backend.models import ParsedConfig, ProtocolType, TransportType
from backend.share_link_builder import build_vless_link


def test_build_vless_reality_link():
    cfg = ParsedConfig(
        protocol=ProtocolType.VLESS,
        address="sub.example.com",
        port=443,
        uuid="7bf723e1-ab1e-4a1e-9e17-0dfb78521c8c",
        reality=True,
        tls=True,
        public_key="abc",
        short_id="01",
        sni="www.microsoft.com",
        fingerprint="chrome",
        flow="xtls-rprx-vision",
        transport_type=TransportType.TCP,
        security="reality",
    )
    link = build_vless_link(cfg, remark="DE|REALITY")
    assert link.startswith("vless://")
    assert "security=reality" in link
    assert "pbk=abc" in link
    assert "fp=chrome" in link
