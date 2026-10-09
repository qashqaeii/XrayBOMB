"""Architecture diagnostics, HTTP baseline, and WebSocket handshake tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from backend.architecture_diagnostics import build_architecture_diagnostics
from backend.models import (
    AnalysisResult,
    ConnectivityResult,
    DNSAnalysis,
    IPIntelligence,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TransportType,
    XrayTestResult,
)
from dns_analyzer.provider import detect_dns_provider


def _load_http_probe():
    path = Path(__file__).resolve().parents[1] / "network" / "http_probe.py"
    spec = importlib.util.spec_from_file_location("http_probe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_http_400_with_ws_version_is_valid_baseline():
    mod = _load_http_probe()
    label, note = mod.classify_http_baseline_status(400, {"sec-websocket-version": "13"})
    assert label == "Valid"
    assert "400" in note


def test_websocket_accept_validation():
    mod = _load_http_probe()
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    expected = mod._expected_ws_accept(key)
    ok, checks = mod.validate_websocket_handshake_response(
        101,
        {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-accept": expected,
        },
        key,
    )
    assert ok
    assert any("101" in c for c in checks)


def test_websocket_101_wrong_accept_fails():
    mod = _load_http_probe()
    ok, _ = mod.validate_websocket_handshake_response(
        101,
        {"upgrade": "websocket", "connection": "Upgrade", "sec-websocket-accept": "bad"},
        "dGhlIHNhbXBsZSBub25jZQ==",
    )
    assert not ok


def test_dns_provider_arvan_from_ns():
    provider, conf, ev = detect_dns_provider(["ns1.arvancloud.ir", "ns2.arvancloud.ir"])
    assert provider == "ArvanCloud"
    assert conf >= 0.55
    assert any("DNS provider" in e or "NS" in e for e in ev)


def test_sv1_fixture_cdn_unconfirmed_direct_probable():
    """Acceptance fixture — mocked observations, not live network."""
    config = ParsedConfig(
        protocol=ProtocolType.VLESS,
        address="sv1.20cloud.ir",
        port=80,
        uuid="00000000-0000-4000-8000-000000000099",
        transport_type=TransportType.WS,
        security="none",
        tls=False,
        path="/",
    )
    dns = DNSAnalysis(
        hostname="sv1.20cloud.ir",
        a_records=["185.204.169.162"],
        ns_records=["ns1.arvancloud.ir"],
        dns_provider="ArvanCloud",
        dns_provider_confidence=0.7,
    )
    network = [
        IPIntelligence(
            ip="185.204.169.162",
            asn="AS50810",
            organization="Afranet",
            cdn_detected=None,
            cdn_confidence=0.0,
        ),
    ]
    conn = ConnectivityResult(
        tcp_connect=TestStatus.VALID,
        tcp_latency_ms=42.0,
        http_baseline_status=TestStatus.VALID,
        http_baseline_status_code=400,
        http_baseline_note="HTTP 400 with Sec-WebSocket-Version",
        http_baseline_headers={"sec-websocket-version": "13"},
        websocket_upgrade=TestStatus.VALID,
        websocket_handshake_validated=True,
        websocket_handshake_status_code=101,
        websocket_upgrade_note="101 OK — Host=sv1.20cloud.ir",
    )
    xray = XrayTestResult(
        proxy_test=TestStatus.VALID,
        internet_e2e_verified=True,
        exit_ip="185.204.169.162",
    )
    result = AnalysisResult(
        config=config,
        dns=dns,
        network=network,
        connectivity=conn,
        xray_test=xray,
    )
    diag = build_architecture_diagnostics(result)
    cdn_line = next(i for i in diag.infrastructure if i.label == "CDN fronting")
    assert cdn_line.status == "unconfirmed"
    assert "Direct" in diag.assessment_title or "WebSocket" in diag.assessment_title
    ws_line = next(i for i in diag.connection_evidence if i.label == "WebSocket handshake")
    assert ws_line.status == "confirmed"
