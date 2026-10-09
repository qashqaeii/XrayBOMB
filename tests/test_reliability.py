"""Reliability and evidence correctness acceptance tests."""

from __future__ import annotations

import asyncio
import json
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.models import (
    ConnectivityResult,
    DeploymentAnalysis,
    DNSAnalysis,
    IPIntelligence,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TracerouteResult,
    TransportType,
    TunnelRoute,
    XrayTestResult,
)
from backend.confidence_engine import build_confidence_calibration
from backend.endpoint_targets import resolve_endpoint_targets
from backend.models import AnalysisResult, TunnelAnalysis
from backend.tunnel_detection import analyze_tunnels
from network.cdn_detector import detect_cdn
from network.transport_security import uses_tls_layer, websocket_scheme
from utils.port_allocator import allocate_loopback_port
from utils.redaction import deep_redact
from xray import manager as manager_mod
from xray import tester as tester_mod


FAKE_UUID = "00000000-0000-4000-8000-000000000001"
FAKE_PASS = "test-password-not-real"


def _vless_config(**kwargs) -> ParsedConfig:
    base = dict(
        protocol=ProtocolType.VLESS,
        address="example.com",
        port=443,
        uuid=FAKE_UUID,
        transport_type=TransportType.TCP,
        tls=True,
        sni="sni.example.com",
        host="host.example.com",
    )
    base.update(kwargs)
    return ParsedConfig(**base)


def test_allocate_independent_ports():
    ports = {allocate_loopback_port() for _ in range(4)}
    assert len(ports) == 4


def test_websocket_scheme_from_config_not_port():
    ws80 = _vless_config(port=80, tls=False, security="none", transport_type=TransportType.WS)
    ws2083 = _vless_config(port=2083, tls=True, security="tls", transport_type=TransportType.WS)
    assert websocket_scheme(ws80) == "ws"
    assert websocket_scheme(ws2083) == "wss"
    assert uses_tls_layer(ws2083)


@pytest.mark.asyncio
async def test_leak_check_no_definitive_leak_on_equal_ip():
    from xray import proxy_diagnostics as pd

    with patch.object(pd, "make_async_socks_client") as mock_socks, patch.object(
        pd, "make_direct_async_client",
    ) as mock_direct:
        mock_direct.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        mock_direct.return_value.__aexit__ = AsyncMock(return_value=False)
        direct_client = mock_direct.return_value.__aenter__.return_value
        direct_client.get = AsyncMock(side_effect=[
            MagicMock(json=lambda: {"ip": "1.2.3.4"}),
            MagicMock(text="1.2.3.4"),
        ])

        mock_socks.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        mock_socks.return_value.__aexit__ = AsyncMock(return_value=False)
        proxied = mock_socks.return_value.__aenter__.return_value
        proxied.get = AsyncMock(side_effect=[
            MagicMock(text="ip=1.2.3.4\nloc=DE"),
            MagicMock(json=lambda: {"ip": "1.2.3.4"}),
        ])

        leak = await pd.run_leak_check(20001, "example.com", client_ip="1.2.3.4")
    assert leak.ip_leak is None
    assert leak.exit_ip_same_observed is True
    assert leak.dns_leak_status == TestStatus.NOT_TESTED
    assert leak.dns_leak is None


@pytest.mark.asyncio
async def test_leak_check_dns_not_false_negative():
    from xray import proxy_diagnostics as pd

    with patch.object(pd, "_baseline_ips", AsyncMock(return_value=([], False))), patch.object(
        pd, "make_async_socks_client",
    ) as mock_socks:
        mock_socks.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
        mock_socks.return_value.__aexit__ = AsyncMock(return_value=False)
        proxied = mock_socks.return_value.__aenter__.return_value
        proxied.get = AsyncMock(return_value=MagicMock(text="ip=9.9.9.9\nloc=US"))
        leak = await pd.run_leak_check(20002, "example.com")
    assert leak.dns_leak is None
    assert leak.dns_leak_status == TestStatus.NOT_TESTED


def test_aws_asn_alone_not_cloudfront():
    cdn, conf = detect_cdn("3.5.6.7", org="Amazon Data Services", asn="AS16509")
    assert cdn != "CloudFront" or conf <= 0.35


def test_cdn_direct_xray_not_proven_without_cdn_absence():
    config = _vless_config()
    deployment = DeploymentAnalysis(cdn_type="Cloudflare")
    connectivity = ConnectivityResult(http_reverse_proxy=None)
    xray_ok = XrayTestResult(
        proxy_test=TestStatus.VALID,
        internet_e2e_verified=True,
        socks_handshake_verified=True,
        process_alive_after_e2e=True,
        e2e_contract_ok=True,
    )
    ta = analyze_tunnels(
        config,
        DNSAnalysis(a_records=["104.16.0.1"]),
        [IPIntelligence(ip="104.16.0.1", cdn_detected="Cloudflare", cdn_confidence=0.9)],
        connectivity,
        deployment,
        TracerouteResult(),
        TunnelRoute(),
        xray_ok,
    )
    ids = {m.tunnel_id for m in ta.detected_types}
    assert "direct_xray_inbound" not in ids


def test_confidence_cdn_keyword_not_proven_by_proxy_alone():
    config = _vless_config()
    from backend.models import TunnelTypeMatch

    r = AnalysisResult(
        config=config,
        xray_test=XrayTestResult(
            proxy_test=TestStatus.VALID,
            internet_e2e_verified=True,
            socks_handshake_verified=True,
            process_alive_after_e2e=True,
            e2e_contract_ok=True,
        ),
        tunnel_analysis=TunnelAnalysis(
            detected_types=[
                TunnelTypeMatch(
                    tunnel_id="cloudflare_cdn",
                    name="Cloudflare CDN",
                    confidence=0.8,
                    evidence=["cdn=Cloudflare", "internet_e2e_verified"],
                )
            ],
        ),
        deployment=DeploymentAnalysis(),
    )
    from backend.models import DPIDetectabilityReport, OriginExposureReport, TrafficCamouflageReport

    report, _, _ = build_confidence_calibration(
        r,
        r.tunnel_analysis,
        r.deployment,
        DPIDetectabilityReport(),
        TrafficCamouflageReport(),
        OriginExposureReport(),
    )
    tunnel_insights = [i for i in report.insights if i.category == "Tunnel"]
    assert all(i.confidence.value != "Proven" for i in tunnel_insights)


@pytest.mark.asyncio
async def test_xray_invalid_config_never_valid_even_if_port_open(monkeypatch):
    """Broken config must not inherit success from unrelated SOCKS on another port."""
    config = _vless_config(uuid="not-a-valid-uuid", address="127.0.0.1", port=9)

    class FakeManager:
        def is_installed(self):
            return True

        def get_version(self):
            return "Xray test"

        def build_temp_config(self, outbound, inbound_port, listen_host="127.0.0.1"):
            return {"inbounds": [], "outbounds": [outbound]}

        def write_config(self, cfg, path):
            path.write_text("{}", encoding="utf-8")

        def validate_config_file(self, path):
            return TestStatus.INVALID, "bad config"

        def start_background(self, *a, **k):
            raise AssertionError("should not start when validation fails")

        def stop_run(self, run):
            pass

    result = await tester_mod.test_config_with_xray(config, manager=FakeManager())
    assert result.status != TestStatus.VALID


@pytest.mark.asyncio
async def test_xray_dead_process_invalid(monkeypatch):
    config = _vless_config()

    class FakeProc:
        pid = 4242

        def poll(self):
            return 1

    class FakeRun:
        proc = FakeProc()

        def poll_exit(self):
            return 1

        def is_alive(self):
            return False

        def filtered_log(self):
            return "exit"

    class FakeManager:
        def is_installed(self):
            return True

        def get_version(self):
            return "Xray test"

        def build_temp_config(self, *a, **k):
            return {}

        def write_config(self, *a, **k):
            pass

        def validate_config_file(self, path):
            return TestStatus.VALID, "ok"

        def start_background(self, *a, **k):
            return FakeRun()

        async def wait_ready(self, run, **k):
            return True, "ready"

        def stop_run(self, run):
            pass

    async def fake_e2e(host, port):
        return TestStatus.VALID, 1.0, "ok"

    monkeypatch.setattr(tester_mod, "_test_socks_e2e", fake_e2e)
    result = await tester_mod.test_config_with_xray(config, manager=FakeManager())
    assert result.status == TestStatus.INVALID


def test_run_test_timeout_not_success():
    mgr = manager_mod.XrayManager()
    with patch.object(mgr, "is_installed", return_value=True), patch(
        "xray.manager.subprocess.Popen",
    ) as popen:
        proc = MagicMock()
        proc.communicate.side_effect = [
            manager_mod.subprocess.TimeoutExpired("xray", 1),
            ("", "stderr"),
        ]
        proc.kill = MagicMock()
        popen.return_value = proc
        code, _, err = mgr.run_test(MagicMock(), timeout=1)
    assert code == -2
    assert "Timed out" in err


def test_deep_redact_raw_and_config():
    payload = {
        "config": {"uuid": FAKE_UUID, "password": FAKE_PASS, "raw_url": f"vless://{FAKE_UUID}@x"},
        "raw_data": {"nested": {"public_key": "abcd1234efgh5678"}},
    }
    red = deep_redact(payload)
    assert FAKE_UUID not in json.dumps(red)
    assert FAKE_PASS not in json.dumps(red)
    assert "vless://" not in json.dumps(red)


@pytest.mark.asyncio
async def test_endpoint_targets_separate_sni(monkeypatch):
    async def fake_dns(host):
        return DNSAnalysis(hostname=host, a_records=[f"10.0.0.{len(host) % 5 + 1}"])

    with patch("backend.endpoint_targets.analyze_dns", fake_dns):
        cfg = _vless_config(address="connect.test", sni="sni.test", host="host.test")
        ep = await resolve_endpoint_targets(cfg)
    assert ep.dns_connect.hostname == "connect.test"
    assert ep.dns_sni and ep.dns_sni.hostname == "sni.test"
    assert ep.dns_host and ep.dns_host.hostname == "host.test"


def test_grpc_not_confirmed():
    from network.transport_tests import test_grpc

    result = asyncio.run(test_grpc("x", 443, "svc", "sni"))
    assert result.status == TestStatus.UNSUPPORTED


def test_reality_external_unsupported():
    from network.transport_tests import test_reality_fingerprint

    cfg = _vless_config(reality=True, public_key="pk")
    result = asyncio.run(test_reality_fingerprint(cfg, "x", 443))
    assert result.status == TestStatus.UNSUPPORTED
