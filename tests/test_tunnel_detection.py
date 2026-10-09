"""Tests for tunnel type detection."""

from backend.models import (
    ConnectivityResult,
    DeploymentAnalysis,
    DeploymentGuess,
    DNSAnalysis,
    IPIntelligence,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TracerouteResult,
    TransportType,
    TunnelRoute,
)
from backend.tunnel_detection import analyze_tunnels


def _cloudflare_vless_config() -> ParsedConfig:
    return ParsedConfig(
        protocol=ProtocolType.VLESS,
        address="104.16.90.120",
        port=443,
        uuid="1ffa3aab-e02a-469e-83f6-0843402e80df",
        tls=True,
        sni="52hp.siddns.shop",
        host="52hp.siddns.shop",
        alpn="h2",
        path="/testpath",
        transport_type=TransportType.XHTTP,
        remark="tls_h2 xhttp CDN dl=h2",
        extra={"type": "xhttp"},
    )


def test_cloudflare_cdn_and_sni_fronting_detected():
    config = _cloudflare_vless_config()
    dns = DNSAnalysis(
        hostname="52hp.siddns.shop",
        a_records=["188.114.97.3", "188.114.96.3"],
    )
    network = [
        IPIntelligence(
            ip="188.114.97.3", asn="AS13335", organization="Cloudflare, Inc.",
            cdn_detected="Cloudflare", cdn_confidence=0.9, is_datacenter=True,
        ),
    ]
    deployment = DeploymentAnalysis(
        cdn_type="Cloudflare",
        cdn_backend_ips=["188.114.97.3"],
        real_server_ip="104.16.90.120",
        guesses=[
            DeploymentGuess(name="CDN Fronted", confidence=0.95, description=""),
            DeploymentGuess(name="Cloudflare CDN", confidence=0.90, description=""),
        ],
    )
    result = analyze_tunnels(
        config, dns, network, ConnectivityResult(tcp_connect=TestStatus.VALID),
        deployment, TracerouteResult(hop_count=12),
        TunnelRoute(route_display="🇮🇷 Iran  →  🇨🇦 Canada"),
    )
    ids = {t.tunnel_id for t in result.detected_types}
    assert "cloudflare_cdn" in ids
    assert "cdn_fronting" in ids
    assert "sni_fronting" in ids
    assert result.primary_type
    assert "Cloudflare" in result.primary_type or "CDN" in result.primary_type


def test_reality_tunnel_detected():
    config = ParsedConfig(
        protocol=ProtocolType.VLESS, address="1.2.3.4", port=443,
        uuid="x", reality=True, sni="www.google.com", public_key="abc",
    )
    result = analyze_tunnels(
        config, DNSAnalysis(), [], ConnectivityResult(),
        DeploymentAnalysis(), TracerouteResult(), TunnelRoute(),
    )
    assert any(t.tunnel_id == "reality_camouflage" for t in result.detected_types)


def test_arvan_http_cdn_and_direct_xray_not_reverse_proxy():
    from backend.models import XrayTestResult

    config = ParsedConfig(
        protocol=ProtocolType.VLESS,
        address="vip.hushi.ir",
        port=443,
        uuid="x",
        tls=True,
        sni="vip.hushi.ir",
        path="/WS",
        transport_type=TransportType.WS,
    )
    dns = DNSAnalysis(
        hostname="vip.hushi.ir",
        a_records=["178.83.46.253"],
        all_resolved_ips=["178.83.46.253", "185.143.233.234"],
        dns_split_detected=True,
    )
    network = [
        IPIntelligence(ip="185.143.233.234", cdn_detected="ArvanCloud", cdn_confidence=0.9),
        IPIntelligence(ip="178.83.46.253", country_code="US"),
    ]
    conn = ConnectivityResult(
        http_server_header="ArvanCloud",
        http_cdn_detected="ArvanCloud",
        http_panel_detected="3x-ui",
        websocket_upgrade=TestStatus.INVALID,
    )
    deployment = DeploymentAnalysis(
        cdn_type="ArvanCloud",
        cdn_backend_ips=["185.143.233.234"],
        guesses=[DeploymentGuess(name="Arvan CDN", confidence=0.92, description="")],
    )
    xray = XrayTestResult(
        proxy_test=TestStatus.VALID,
        internet_e2e_verified=True,
        socks_handshake_verified=True,
        process_alive_after_e2e=True,
        e2e_contract_ok=True,
        exit_ip="178.83.46.253",
        exit_country="US",
    )

    result = analyze_tunnels(
        config, dns, network, conn, deployment, TracerouteResult(), TunnelRoute(), xray,
    )
    ids = {t.tunnel_id for t in result.detected_types}
    assert "arvan_cdn" in ids
    assert "direct_xray_inbound" not in ids
    assert "reverse_proxy" not in ids
    arvan = next(t for t in result.detected_types if t.tunnel_id == "arvan_cdn")
    assert arvan.confidence >= 0.85
