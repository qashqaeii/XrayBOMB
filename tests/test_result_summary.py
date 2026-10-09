"""Tests for comprehensive Result tab scenario engine."""

from backend.models import (
    AnalysisResult,
    ConfigOptimizationReport,
    ConnectivityResult,
    DeploymentAnalysis,
    DeploymentGuess,
    DNSAnalysis,
    IPIntelligence,
    OptimizationAction,
    OptimizationPriority,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TransportType,
    TunnelAnalysis,
    TunnelTypeMatch,
    XrayTestResult,
)
from backend.result_summary import build_result_summary


def _arvan_ws_config() -> ParsedConfig:
    return ParsedConfig(
        protocol=ProtocolType.VLESS,
        address="vip.example.ir",
        port=80,
        uuid="7bf723e1-ab1e-4a1e-9e17-0dfb78521c8c",
        security="none",
        tls=False,
        host="vip.example.ir",
        path="/",
        transport_type=TransportType.WS,
    )


def test_result_includes_verdict_and_enhanced_sections():
    r = AnalysisResult(
        config=_arvan_ws_config(),
        dns=DNSAnalysis(
            hostname="vip.example.ir",
            a_records=["185.143.233.234", "185.143.234.234"],
            all_resolved_ips=["185.143.233.234", "185.143.234.234"],
        ),
        network=[
            IPIntelligence(
                ip="185.143.233.234",
                country="Iran",
                country_code="IR",
                asn="AS202468",
                cdn_detected="ArvanCloud",
                cdn_confidence=0.90,
                is_datacenter=True,
            ),
        ],
        connectivity=ConnectivityResult(
            tcp_connect=TestStatus.VALID,
            tcp_latency_ms=45.0,
            websocket_upgrade=TestStatus.VALID,
            http_response=TestStatus.VALID,
        ),
        deployment=DeploymentAnalysis(
            cdn_type="ArvanCloud",
            cdn_backend_ips=["185.143.233.234"],
            guesses=[
                DeploymentGuess(name="Arvan CDN", confidence=0.90, description="Arvan edge detected"),
                DeploymentGuess(name="CDN Fronted", confidence=0.85, description="CDN fronting"),
                DeploymentGuess(name="Reverse Proxy", confidence=0.55, description="WS transport"),
            ],
            uncertain_fields=["Real server IP", "IP Origin behind CDN"],
        ),
        optimization=ConfigOptimizationReport(
            iran_score=42,
            grade="D",
            sell_readiness=35,
            verdict="Needs TLS upgrade for Iran market",
            actions=[
                OptimizationAction(
                    priority=OptimizationPriority.CRITICAL,
                    priority_rank=1,
                    title="Enable TLS or REALITY",
                    description="Plain WS is blockable",
                    score_gain=30,
                ),
            ],
        ),
        tunnel_analysis=TunnelAnalysis(
            primary_type="Arvan CDN Fronting",
            primary_tunnel_id="arvan_cdn",
            primary_confidence=0.92,
            traffic_flow="Client → Arvan edge → origin VPS",
            detected_types=[
                TunnelTypeMatch(
                    tunnel_id="arvan_cdn",
                    name="Arvan CDN Fronting",
                    category="cdn",
                    confidence=0.92,
                    evidence=["cdn=ArvanCloud", "ips=185.143.233.234"],
                    traffic_flow="Client → Arvan edge → origin VPS",
                    description="Arvan CDN in front of the server.",
                    setup_steps=["Arvan panel → CDN → vip.example.ir"],
                ),
                TunnelTypeMatch(
                    tunnel_id="reverse_proxy",
                    name="Reverse Proxy (Nginx/Caddy/HAProxy)",
                    category="reverse_proxy",
                    confidence=0.55,
                    evidence=["transport=WebSocket"],
                    traffic_flow="Client → :80 Nginx → localhost:Xray",
                    description="Nginx forwards WS to Xray.",
                    setup_steps=["Nginx location / → proxy_pass localhost"],
                ),
                TunnelTypeMatch(
                    tunnel_id="direct_vps",
                    name="Direct VPS Connection",
                    category="direct",
                    confidence=0.25,
                    evidence=["heuristic"],
                    traffic_flow="Client → server",
                    description="Direct",
                    setup_steps=[],
                ),
            ],
        ),
    )
    text = build_result_summary(r)

    assert "VERDICT" in text
    assert "MOST LIKELY" in text
    assert "MOST LIKELY SCENARIO" in text
    assert "Arvan CDN Fronting" in text
    assert "Exit IP intelligence" in text
    assert "Origin location hypotheses" in text
    assert "Origin country unknown" in text
    assert "Connectivity & transport tests" in text
    assert "Iran market & filtering context" in text
    assert "Prioritized security actions" in text
    assert "TOPOLOGY CATALOG COVERAGE" in text
    assert "CDN EDGE" in text
    assert "Origin (hidden)" in text or "edge" in text.lower()


def test_result_shows_exit_intel_and_origin_hypotheses():
    r = AnalysisResult(
        config=_arvan_ws_config(),
        dns=DNSAnalysis(hostname="vip.example.ir", a_records=["185.143.233.234", "185.143.234.234"]),
        network=[
            IPIntelligence(
                ip="185.143.233.234",
                country="Iran",
                country_code="IR",
                cdn_detected="ArvanCloud",
                cdn_confidence=0.90,
            ),
        ],
        deployment=DeploymentAnalysis(cdn_type="ArvanCloud", cdn_backend_ips=["185.143.233.234"]),
        xray_test=XrayTestResult(
            proxy_test=TestStatus.VALID,
            proxy_latency_ms=767.9,
            exit_ip="185.204.171.220",
            exit_country="DE",
            leak_check__dict=None,
        ),
        raw_data={
            "exit_intel": {
                "ip": "185.204.171.220",
                "country": "Germany",
                "country_code": "DE",
                "asn": "AS16276",
                "organization": "OVH GmbH",
                "is_datacenter": True,
                "reputation_score": 55,
            },
        },
        tunnel_analysis=TunnelAnalysis(
            primary_type="Arvan CDN Fronting",
            primary_tunnel_id="arvan_cdn",
            primary_confidence=0.90,
            detected_types=[
                TunnelTypeMatch(
                    tunnel_id="arvan_cdn",
                    name="Arvan CDN Fronting",
                    category="cdn",
                    confidence=0.90,
                    evidence=["cdn=ArvanCloud"],
                    traffic_flow="Client → Arvan edge → origin VPS",
                    description="Arvan CDN",
                    setup_steps=[],
                ),
            ],
        ),
    )
    text = build_result_summary(r)

    assert "185.204.171.220" in text
    assert "OVH" in text
    assert "Origin location hypotheses" in text
    assert "Foreign origin VPS" in text
    assert "Latency interpretation" in text
    assert "slow" in text.lower() or "767" in text
    assert "Low probability scenarios" not in text or "Direct VPS" in text


def test_confidence_capped_and_low_scenarios_bucket():
    r = AnalysisResult(
        config=_arvan_ws_config(),
        dns=DNSAnalysis(hostname="vip.example.ir", a_records=["185.143.233.234", "185.143.234.234"]),
        network=[
            IPIntelligence(
                ip="185.143.233.234", country_code="IR", cdn_detected="ArvanCloud", cdn_confidence=0.95,
            ),
        ],
        deployment=DeploymentAnalysis(cdn_type="ArvanCloud"),
        xray_test=XrayTestResult(
            proxy_test=TestStatus.VALID, exit_ip="1.2.3.4", exit_country="DE",
        ),
        tunnel_analysis=TunnelAnalysis(
            primary_tunnel_id="arvan_cdn",
            primary_type="Arvan CDN Fronting",
            primary_confidence=0.95,
            detected_types=[
                TunnelTypeMatch(
                    tunnel_id="arvan_cdn", name="Arvan CDN Fronting", category="cdn",
                    confidence=0.95, evidence=[], traffic_flow="", description="", setup_steps=[],
                ),
                TunnelTypeMatch(
                    tunnel_id="direct_vps", name="Direct VPS Connection", category="direct",
                    confidence=0.25, evidence=[], traffic_flow="", description="", setup_steps=[],
                ),
            ],
        ),
    )
    text = build_result_summary(r)
    assert "98%" not in text
    assert "92%" in text or "91%" in text or "90%" in text
    assert "Low probability scenarios" in text


def test_reality_scenario_playbook():
    r = AnalysisResult(
        config=ParsedConfig(
            protocol=ProtocolType.VLESS,
            address="edge.example.com",
            port=443,
            uuid="aaa-bbb-ccc",
            tls=False,
            reality=True,
            sni="www.google.com",
            public_key="abc123",
            short_id="abcd",
            transport_type=TransportType.TCP,
            flow="xtls-rprx-vision",
        ),
        tunnel_analysis=TunnelAnalysis(
            primary_type="REALITY Camouflage Tunnel",
            primary_tunnel_id="reality_camouflage",
            primary_confidence=0.92,
            detected_types=[
                TunnelTypeMatch(
                    tunnel_id="reality_camouflage",
                    name="REALITY Camouflage Tunnel",
                    category="camouflage",
                    confidence=0.92,
                    evidence=["security=reality"],
                    traffic_flow="Client → REALITY handshake → Xray",
                    description="REALITY obfuscation.",
                    setup_steps=["REALITY inbound"],
                ),
            ],
        ),
    )
    text = build_result_summary(r)

    assert "REALITY CAMOUFLAGE" in text
    assert "www.google.com" in text
    assert "xtls-rprx-vision" in text
