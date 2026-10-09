"""Cross-tab consistency driven by ArchitectureDiagnosticsReport."""

from backend.architecture_consistency import align_analysis_with_architecture
from backend.architecture_diagnostics import build_architecture_diagnostics
from backend.models import (
    AnalysisResult,
    ConnectivityResult,
    DeploymentAnalysis,
    DeploymentGuess,
    DeploymentSetupGuide,
    DNSAnalysis,
    IPIntelligence,
    LeakCheckResult,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TransportType,
    TunnelAnalysis,
    TunnelTypeMatch,
    XrayTestResult,
)
from backend.result_summary import build_result_summary, _build_ranked_scenarios


def _sv1_result() -> AnalysisResult:
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
        dns_provider="ArvanCloud",
    )
    network = [
        IPIntelligence(ip="185.204.169.162", asn="AS50810", organization="Afranet"),
    ]
    conn = ConnectivityResult(
        tcp_connect=TestStatus.VALID,
        http_baseline_status=TestStatus.VALID,
        http_baseline_status_code=400,
        websocket_upgrade=TestStatus.VALID,
        websocket_handshake_validated=True,
        websocket_handshake_status_code=101,
    )
    xray = XrayTestResult(
        proxy_test=TestStatus.VALID,
        internet_e2e_verified=True,
        exit_ip="185.204.169.162",
        leak_check=LeakCheckResult(ip_leak=None, dns_leak=None),
    )
    deployment = DeploymentAnalysis(
        cdn_type="ArvanCloud",
        guesses=[
            DeploymentGuess(name="Arvan CDN", confidence=0.92, description="heuristic"),
            DeploymentGuess(name="Direct VPS", confidence=0.45, description=""),
        ],
    )
    tunnel_analysis = TunnelAnalysis(
        primary_type="Arvan CDN Fronting",
        detected_types=[
            TunnelTypeMatch(
                tunnel_id="arvan_cdn",
                name="Arvan CDN Fronting",
                confidence=0.92,
                evidence=["cdn=ArvanCloud"],
            ),
            TunnelTypeMatch(
                tunnel_id="direct_vps",
                name="Direct VPS Connection",
                confidence=0.60,
                evidence=["dns_a=185.204.169.162"],
            ),
        ],
    )
    r = AnalysisResult(
        config=config,
        dns=dns,
        network=network,
        connectivity=conn,
        xray_test=xray,
        deployment=deployment,
        tunnel_analysis=tunnel_analysis,
        setup_guide=DeploymentSetupGuide(detected_scenario="Arvan CDN", scenario_confidence=0.92),
    )
    r = r.model_copy(update={"architecture_diagnostics": build_architecture_diagnostics(r)})
    return align_analysis_with_architecture(r)


def test_sv1_cdn_unconfirmed_and_direct_not_ruled_out():
    r = _sv1_result()
    assert r.deployment.cdn_type is None
    assert r.architecture_diagnostics.cdn_fronting_tier == "unconfirmed"
    ranked = _build_ranked_scenarios(r)
    direct = next(s for s in ranked if s.tunnel_id == "direct_vps")
    assert direct.confidence >= 0.48
    arvan = next(s for s in ranked if s.tunnel_id == "arvan_cdn")
    assert arvan.confidence <= 0.42


def test_sv1_result_summary_no_high_cdn_percent():
    r = _sv1_result()
    text = build_result_summary(r)
    assert "92%" not in text
    assert "Origin hidden behind CDN" not in text
    assert "RULED OUT" not in text or "direct_vps" not in text.lower()
    assert "unconfirmed" in text.lower() or "Unconfirmed" in text
