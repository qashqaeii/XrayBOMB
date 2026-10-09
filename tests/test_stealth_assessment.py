"""Tests for DPI, camouflage, origin exposure, and confidence calibration."""

from backend.models import (
    AnalysisResult,
    ConfidenceLevel,
    ConnectivityResult,
    DeploymentAnalysis,
    DNSAnalysis,
    IPIntelligence,
    LeakCheckResult,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TransportType,
    XrayTestResult,
)
from backend.stealth_assessment import (
    assess_stealth,
    build_camouflage_report,
    build_dpi_report,
    build_origin_exposure_report,
)


def _reality_vless() -> AnalysisResult:
    return AnalysisResult(
        config=ParsedConfig(
            protocol=ProtocolType.VLESS,
            address="cdn.example.com",
            port=443,
            uuid="u",
            reality=True,
            tls=True,
            flow="xtls-rprx-vision",
            fingerprint="chrome",
            public_key="pk",
            short_id="ab",
            sni="www.cloudflare.com",
            alpn="h2,http/1.1",
            transport_type=TransportType.TCP,
        ),
        connectivity=ConnectivityResult(
            tcp_connect=TestStatus.VALID,
            tls_handshake=TestStatus.VALID,
            reality_test=TestStatus.VALID,
            http_cdn_detected="Cloudflare",
        ),
        dns=DNSAnalysis(
            hostname="cdn.example.com",
            a_records=["104.16.1.1"],
            all_resolved_ips=["104.16.1.1"],
        ),
        network=[IPIntelligence(ip="104.16.1.1", cdn_detected="Cloudflare", reputation_score=80)],
        deployment=DeploymentAnalysis(cdn_type="Cloudflare"),
        xray_test=XrayTestResult(
            proxy_test=TestStatus.VALID,
            exit_ip="104.16.2.2",
            leak_check=LeakCheckResult(ip_leak=False),
        ),
    )


def test_strong_reality_high_dpi_and_camouflage():
    r = assess_stealth(_reality_vless())
    assert r.dpi.score >= 75
    assert r.camouflage.score >= 75
    assert r.dpi.detection_risk == "Low"
    assert r.camouflage.grade in ("A", "B")


def test_direct_ip_high_origin_exposure():
    r = _reality_vless()
    r.config.address = "185.1.2.3"
    assessed = assess_stealth(r)
    assert assessed.origin_exposure.risk_score >= 25
    assert assessed.origin_exposure.exposure_level in ("partial", "exposed")
    assert assessed.origin_exposure.inferred_origin_ip == "185.1.2.3"


def test_vmess_ws_lower_dpi_than_reality():
    weak = _reality_vless()
    weak.config.protocol = ProtocolType.VMESS
    weak.config.reality = False
    weak.config.tls = True
    weak.config.transport_type = TransportType.WS
    weak.config.port = 8080
    weak.config.fingerprint = None
    strong = _reality_vless()
    assert build_dpi_report(weak).score < build_dpi_report(strong).score
    assert build_camouflage_report(weak).score < build_camouflage_report(strong).score


def test_confidence_calibration_populated():
    r = assess_stealth(_reality_vless())
    assert r.confidence_calibration.insights
    assert any(i.category == "DPI" for i in r.confidence_calibration.insights)
    assert r.tunnel_analysis.primary_confidence_level is not None
    assert "Proven" in r.confidence_calibration.summary or "Strong" in r.confidence_calibration.summary


def test_cdn_exit_differs_from_dns_reduces_origin_risk():
    r = _reality_vless()
    origin = build_origin_exposure_report(r)
    assert origin.risk_score is not None
    assert origin.risk_score < 40


def test_no_config_no_fake_default_scores():
    empty = assess_stealth(AnalysisResult(config=ParsedConfig()))
    assert empty.dpi.score is None
    assert empty.camouflage.score is None
    assert empty.origin_exposure.risk_score is None
    assert "Insufficient" in empty.dpi.summary or "No origin" in empty.origin_exposure.summary


def test_dpi_pattern_db_penalizes_plain_vmess_ws():
    r = _reality_vless()
    r.config.protocol = ProtocolType.VMESS
    r.config.reality = False
    r.config.tls = False
    r.config.transport_type = TransportType.WS
    r.config.port = 80
    report = build_dpi_report(r)
    pattern_titles = [f.title for f in report.factors]
    assert any("Pattern:" in t for t in pattern_titles)


def test_cdn_demotes_direct_xray_inbound_confidence():
    """Direct Xray Inbound must not stay Proven when Arvan CDN is strongly detected."""
    from backend.tunnel_detection import analyze_tunnels

    r = _reality_vless()
    r.deployment = DeploymentAnalysis(cdn_type="ArvanCloud")
    r.connectivity.http_cdn_detected = "ArvanCloud"
    r.network = [
        IPIntelligence(ip="104.16.1.1", cdn_detected="ArvanCloud", cdn_confidence=0.92, asn="AS202585"),
    ]
    tunnel = analyze_tunnels(
        r.config, r.dns, r.network, r.connectivity, r.deployment,
        r.traceroute, r.tunnel, r.xray_test,
    )
    r.tunnel_analysis = tunnel
    assessed = assess_stealth(r)

    direct = next((m for m in assessed.tunnel_analysis.detected_types if m.tunnel_id == "direct_xray_inbound"), None)
    arvan = next((m for m in assessed.tunnel_analysis.detected_types if m.tunnel_id == "arvan_cdn"), None)
    assert arvan is not None
    assert direct is None


def _level_rank(level: ConfidenceLevel) -> int:
    order = (
        ConfidenceLevel.PROVEN,
        ConfidenceLevel.STRONG,
        ConfidenceLevel.WEAK,
        ConfidenceLevel.SPECULATIVE,
    )
    return order.index(level)
