"""Tests for English How to Run implementation guide."""

from backend.deployment_guide import build_deployment_setup_guide
from backend.how_to_run_fa import CATALOG_FA, SCENARIO_SECTIONS_FA
from backend.models import (
    ConnectivityResult,
    DeploymentAnalysis,
    DeploymentGuess,
    DNSAnalysis,
    IPIntelligence,
    ParsedConfig,
    ProtocolType,
    TracerouteResult,
    TransportType,
    TunnelAnalysis,
    TunnelRoute,
    TunnelTypeMatch,
    TLSAnalysis,
)
from backend.tunnel_detection import TUNNEL_CATALOG


def _arvan_ctx():
    config = ParsedConfig(
        protocol=ProtocolType.VLESS,
        address="185.143.233.234",
        port=443,
        uuid="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        sni="sub.example.ir",
        host="sub.example.ir",
        path="/ws-path",
        tls=True,
        transport_type=TransportType.WS,
    )
    deployment = DeploymentAnalysis(
        cdn_type="ArvanCloud",
        cdn_backend_ips=["185.143.233.234"],
        guesses=[DeploymentGuess(name="Arvan CDN", confidence=0.92, description="")],
    )
    dns = DNSAnalysis(hostname="sub.example.ir", a_records=["185.143.233.234"])
    network = [
        IPIntelligence(ip="185.143.233.234", cdn_detected="ArvanCloud", cdn_confidence=0.9),
    ]
    conn = ConnectivityResult(http_cdn_detected="ArvanCloud")
    tunnel_analysis = TunnelAnalysis(
        primary_type="Arvan CDN Fronting",
        primary_tunnel_id="arvan_cdn",
        primary_confidence=0.9,
        detected_types=[
            TunnelTypeMatch(
                tunnel_id="arvan_cdn",
                name="Arvan CDN Fronting",
                category="cdn",
                confidence=0.9,
                evidence=["cdn=ArvanCloud"],
                traffic_flow="Client → Arvan → origin",
                description="Arvan CDN",
                setup_steps=[],
            ),
        ],
    )
    return build_deployment_setup_guide(
        config, deployment, TLSAnalysis(), dns, network, conn,
        TunnelRoute(), TracerouteResult(), tunnel_analysis=tunnel_analysis,
    )


def test_how_to_run_populated_for_arvan():
    guide = _arvan_ctx()
    assert guide.how_to_run_text
    assert "Arvan" in guide.how_to_run_text
    assert "sub.example.ir" in guide.how_to_run_text
    assert "/ws-path" in guide.how_to_run_text
    assert "a1b2c3d4-e5f6-7890-abcd-ef1234567890" in guide.how_to_run_text


def test_no_fake_placeholder_ips():
    guide = _arvan_ctx()
    assert "1.2.3.4" not in guide.how_to_run_text


def test_3xui_steps_in_primary_scenario():
    guide = _arvan_ctx()
    assert "3x-ui" in guide.how_to_run_text


def test_guide_shows_only_detected_scenario():
    guide = _arvan_ctx()
    text = guide.how_to_run_text
    assert "Arvan" in text
    assert "WireGuard" not in text
    assert "Akamai CDN" not in text
    titles = [s.title for s in guide.how_to_run_sections]
    assert len(titles) == 3
    assert titles[1].startswith("Scenario:")


def test_origin_placeholder_when_unknown():
    config = ParsedConfig(protocol=ProtocolType.VLESS, address="cdn-edge.ir", port=443, tls=True)
    guide = build_deployment_setup_guide(
        config,
        DeploymentAnalysis(cdn_type="ArvanCloud"),
        TLSAnalysis(),
        DNSAnalysis(hostname="cdn-edge.ir"),
        [],
        ConnectivityResult(),
        TunnelRoute(),
        TracerouteResult(),
    )
    assert "<origin-vps-ip>" in guide.how_to_run_text


def test_all_catalog_scenarios_have_fa_builders():
    assert set(SCENARIO_SECTIONS_FA.keys()) == set(TUNNEL_CATALOG.keys())
    assert set(CATALOG_FA.keys()) == set(TUNNEL_CATALOG.keys())


def test_each_scenario_has_minimum_depth():
    builders = __import__("backend.how_to_run_fa", fromlist=["SCENARIO_SECTIONS_FA"]).SCENARIO_SECTIONS_FA
    from backend.deployment_guide import GuideContext
    from backend.how_to_run import _resolve_values

    ctx = GuideContext(
        config=ParsedConfig(
            protocol=ProtocolType.VLESS, address="sub.example.ir", port=443,
            sni="sub.example.ir", path="/ws", tls=True, transport_type=TransportType.WS,
        ),
        deployment=DeploymentAnalysis(cdn_type="ArvanCloud"),
        tls=TLSAnalysis(),
        dns=DNSAnalysis(hostname="sub.example.ir"),
        network=[],
        connectivity=ConnectivityResult(),
        tunnel=TunnelRoute(),
        traceroute=TracerouteResult(),
    )
    v = _resolve_values(ctx)
    for tid, fn in builders.items():
        sec = fn(v, ctx)
        assert len(sec.steps) >= 15, f"{tid} has only {len(sec.steps)} steps"
