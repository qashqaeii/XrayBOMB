"""Tests for deployment setup guide scenario selection."""

from backend.deployment_guide import build_deployment_setup_guide
from backend.models import (
    ConnectivityResult,
    DeploymentAnalysis,
    DeploymentGuess,
    DNSAnalysis,
    ParsedConfig,
    ProtocolType,
    TracerouteResult,
    TunnelAnalysis,
    TunnelRoute,
    TLSAnalysis,
)


def _minimal_guide(tunnel_analysis: TunnelAnalysis | None = None):
    deployment = DeploymentAnalysis(
        guesses=[DeploymentGuess(name="Direct VPS", confidence=0.85, description="test")],
    )
    return build_deployment_setup_guide(
        ParsedConfig(protocol=ProtocolType.VLESS, address="1.2.3.4", port=443, uuid="u"),
        deployment,
        TLSAnalysis(),
        DNSAnalysis(),
        [],
        ConnectivityResult(),
        TunnelRoute(),
        TracerouteResult(),
        tunnel_analysis=tunnel_analysis,
    )


def test_zero_confidence_not_replaced_by_deployment_guess():
    ta = TunnelAnalysis(primary_type="Reverse Tunnel", primary_confidence=0.0)
    guide = _minimal_guide(ta)
    assert guide.scenario_confidence == 0.0
    assert guide.detected_scenario == "Reverse Tunnel"


def test_empty_primary_type_kept_when_tunnel_analysis_present():
    ta = TunnelAnalysis(primary_type="", primary_confidence=0.0)
    guide = _minimal_guide(ta)
    assert guide.detected_scenario == ""
    assert guide.scenario_confidence == 0.0


def test_fallback_when_tunnel_analysis_missing():
    guide = _minimal_guide(None)
    assert guide.detected_scenario == "Direct VPS"
    assert guide.scenario_confidence == 0.85
