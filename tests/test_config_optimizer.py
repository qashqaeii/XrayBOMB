"""Tests for Iran-focused config optimizer."""

from backend.config_optimizer import build_config_optimization
from backend.models import (
    AnalysisResult,
    ConnectivityResult,
    DNSAnalysis,
    IPIntelligence,
    LeakCheckResult,
    ParsedConfig,
    ProtocolType,
    SecurityReport,
    TestStatus,
    XrayTestResult,
)


def _minimal_result() -> AnalysisResult:
    return AnalysisResult(
        config=ParsedConfig(
            protocol=ProtocolType.VLESS,
            address="cdn.example.com",
            port=443,
            uuid="test-uuid",
            reality=True,
            tls=True,
            flow="xtls-rprx-vision",
            fingerprint="chrome",
            public_key="pk",
            short_id="ab",
            sni="cdn.example.com",
        ),
        connectivity=ConnectivityResult(tcp_connect=TestStatus.VALID, tcp_latency_ms=80.0),
        dns=DNSAnalysis(hostname="cdn.example.com", a_records=["1.2.3.4"], all_resolved_ips=["1.2.3.4"]),
        network=[IPIntelligence(ip="1.2.3.4", reputation_score=75, cdn_detected="Cloudflare", country="DE")],
        security=SecurityReport(score=80, potential_score=90),
        xray_test=XrayTestResult(
            proxy_test=TestStatus.VALID,
            leak_check=LeakCheckResult(ip_leak=None, dns_leak=None),
        ),
    )


def test_strong_config_high_iran_score():
    r = _minimal_result()
    opt = build_config_optimization(r)
    assert opt.iran_score >= 50
    assert opt.grade in ("A", "B", "C")
    assert any(a.priority_rank == 1 for a in opt.actions) is False or opt.sell_readiness >= 40


def test_vmess_gets_migration_action():
    r = _minimal_result()
    r.config.protocol = ProtocolType.VMESS
    r.config.reality = False
    opt = build_config_optimization(r)
    titles = [a.title for a in opt.actions]
    assert any("VMess" in t for t in titles)


def test_blocklist_critical_action():
    r = _minimal_result()
    from backend.models import ThreatIntel
    r.threat_intel = [ThreatIntel(ip="1.2.3.4", blocklist_hits=["zen.spamhaus.org"])]
    opt = build_config_optimization(r)
    assert any("blocklist" in a.title.lower() for a in opt.actions)


def test_suggested_vless_link_when_uuid_present():
    r = _minimal_result()
    opt = build_config_optimization(r)
    assert opt.suggested_share_link
    assert opt.suggested_share_link.startswith("vless://")
