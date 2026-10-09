"""Architecture-compatible reconstruction guide (not server config discovery)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from backend.e2e_validity import evaluate_xray_test_result
from backend.models import AnalysisResult, TestStatus, TunnelTypeMatch
from xray.effective_client import effective_client_params


class ArchitectureScenario(BaseModel):
    tunnel_id: str = ""
    name: str
    confidence_note: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    suggested_followup_checks: list[str] = Field(default_factory=list)


class ImplementationAnalysisReport(BaseModel):
    title: str = "معماری سازگار با مشاهدات"
    client_effective_settings: list[str] = Field(default_factory=list)
    entry_point: str = ""
    entry_peer_observed: str = ""
    entry_network_owner: str = ""
    cdn_edge_evidence: list[str] = Field(default_factory=list)
    transport_handshake: str = ""
    external_ws_probe: str = ""
    xray_e2e: str = ""
    config_verified_e2e: str = ""
    observed_egress_ip: str = ""
    baseline_vs_exit: str = ""
    entry_vs_exit: str = ""
    scenarios: list[ArchitectureScenario] = Field(default_factory=list)
    server_side_questions: list[str] = Field(default_factory=list)
    client_side_limitations: list[str] = Field(default_factory=list)
    reconstruction_steps: list[str] = Field(default_factory=list)


def _scenario_from_match(match: TunnelTypeMatch, r: AnalysisResult) -> ArchitectureScenario:
    ev = list(match.evidence)
    supporting = ev[:6]
    contradicting: list[str] = []
    unknowns = list(r.deployment.uncertain_fields[:4])

    if match.tunnel_id.endswith("_cdn") or "cdn" in match.tunnel_id:
        if not any(ip.cdn_detected for ip in r.network):
            contradicting.append("CDN tunnel guess but no CDN intelligence on resolved connect IPs")
        contradicting.append("ASN/network owner alone does not prove active CDN on this connection")

    e2e = evaluate_xray_test_result(r.xray_test)
    if e2e.internet_verified:
        supporting.append("internet_e2e_verified for this config/run")
    else:
        contradicting.append(f"No verified internet E2E ({e2e.reason})")

    if r.connectivity.http_reverse_proxy:
        contradicting.append("HTTP Server header suggests reverse proxy — weak against direct inbound guesses")

    followups = [
        "Run E2E with VPN/Proxifier off for clean baseline (manual — not executed here)",
        "Compare external WS probe vs xray-core E2E parameters",
    ]
    if match.tunnel_id == "direct_xray_inbound":
        followups.append("Server-side listener inventory (SSH read-only) if you own the host")

    return ArchitectureScenario(
        tunnel_id=match.tunnel_id,
        name=match.name,
        confidence_note=match.confidence_level.value,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
        unknowns=unknowns,
        suggested_followup_checks=followups,
    )


def build_implementation_analysis(result: AnalysisResult) -> ImplementationAnalysisReport:
    c = result.config
    eff = effective_client_params(c)
    report = ImplementationAnalysisReport()

    report.client_effective_settings = [
        f"protocol={c.protocol.value} network={eff['network']} security={eff['security']}",
        f"connect={eff['connect_address']}:{eff['connect_port']}",
        f"effective_sni={eff['effective_sni']}",
        f"effective_host={eff['effective_host']} (default applied when link omits Host)",
        f"effective_path={eff['effective_path']}",
        f"flow={c.flow or '(none)'} fingerprint={c.fingerprint or '(default)'}",
    ]
    if c.remark:
        report.client_effective_settings.append(f"remark (untrusted metadata)={c.remark[:80]}")

    report.entry_point = f"{c.address}:{c.port}"
    report.entry_peer_observed = "Unknown — TCP peer IP not observed in client-only analysis"
    if result.network:
        n0 = result.network[0]
        report.entry_point += f" (DNS/resolver IP intel: {n0.ip})"
        report.entry_network_owner = f"{n0.organization or n0.isp or '?'} ({n0.asn or '?'})"
        if n0.cdn_detected:
            report.cdn_edge_evidence.append(
                f"Geo/CDN hint on resolved IP {n0.ip}: {n0.cdn_detected} (heuristic, not proof on wire)"
            )
    else:
        report.entry_network_owner = "Unknown"

    if result.connectivity.http_cdn_detected:
        report.cdn_edge_evidence.append(f"HTTP probe hint: {result.connectivity.http_cdn_detected}")

    conn = result.connectivity
    report.transport_handshake = (
        f"TCP={conn.tcp_connect.value} TLS={conn.tls_handshake.value} WS={conn.websocket_upgrade.value}"
    )
    if conn.websocket_upgrade_note:
        report.external_ws_probe = conn.websocket_upgrade_note
    else:
        report.external_ws_probe = (
            "External WebSocket probe uses different stack/parameters than xray-core E2E."
        )

    xt = result.xray_test
    validity = evaluate_xray_test_result(xt)
    if validity.internet_verified:
        report.config_verified_e2e = (
            "Internet E2E verified for this config via isolated SOCKS + generate_204 contract "
            f"(run_id={xt.run_id or '?'}) — only this run/network moment."
        )
        report.xray_e2e = report.config_verified_e2e
    elif xt.proxy_test == TestStatus.NOT_TESTED:
        report.config_verified_e2e = (
            "Config syntax checked with xray -test only — no SOCKS/internet E2E; "
            "no successful internet claim."
        )
        report.xray_e2e = report.config_verified_e2e
    else:
        report.config_verified_e2e = f"E2E not verified: {validity.reason}"
        report.xray_e2e = report.config_verified_e2e

    report.observed_egress_ip = xt.exit_ip or (xt.leak_check.proxy_exit_ip if xt.leak_check else None) or "Not observed"
    lc = xt.leak_check
    if lc.baseline_samples:
        bases = [s.get("ip") for s in lc.baseline_samples if s.get("ip")]
        report.baseline_vs_exit = (
            f"baseline_status={lc.baseline_status} samples={len(lc.baseline_samples)} "
            f"ips={', '.join(sorted(set(bases))) or 'none'} vs exit={lc.proxy_exit_ip or '?'}"
        )
    else:
        report.baseline_vs_exit = "Baseline not collected in this run."

    if lc.exit_ip_same_observed is True:
        report.baseline_vs_exit += " — same IP observed (not leak proof)."
    elif lc.exit_ip_same_observed is False:
        report.baseline_vs_exit += " — different IPs observed (not full anti-leak proof)."
    else:
        report.baseline_vs_exit += " — comparison inconclusive."

    entry_ip = result.network[0].ip if result.network else None
    exit_ip = lc.proxy_exit_ip or xt.exit_ip
    if entry_ip and exit_ip:
        report.entry_vs_exit = (
            f"Resolver/connect IP intel {entry_ip} vs egress observed {exit_ip} — "
            "entry DNS intel is not the same as TCP peer or origin."
        )
    else:
        report.entry_vs_exit = "Entry vs exit comparison incomplete."

    primary_id = result.tunnel_analysis.primary_tunnel_id
    for match in result.tunnel_analysis.detected_types[:6]:
        scenario = _scenario_from_match(match, result)
        if match.tunnel_id == primary_id:
            scenario.supporting_evidence.insert(0, f"primary_type selection ({primary_id})")
        report.scenarios.append(scenario)

    if not report.scenarios and result.tunnel_analysis.primary_type:
        report.scenarios.append(ArchitectureScenario(
            tunnel_id=primary_id,
            name=result.tunnel_analysis.primary_type,
            confidence_note=result.tunnel_analysis.primary_confidence_level.value,
            unknowns=list(result.deployment.uncertain_fields[:6]),
        ))

    report.server_side_questions = [
        "Inbound listener on server (port/protocol)?",
        "Reverse proxy in front of Xray?",
        "CDN edge vs origin separation?",
        "REALITY dest/serverNames if used?",
    ]
    report.client_side_limitations = [
        "Cannot discover relay/FRP/WireGuard hops behind CDN from link alone.",
        "HTTP Server header is spoofable; absence does not disprove reverse proxy.",
        "SOCKS success confirms this run only — not permanent stability or all ISPs.",
        "Heuristic confidence scores are not calibrated statistical probabilities.",
    ]
    report.reconstruction_steps = [
        "روش ساخت معماری مشابه (not discovery of someone else's live config):",
        f"1) Client uses {eff['connect_address']}:{eff['connect_port']} with network={eff['network']}, security={eff['security']}.",
        f"2) Apply effective Host={eff['effective_host']}, SNI={eff['effective_sni']}, path={eff['effective_path']}.",
        "3) Treat CDN-facing IP as edge; origin requires admin/SSH evidence.",
    ]
    if result.reproduction.reproducible:
        for item in result.reproduction.reproducible[:5]:
            report.reconstruction_steps.append(f"• {item.field}: {item.value or '—'}")

    return report
