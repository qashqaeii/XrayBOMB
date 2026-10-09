"""Evidence-based architecture diagnostics (client-side, reproducible)."""

from __future__ import annotations

from backend.e2e_validity import evaluate_xray_test_result
from backend.models import (
    AnalysisResult,
    ArchitectureDiagnosticsReport,
    ArchitectureEvidenceLine,
    TestStatus,
    TransportType,
)
from utils.helpers import is_ip_address
from xray.effective_client import effective_client_params


def _evidence_status_from_test(status: TestStatus) -> str:
    if status == TestStatus.VALID:
        return "confirmed"
    if status in (TestStatus.WARNING, TestStatus.INCONCLUSIVE):
        return "probable"
    if status in (TestStatus.INVALID, TestStatus.FAILED):
        return "failed"
    if status == TestStatus.NOT_APPLICABLE:
        return "n/a"
    return "unknown"


def _cdn_fronting_tier(r: AnalysisResult) -> tuple[str, str]:
    conn = r.connectivity
    wire_headers = conn.http_baseline_headers or conn.http_probe_headers
    has_edge_header = any(k in wire_headers for k in ("cf-ray", "x-arvan", "x-sid", "x-cache"))
    if conn.http_cdn_detected and has_edge_header:
        return "confirmed", f"HTTP edge headers + Server/CDN hint ({conn.http_cdn_detected})"
    if conn.http_cdn_detected:
        return "probable", f"HTTP fingerprint suggests {conn.http_cdn_detected} (no full edge header set)"
    if r.dns.dns_provider and "cdn" not in (r.dns.dns_provider or "").lower():
        return "unconfirmed", (
            f"DNS hosted by {r.dns.dns_provider} — DNS management ≠ active CDN fronting"
        )
    return "unconfirmed", "No CDN edge proof on this connection path"


def _assess_architecture(r: AnalysisResult) -> tuple[str, str, list[str], list[str], list[str]]:
    c = r.config
    positives: list[str] = []
    negatives: list[str] = []
    unknowns: list[str] = list(r.deployment.uncertain_fields[:6])

    if r.connectivity.tcp_connect == TestStatus.VALID:
        positives.append(f"TCP reachable on {r.connectivity.tcp_latency_ms or '?'} ms")
    if c.transport_type == TransportType.WS:
        if r.connectivity.websocket_handshake_validated:
            positives.append("WebSocket RFC6455 handshake validated (HTTP 101 + Accept)")
        elif r.connectivity.websocket_upgrade == TestStatus.VALID:
            positives.append("WebSocket upgrade probe succeeded")
        elif r.connectivity.websocket_upgrade == TestStatus.INVALID:
            negatives.append("External WebSocket handshake failed (check Host/path vs link)")

    e2e = evaluate_xray_test_result(r.xray_test)
    if e2e.internet_verified:
        positives.append("Xray SOCKS E2E internet verified (this run only)")
    elif r.xray_test.status != TestStatus.SKIPPED:
        negatives.append(f"Xray E2E not verified: {e2e.reason}")

    cdn_tier, cdn_detail = _cdn_fronting_tier(r)
    if cdn_tier == "confirmed":
        title = f"CDN-fronted {c.transport_type.value} — probable"
        summary = cdn_detail
    elif cdn_tier == "probable":
        title = f"Direct or CDN-fronted {c.transport_type.value} — inconclusive"
        summary = (
            f"{cdn_detail}. Direct VPS/WebSocket remains compatible with observations."
        )
        unknowns.append("Whether traffic traverses a CDN edge")
    else:
        title = f"Direct Xray / {c.transport_type.value} — probable"
        summary = (
            "Evidence fits direct connect to resolved IP; CDN, reverse proxy, or relay "
            "cannot be ruled out without server-side or edge headers."
        )
        if r.dns.dns_provider:
            unknowns.append(f"Role of DNS provider ({r.dns.dns_provider}) vs origin hosting")

    if r.connectivity.http_reverse_proxy:
        positives.append(f"Reverse proxy Server header: {r.connectivity.http_reverse_proxy}")
    else:
        unknowns.append("Hidden reverse proxy (no nginx/caddy in HTTP Server header)")

    exit_ip = r.xray_test.exit_ip or r.xray_test.leak_check.proxy_exit_ip
    target_ip = r.dns.a_records[0] if r.dns.a_records else (r.network[0].ip if r.network else None)
    if exit_ip and target_ip and exit_ip == target_ip:
        positives.append(
            f"Exit IP equals DNS/connect IP {target_ip} for this run (egress observed, not separate origin proof)"
        )
    elif exit_ip and target_ip:
        positives.append(f"Exit IP {exit_ip} differs from DNS A {target_ip}")
        unknowns.append("Intermediate hops between connect IP and egress")

    unknowns.append("Origin IP (independent of exit IP)")
    unknowns.append("Internal server inbound / panel layout")

    return title, summary, positives, negatives, list(dict.fromkeys(unknowns))[:8]


def build_architecture_diagnostics(r: AnalysisResult) -> ArchitectureDiagnosticsReport:
    c = r.config
    conn = r.connectivity
    eff = effective_client_params(c)
    report = ArchitectureDiagnosticsReport(
        endpoint=f"{c.address}:{c.port}",
    )

    report.connection_evidence = [
        ArchitectureEvidenceLine(
            label="DNS resolve",
            status=_evidence_status_from_test(conn.dns_resolve),
            detail=f"{conn.dns_latency_ms or '?'} ms",
        ),
        ArchitectureEvidenceLine(
            label="TCP",
            status=_evidence_status_from_test(conn.tcp_connect),
            detail=f"{conn.tcp_latency_ms or '?'} ms",
        ),
        ArchitectureEvidenceLine(
            label="HTTP baseline",
            status=_evidence_status_from_test(conn.http_baseline_status),
            detail=conn.http_baseline_note or str(conn.http_baseline_status_code or "—"),
        ),
    ]
    if c.transport_type == TransportType.WS:
        if conn.websocket_handshake_validated:
            ws_status = "confirmed"
        elif conn.websocket_upgrade == TestStatus.WARNING:
            ws_status = "probable"
        else:
            ws_status = _evidence_status_from_test(conn.websocket_upgrade)
        ws_detail = conn.websocket_upgrade_note or "—"
        if conn.websocket_handshake_status_code:
            ws_detail = f"HTTP {conn.websocket_handshake_status_code} — {ws_detail}"
        report.connection_evidence.append(ArchitectureEvidenceLine(
            label="WebSocket handshake",
            status=ws_status,
            detail=ws_detail,
        ))

    if c.tls or (c.security or "").lower() in ("tls", "reality"):
        report.connection_evidence.append(ArchitectureEvidenceLine(
            label="TLS probe",
            status=_evidence_status_from_test(conn.tls_handshake),
            detail=f"{conn.tls_latency_ms or '?'} ms",
        ))

    e2e = evaluate_xray_test_result(r.xray_test)
    xray_status = "confirmed" if e2e.internet_verified else (
        "unknown" if r.xray_test.status == TestStatus.SKIPPED else "failed"
    )
    report.connection_evidence.append(ArchitectureEvidenceLine(
        label="Xray E2E",
        status=xray_status,
        detail=r.xray_test.summary[:160] if r.xray_test.summary else e2e.reason,
    ))

    net0 = r.network[0] if r.network else None
    cdn_tier, cdn_note = _cdn_fronting_tier(r)
    report.infrastructure = [
        ArchitectureEvidenceLine(
            label="DNS provider",
            status="probable" if r.dns.dns_provider else "unknown",
            detail=r.dns.dns_provider or "Unknown",
        ),
        ArchitectureEvidenceLine(
            label="Target IP (A)",
            status="confirmed" if r.dns.a_records else "unknown",
            detail=", ".join(r.dns.a_records[:3]) or (net0.ip if net0 else "Unknown"),
        ),
        ArchitectureEvidenceLine(
            label="ASN / ISP",
            status="probable" if net0 and net0.asn else "unknown",
            detail=f"{net0.asn or '?'} — {net0.organization or net0.isp or '?'}" if net0 else "Unknown",
        ),
        ArchitectureEvidenceLine(
            label="CDN fronting",
            status=cdn_tier,
            detail=cdn_note,
        ),
        ArchitectureEvidenceLine(
            label="Exit IP",
            status="confirmed" if r.xray_test.exit_ip else "unknown",
            detail=r.xray_test.exit_ip or r.xray_test.leak_check.proxy_exit_ip or "Not observed",
        ),
    ]

    title, summary, pos, neg, unk = _assess_architecture(r)
    report.assessment_title = title
    report.assessment_summary = summary
    report.positive_evidence = pos
    report.negative_evidence = neg
    report.unknowns = unk

    tls_active = c.tls or (c.security or "").lower() in ("tls", "reality")
    report.reproduction_client = [
        f"Connect {eff['connect_address']}:{eff['connect_port']} network={eff['network']} security={eff['security']}",
        f"Host={eff['effective_host']} path={eff['effective_path']}",
    ]
    if tls_active:
        report.reproduction_client.append(f"TLS SNI={eff['effective_sni']}")
    elif c.sni or c.host:
        report.reproduction_client.append(
            f"Host header domain={eff['effective_host']} (no TLS — SNI not used on wire)"
        )
    report.reproduction_server_hints = [
        "If direct inbound: Xray listens on public port with matching path/Host.",
        "If reverse proxy: terminate TLS/HTTP on nginx/caddy and proxy_pass to localhost Xray.",
        "If CDN: origin must accept CDN-forwarded Host/SNI — requires panel/DNS evidence (not guessed here).",
    ]
    if is_ip_address(c.address) and c.sni and tls_active:
        report.reproduction_client.append(f"Client uses IP connect with TLS SNI={c.sni}")

    report.cdn_fronting_tier = cdn_tier
    report.direct_vps_compatible = cdn_tier != "confirmed"
    report.origin_ip_status = "unknown"
    report.primary_scenario_label = title

    return report


def format_architecture_diagnostics_text(r: AnalysisResult) -> str:
    d = r.architecture_diagnostics
    if not d.endpoint:
        d = build_architecture_diagnostics(r)
    lines = [
        d.title,
        "=" * 50,
        "",
        d.endpoint,
        "",
        "── Connection Evidence ──",
    ]
    for item in d.connection_evidence:
        lines.append(f"  {item.label:<22} [{item.status}]  {item.detail}")
    lines.extend(["", "── Infrastructure ──"])
    for item in d.infrastructure:
        lines.append(f"  {item.label:<22} [{item.status}]  {item.detail}")
    lines.extend([
        "",
        "── Architecture Assessment ──",
        f"  {d.assessment_title}",
        f"  {d.assessment_summary}",
    ])
    if d.positive_evidence:
        lines.extend(["", "  + Positive:"])
        for p in d.positive_evidence:
            lines.append(f"      • {p}")
    if d.negative_evidence:
        lines.extend(["", "  − Negative / gaps:"])
        for n in d.negative_evidence:
            lines.append(f"      • {n}")
    if d.unknowns:
        lines.extend(["", "  ? Unknown (not provable client-side):"])
        for u in d.unknowns:
            lines.append(f"      • {u}")
    lines.extend(["", "── Reproduction Guide ──", "  Client:"])
    for step in d.reproduction_client:
        lines.append(f"    • {step}")
    lines.append("  Server (hypotheses — verify on host):")
    for step in d.reproduction_server_hints:
        lines.append(f"    • {step}")
    return "\n".join(lines)
