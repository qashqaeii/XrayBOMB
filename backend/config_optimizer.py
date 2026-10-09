"""Iran-focused config optimization — priority scoring and best-config blueprint."""

from __future__ import annotations

import copy
from typing import Optional

from backend.models import (
    AnalysisResult,
    ConfigOptimizationReport,
    IPNodeScore,
    OptimizationAction,
    OptimizationPriority,
    OptimizedBlueprint,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TransportType,
)
from backend.share_link_builder import build_share_link
from utils.helpers import is_ip_address


IDEAL_STACK = (
    "VLESS + REALITY + TCP/443 + flow=xtls-rprx-vision + fp=chrome + "
    "valid domain/SNI + CDN (Cloudflare/Arvan) + clean IP + Xray test with no leaks"
)

PRIORITY_ORDER = {
    OptimizationPriority.CRITICAL: 1,
    OptimizationPriority.HIGH: 2,
    OptimizationPriority.MEDIUM: 3,
    OptimizationPriority.LOW: 4,
    OptimizationPriority.INFO: 5,
}


def _grade(score: int) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _action(
    priority: OptimizationPriority,
    title: str,
    description: str,
    *,
    field: str | None = None,
    current: str | None = None,
    suggested: str | None = None,
    gain: int = 0,
) -> OptimizationAction:
    return OptimizationAction(
        priority=priority,
        priority_rank=PRIORITY_ORDER[priority],
        title=title,
        description=description,
        field=field,
        current_value=current,
        suggested_value=suggested,
        score_gain=gain,
    )


def _rank_ips(result: AnalysisResult) -> list[IPNodeScore]:
    dns_ips = result.dns.all_resolved_ips or []
    net_by_ip = {n.ip: n for n in result.network}
    threat_by_ip = {t.ip: t for t in result.threat_intel}
    rankings: list[IPNodeScore] = []

    for ip in dns_ips[:8]:
        intel = net_by_ip.get(ip)
        threat = threat_by_ip.get(ip)
        rep = intel.reputation_score if intel else (threat.reputation_score if threat else 50)
        bl = threat.blocklist_hits if threat else []
        score = rep
        notes: list[str] = []
        if bl:
            score -= 40
            notes.append(f"Blocklist: {', '.join(bl)}")
        if intel and intel.is_datacenter:
            notes.append("Datacenter — acceptable for REALITY")
        if intel and intel.cdn_detected:
            score += 5
            notes.append(f"CDN: {intel.cdn_detected}")
        if rep >= 65 and not bl:
            notes.append("Clean IP candidate")
        rankings.append(IPNodeScore(
            ip=ip,
            score=max(0, min(100, score)),
            reputation=rep,
            tcp_ok=result.connectivity.tcp_connect.value == "Valid",
            tcp_latency_ms=result.connectivity.tcp_latency_ms,
            is_datacenter=bool(intel and intel.is_datacenter),
            cdn=intel.cdn_detected if intel else None,
            country=intel.country if intel else None,
            blocklist_hits=bl,
            notes=notes,
        ))

    if not rankings and result.config.address and is_ip_address(result.config.address):
        n = result.network[0] if result.network else None
        rankings.append(IPNodeScore(
            ip=result.config.address,
            score=n.reputation_score if n else 50,
            reputation=n.reputation_score if n else 50,
            tcp_ok=result.connectivity.tcp_connect.value == "Valid",
            tcp_latency_ms=result.connectivity.tcp_latency_ms,
            is_datacenter=bool(n and n.is_datacenter),
            cdn=n.cdn_detected if n else None,
            country=n.country if n else None,
        ))

    rankings.sort(key=lambda x: x.score, reverse=True)
    return rankings


def _apply_blueprint(config: ParsedConfig) -> ParsedConfig:
    opt = copy.deepcopy(config)
    if opt.protocol == ProtocolType.VLESS:
        if opt.reality or opt.tls:
            if not opt.fingerprint:
                opt.fingerprint = "chrome"
            if opt.reality and not opt.flow:
                opt.flow = "xtls-rprx-vision"
        if opt.port not in (443, 8443):
            opt.port = 443
        opt.allow_insecure = False
        if opt.transport_type == TransportType.WS and not opt.path:
            opt.path = "/"
    if not is_ip_address(opt.address) and opt.sni and opt.sni != opt.address:
        if not opt.host:
            opt.host = opt.sni
    return opt


def _build_blueprint(config: ParsedConfig, actions: list[OptimizationAction]) -> OptimizedBlueprint:
    opt = _apply_blueprint(config)
    notes: list[str] = []
    security = "reality" if opt.reality else ("tls" if opt.tls else "none")
    if opt.reality and not opt.public_key:
        notes.append("REALITY keys (pbk/sid) are generated on server — copy from panel.")
    if is_ip_address(opt.address):
        notes.append("Use a CDN domain in the link; raw IP is not recommended for resale.")
    if opt.transport_type == TransportType.WS:
        notes.append("WebSocket is deprecated in Xray 26+ — prefer XHTTP or gRPC+REALITY for new servers.")

    return OptimizedBlueprint(
        protocol=opt.protocol.value,
        address=opt.address,
        port=opt.port,
        transport=opt.transport_type.value,
        security=security,
        flow=opt.flow,
        sni=opt.sni,
        host=opt.host,
        path=opt.path,
        fingerprint=opt.fingerprint,
        alpn=opt.alpn,
        service_name=opt.service_name,
        allow_insecure=opt.allow_insecure,
        notes=notes,
    )


def _server_recipe(result: AnalysisResult, blueprint: OptimizedBlueprint) -> list[str]:
    c = result.config
    d = result.deployment
    top = d.guesses[0].name if d.guesses else "Direct VPS"
    steps = [
        "1. VPS in target region (EU/Turkey with stable ping to Iran is common).",
        "2. Point domain through CDN (Cloudflare or Arvan) — Proxied for WS/gRPC.",
        "3. Install latest stable Xray-core + 3x-ui or Marzban panel.",
    ]
    if blueprint.security == "reality":
        steps.extend([
            "4. Panel: Inbound → VLESS + REALITY + TCP:443.",
            "5. dest/SNI: high-traffic site (e.g. www.microsoft.com) — must match client SNI.",
            "6. Generate REALITY key pair; set publicKey and shortId in client link.",
            "7. Client: flow=xtls-rprx-vision and fingerprint=chrome.",
        ])
    else:
        steps.extend([
            "4. Inbound: VLESS + TLS (or Trojan) on port 443.",
            "5. Let's Encrypt cert for SNI domain (not IP).",
            "6. fp=chrome and disable allowInsecure.",
        ])
    if top.startswith("Cloudflare"):
        steps.append("8. Cloudflare: SSL Full (strict), WebSockets ON, gRPC ON if used.")
    elif "Arvan" in top:
        steps.append("8. Arvan: proxy ON, cert and WS path per panel.")
    steps.extend([
        "9. Firewall: only 443 (and 80 for ACME) — do not expose panel publicly.",
        "10. Run Analyzer: Xray Test + Leak + YouTube/Telegram from Iran network.",
        "11. After pass: standard remark (country|REALITY|date) and deliver to customer.",
    ])
    if c.protocol not in (ProtocolType.VLESS, ProtocolType.TROJAN):
        steps.insert(3, "For Iran filtering, migrate to VLESS+REALITY on this server.")
    return steps


def _delivery_checklist(result: AnalysisResult) -> list[str]:
    x, v, s = result.xray_test, result.validation, result.security
    lk = x.leak_check
    items = [
        f"{'[x]' if v.valid else '[ ]'} Config validation — no errors",
        f"{'[x]' if result.connectivity.tcp_connect.value == 'Valid' else '[ ]'} TCP {result.config.address}:{result.config.port}",
        f"{'[x]' if not result.config.allow_insecure else '[ ]'} allowInsecure disabled",
        f"{'[x]' if result.config.reality or (result.config.tls and s.score >= 60) else '[ ]'} REALITY or valid TLS",
        f"{'[x]' if x.proxy_test.value == 'Valid' else '[ ]'} Live Xray test (proxy valid)",
        f"{'[x]' if not lk.ip_leak else '[ ]'} No IP leak",
        f"{'[x]' if lk.dns_leak is False else '[ ]'} No DNS leak (or N/A)",
        f"{'[x]' if s.score >= 65 else '[ ]'} Security score >= 65",
        f"{'[x]' if result.optimization.iran_score >= 60 else '[ ]'} Iran score >= 60",
    ]
    for site in x.site_reachability:
        if site.name in ("YouTube", "Telegram", "Google"):
            ok = site.status.value == "Valid"
            items.append(f"{'[x]' if ok else '[ ]'} {site.name} reachable via tunnel")
    lb = result.connectivity.latency_benchmark
    if lb.p95_ms is not None:
        ok = lb.p95_ms < 350
        items.append(f"{'[x]' if ok else '[ ]'} p95 ping under 350ms (now: {lb.p95_ms}ms)")
    return items


def _support_message(result: AnalysisResult, grade: str) -> str:
    c = result.config
    x = result.xray_test
    opt = result.optimization
    sites = ", ".join(
        f"{s.name} OK" if s.status.value == "Valid" else f"{s.name} FAIL"
        for s in x.site_reachability[:5]
    ) or "not tested"
    leak = "no leak" if not x.leak_check.ip_leak else "IP LEAK"
    return (
        f"Config report | Grade {grade} | Iran score {opt.iran_score}/100\n"
        f"Protocol: {c.protocol.value} | {c.address}:{c.port} | {c.transport_type.value}\n"
        f"Proxy test: {x.proxy_test.value} | Ping: {x.proxy_latency_ms or '-'} ms\n"
        f"Sites: {sites} | {leak}\n"
        f"Sell readiness: {opt.sell_readiness}%"
    )


def apply_optimization_to_config(config: ParsedConfig) -> ParsedConfig:
    return _apply_blueprint(config)


def build_config_optimization(result: AnalysisResult) -> ConfigOptimizationReport:
    c = result.config
    actions: list[OptimizationAction] = []
    iran = 0
    sell = 0
    x = result.xray_test

    if x.proxy_test.value != "Valid":
        if x.status == TestStatus.SKIPPED:
            actions.append(_action(
                OptimizationPriority.CRITICAL,
                "Run live Xray test",
                "Install Xray-core and enable Real Proxy Test — risky to sell without it.",
                gain=20,
            ))
        else:
            actions.append(_action(
                OptimizationPriority.CRITICAL,
                "Proxy not working",
                "Config failed from your network (Iran context) — check UUID, port, REALITY keys, firewall.",
                gain=25,
            ))
    else:
        iran += 18
        sell += 25

    if x.leak_check.ip_leak:
        actions.append(_action(
            OptimizationPriority.CRITICAL, "IP leak",
            "Traffic exits outside tunnel — fix client routing or DNS.", gain=15,
        ))
    else:
        iran += 10
        sell += 10

    if x.leak_check.dns_leak:
        actions.append(_action(
            OptimizationPriority.CRITICAL, "DNS leak",
            "ISP DNS used directly — enable remote DNS or full tun mode.", gain=10,
        ))
    elif x.leak_check.dns_leak is False:
        iran += 5
        sell += 5

    if not result.validation.valid:
        actions.append(_action(
            OptimizationPriority.CRITICAL, "Validation errors",
            "Required config fields missing — fix before selling.", gain=10,
        ))

    if c.protocol == ProtocolType.VMESS:
        actions.append(_action(
            OptimizationPriority.HIGH, "Migrate from VMess",
            "VMess is quickly detected under Iranian DPI — use VLESS+REALITY.",
            field="protocol", current="VMess", suggested="VLESS", gain=15,
        ))
        iran += 5
    elif c.protocol == ProtocolType.VLESS:
        iran += 8
        sell += 5

    if not c.reality:
        actions.append(_action(
            OptimizationPriority.HIGH, "Enable REALITY",
            "Best anti-DPI option for Iran — plain TLS or VMess alone is weak.",
            field="security", current=c.security or "tls/none", suggested="reality", gain=20,
        ))
    else:
        iran += 22
        sell += 10
        if not c.flow:
            actions.append(_action(
                OptimizationPriority.HIGH, "Set flow",
                "REALITY usually needs xtls-rprx-vision.",
                field="flow", suggested="xtls-rprx-vision", gain=8,
            ))
        else:
            iran += 8

    if c.allow_insecure:
        actions.append(_action(
            OptimizationPriority.HIGH, "Disable allowInsecure",
            "MITM risk and customer distrust — use valid certificate.", gain=12,
        ))
    else:
        iran += 6

    if not c.fingerprint and (c.tls or c.reality):
        actions.append(_action(
            OptimizationPriority.HIGH, "Browser fingerprint",
            "fp=chrome helps pass smart DPI on Iranian ISPs.", field="fp", suggested="chrome", gain=8,
        ))
    elif c.fingerprint:
        iran += 6

    if c.port != 443:
        actions.append(_action(
            OptimizationPriority.HIGH, "Use port 443",
            "Looks like HTTPS — odd ports get filtered faster in Iran.", field="port",
            current=str(c.port), suggested="443", gain=8,
        ))
    else:
        iran += 6

    if is_ip_address(c.address):
        actions.append(_action(
            OptimizationPriority.HIGH, "Use domain instead of IP",
            "Direct IP exposes origin — use domain + CDN.", field="address",
            current=c.address, suggested="sub.example.com", gain=10,
        ))
    else:
        iran += 5
        sell += 5

    cdn_any = any(n.cdn_detected for n in result.network) or result.deployment.cdn_type
    if not cdn_any and not is_ip_address(c.address):
        actions.append(_action(
            OptimizationPriority.HIGH, "CDN fronting",
            "Cloudflare or Arvan to hide server IP.", gain=8,
        ))
    elif cdn_any:
        iran += 8

    rankings = _rank_ips(result)
    best_ip = rankings[0].ip if rankings else None
    if rankings:
        top = rankings[0]
        if top.blocklist_hits:
            actions.append(_action(
                OptimizationPriority.CRITICAL, "IP on blocklist",
                f"IP {top.ip} listed on {', '.join(top.blocklist_hits)} — change IP.",
                field="ip", current=top.ip, gain=20,
            ))
        elif top.score >= 65:
            iran += 12
            sell += 8
        else:
            actions.append(_action(
                OptimizationPriority.MEDIUM, "Average IP quality",
                "Try a cleaner IP or different location.", field="ip", current=top.ip, gain=5,
            ))

    if result.tls.certificate_expired:
        actions.append(_action(
            OptimizationPriority.CRITICAL, "Expired certificate",
            "Renew Let's Encrypt certificate.", gain=15,
        ))
    elif result.tls.enabled and result.tls.days_until_expiry is not None:
        if result.tls.days_until_expiry < 14:
            actions.append(_action(
                OptimizationPriority.MEDIUM, "Certificate expiring soon",
                f"{result.tls.days_until_expiry} days left — renew early.", gain=5,
            ))
        else:
            iran += 4

    if c.transport_type == TransportType.WS:
        actions.append(_action(
            OptimizationPriority.MEDIUM, "WebSocket transport",
            "For new deploys prefer XHTTP (H2/H3) or gRPC+REALITY.",
            field="type", current="ws", suggested="xhttp", gain=5,
        ))
    elif c.transport_type in (TransportType.XHTTP, TransportType.GRPC, TransportType.TCP):
        iran += 5

    lb = result.connectivity.latency_benchmark
    if lb.p95_ms and lb.p95_ms > 400:
        actions.append(_action(
            OptimizationPriority.MEDIUM, "High ping",
            f"p95={lb.p95_ms}ms — try closer server or better route.", gain=5,
        ))
    elif lb.p95_ms and lb.p95_ms < 250:
        iran += 8
        sell += 10

    st = x.speed_test
    if st.download_mbps and st.download_mbps >= 5:
        sell += 10
    elif st.status == TestStatus.VALID and st.download_mbps and st.download_mbps < 2:
        actions.append(_action(
            OptimizationPriority.MEDIUM, "Low speed",
            f"~{st.download_mbps} Mbps — weak for video streaming.", gain=3,
        ))

    for site in x.site_reachability:
        if site.name in ("YouTube", "Telegram") and site.status.value == "Invalid":
            actions.append(_action(
                OptimizationPriority.HIGH, f"{site.name} blocked",
                "Iranian customers expect this — change route or IP.", gain=10,
            ))
        elif site.name in ("YouTube", "Telegram") and site.status.value == "Valid":
            iran += 5
            sell += 5

    if c.sni and not is_ip_address(c.address) and c.sni != c.host and c.transport_type in (
        TransportType.WS, TransportType.GRPC, TransportType.XHTTP,
    ):
        if not c.host:
            actions.append(_action(
                OptimizationPriority.MEDIUM, "Host header",
                "Host must match SNI/CDN domain.", field="host", suggested=c.sni, gain=4,
            ))

    if result.dns.doh_results and result.dns.a_records:
        local_set = set(result.dns.a_records)
        for provider, ips in result.dns.doh_results.items():
            if ips and set(ips) != local_set:
                actions.append(_action(
                    OptimizationPriority.HIGH, "Local DNS vs DoH mismatch",
                    f"Local resolver differs from {provider} — possible DNS filtering in Iran.", gain=8,
                ))
                break

    actions.sort(key=lambda a: (a.priority_rank, -a.score_gain))

    blueprint = _build_blueprint(c, actions)
    suggested_link = build_share_link(_apply_blueprint(c))

    iran = max(0, min(100, iran))
    sell = max(0, min(100, sell))
    critical_count = sum(1 for a in actions if a.priority == OptimizationPriority.CRITICAL)
    sell = max(0, sell - critical_count * 12)
    iran = max(0, iran - critical_count * 8)

    grade = _grade(iran)
    if sell >= 75 and iran >= 70:
        verdict = "Ready to sell — complete delivery checklist."
    elif sell >= 50:
        verdict = "Sellable with fixes — resolve P1/P2 before delivery."
    else:
        verdict = "Not ready for Iran market — fix live test, REALITY, CDN, clean IP first."

    report = ConfigOptimizationReport(
        iran_score=iran,
        sell_readiness=sell,
        grade=grade,
        verdict=verdict,
        ip_rankings=rankings,
        best_ip=best_ip,
        actions=actions,
        blueprint=blueprint,
        suggested_share_link=suggested_link,
        server_recipe=_server_recipe(result, blueprint),
        delivery_checklist=[],
        support_message="",
        ideal_stack_summary=IDEAL_STACK,
    )
    report.delivery_checklist = _delivery_checklist(result.model_copy(update={"optimization": report}))
    report.support_message = _support_message(result.model_copy(update={"optimization": report}), grade)
    return report
