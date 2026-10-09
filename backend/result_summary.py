"""Comprehensive evidence-based scenario engine for the Result tab.

Produces a full English narrative covering every known deployment topology:
CDN fronting (all providers), direct VPS, reverse proxy, reverse tunnels,
REALITY, protocol-native tunnels (Hy2/TUIC/WG/OpenVPN), fronting variants,
multi-hop, load balancing — ranked by confidence with implementation playbooks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Optional

from backend.models import (
    AnalysisResult,
    DeploymentGuess,
    ParsedConfig,
    ProtocolType,
    TestStatus,
    TransportType,
    TunnelTypeMatch,
)
from backend.stealth_assessment import format_risk_factors, format_score, score_bar
from backend.tunnel_detection import TUNNEL_CATALOG
from utils.country import format_country
from utils.helpers import is_ip_address


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pct(x: float) -> str:
    try:
        return f"{max(0.0, min(1.0, float(x))) * 100:.0f}%"
    except Exception:
        return "N/A"


def _bar(conf: float, width: int = 12) -> str:
    filled = int(conf * width)
    return "█" * filled + "░" * (width - filled)


def _effective_transport(c: ParsedConfig) -> TransportType:
    if c.transport_type != TransportType.UNKNOWN:
        return c.transport_type
    raw = str(c.extra.get("type") or c.extra.get("net") or "").lower()
    mapping = {
        "tcp": TransportType.TCP, "ws": TransportType.WS, "grpc": TransportType.GRPC,
        "httpupgrade": TransportType.HTTPUPGRADE, "http": TransportType.HTTPUPGRADE,
        "xhttp": TransportType.XHTTP, "splithttp": TransportType.XHTTP, "quic": TransportType.QUIC,
    }
    return mapping.get(raw, TransportType.UNKNOWN)


def _security_label(c: ParsedConfig) -> str:
    if c.reality:
        return "REALITY"
    if c.tls:
        return "TLS"
    return "PLAIN (no TLS)"


def _transport_label(r: AnalysisResult) -> str:
    c = r.config
    tr = _effective_transport(c)
    return f"{c.protocol.value} over {tr.value} ({_security_label(c)})"


def _front_host(c: ParsedConfig, dns_hostname: str = "") -> str:
    return c.sni or c.host or dns_hostname or c.address


def _exit_info(r: AnalysisResult) -> tuple[Optional[str], Optional[str], Optional[str]]:
    x = r.xray_test
    ip = x.exit_ip or x.leak_check.proxy_exit_ip
    country = x.exit_country or x.leak_check.proxy_exit_country
    colo = x.leak_check.proxy_exit_colo
    return ip, country, colo


def _proxy_ok(r: AnalysisResult) -> bool:
    return r.xray_test.proxy_test == TestStatus.VALID


CONFIDENCE_CAP = 0.92
LOW_SCENARIO_THRESHOLD = 0.30


@dataclass(frozen=True)
class ExitIntelSnapshot:
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    datacenter: Optional[str] = None
    is_datacenter: bool = False
    colo: Optional[str] = None
    reputation: Optional[int] = None


def _get_exit_intel(r: AnalysisResult) -> Optional[ExitIntelSnapshot]:
    """Resolve exit IP intelligence from raw_data, network match, or xray fields."""
    exit_ip, exit_ct, colo = _exit_info(r)
    if not exit_ip:
        return None

    raw = r.raw_data.get("exit_intel") if r.raw_data else None
    if isinstance(raw, dict) and raw.get("ip"):
        return ExitIntelSnapshot(
            ip=raw["ip"],
            country=raw.get("country") or exit_ct,
            country_code=raw.get("country_code") or exit_ct,
            asn=raw.get("asn"),
            isp=raw.get("isp"),
            organization=raw.get("organization"),
            datacenter=raw.get("datacenter"),
            is_datacenter=bool(raw.get("is_datacenter")),
            colo=colo,
            reputation=raw.get("reputation_score"),
        )

    for net in r.network:
        if net.ip == exit_ip:
            return ExitIntelSnapshot(
                ip=net.ip,
                country=net.country or exit_ct,
                country_code=net.country_code or exit_ct,
                asn=net.asn,
                isp=net.isp,
                organization=net.organization,
                datacenter=net.datacenter,
                is_datacenter=net.is_datacenter,
                colo=colo,
                reputation=net.reputation_score,
            )

    return ExitIntelSnapshot(ip=exit_ip, country=exit_ct, country_code=exit_ct, colo=colo)


@dataclass
class RankedScenario:
    rank: int
    tunnel_id: str
    name: str
    category: str
    confidence: float
    traffic_flow: str
    description: str
    evidence: list[str] = field(default_factory=list)
    setup_steps: list[str] = field(default_factory=list)
    ruled_out: bool = False
    rule_out_reason: str = ""


def _format_edge_route(r: AnalysisResult) -> str:
    """Human-readable edge route — never imply origin geo when CDN is present."""
    d = r.deployment
    t = r.tunnel
    cdn = r.connectivity.http_cdn_detected or d.cdn_type
    client = format_country(t.client_country_code, t.client_country) or "Client"

    if cdn:
        cdn_ips = [ip for ip in r.network if ip.cdn_detected]
        edge_ip = (
            cdn_ips[0].ip if cdn_ips
            else (d.cdn_backend_ips[0] if d.cdn_backend_ips else None)
            or (r.dns.a_records[0] if r.dns.a_records else None)
        )
        edge_loc = "?"
        if cdn_ips:
            edge_loc = format_country(cdn_ips[0].country_code, cdn_ips[0].country) or "?"
        elif r.network:
            edge_loc = format_country(r.network[0].country_code, r.network[0].country) or "?"
        ip_txt = f"{edge_ip}, {edge_loc}" if edge_ip else "edge IPs"
        return f"{client} → {cdn} edge ({ip_txt}) → Origin (hidden)"

    if t.server_country_code or t.server_country:
        srv = format_country(t.server_country_code, t.server_country)
        return f"{client} → {srv}"

    return t.route_display or "Country data unavailable"


def _origin_country_hint(r: AnalysisResult, exit_intel: Optional[ExitIntelSnapshot]) -> Optional[str]:
    if not exit_intel or not (exit_intel.country_code or exit_intel.country):
        return None
    return format_country(exit_intel.country_code, exit_intel.country)


def _build_verdict(
    r: AnalysisResult,
    primary: Optional[RankedScenario],
    exit_intel: Optional[ExitIntelSnapshot],
) -> str:
    """One-line executive verdict."""
    c = r.config
    d = r.deployment
    host = _front_host(c, r.dns.hostname)
    transport = _effective_transport(c)
    origin_hint = _origin_country_hint(r, exit_intel)

    parts: list[str] = []
    http_cdn = r.connectivity.http_cdn_detected
    if http_cdn or d.cdn_type:
        parts.append(f"{(http_cdn or d.cdn_type)} CDN fronting")
    elif primary:
        parts.append(primary.name)
    else:
        parts.append("Direct or unknown topology")

    parts.append(f"{c.protocol.value}+{transport.value}")
    parts.append(_security_label(c))
    parts.append(f"on :{c.port}")

    if origin_hint and d.cdn_type:
        parts.append(f"— origin likely {origin_hint} VPS (from live exit IP)")
    elif origin_hint:
        parts.append(f"— server egress {origin_hint}")

    if _proxy_ok(r):
        lat = r.xray_test.proxy_latency_ms
        if lat is not None:
            parts.append(f"| tunnel works ({lat:.0f}ms)")
    else:
        parts.append("| live test not confirmed")

    return (
        f"MOST LIKELY: {' '.join(parts[:4])} {host} "
        + " ".join(parts[4:])
    ).strip()


@dataclass(frozen=True)
class OriginAlternative:
    name: str
    confidence: float
    explanation: str


def _build_origin_alternatives(
    r: AnalysisResult,
    exit_intel: Optional[ExitIntelSnapshot],
) -> list[OriginAlternative]:
    """Ranked origin-location hypotheses when CDN hides the backend."""
    d = r.deployment
    if not d.cdn_type:
        return []

    exit_ct = (exit_intel.country_code or exit_intel.country) if exit_intel else None
    edge_ct = r.network[0].country_code if r.network else None
    alts: list[OriginAlternative] = []

    if exit_ct and edge_ct and exit_ct != edge_ct:
        dc = ""
        if exit_intel and exit_intel.organization:
            dc = f" ({exit_intel.organization})"
        alts.append(OriginAlternative(
            name=f"Foreign origin VPS ({exit_ct}){dc}",
            confidence=0.78,
            explanation=(
                f"Live exit IP is in {exit_ct} while CDN edge is {edge_ct}. "
                "The egress IP usually belongs to the origin VPS itself."
            ),
        ))
        alts.append(OriginAlternative(
            name="Regional origin + foreign egress relay",
            confidence=0.15,
            explanation=(
                "Less common: origin in edge region but outbound/Warp/relay sends traffic abroad."
            ),
        ))
    elif exit_ct and edge_ct and exit_ct == edge_ct:
        alts.append(OriginAlternative(
            name=f"Regional origin VPS ({exit_ct})",
            confidence=0.55,
            explanation="Exit country matches CDN edge — origin may be local/regional (not proven).",
        ))
        alts.append(OriginAlternative(
            name="Foreign origin with regional CDN only",
            confidence=0.25,
            explanation="CDN edge is local but origin could still be abroad if routing is unusual.",
        ))
    else:
        alts.append(OriginAlternative(
            name="Origin country unknown",
            confidence=0.0,
            explanation="Run Xray live proxy test to observe exit IP and infer origin region.",
        ))

    return alts


def _dns_summary(r: AnalysisResult) -> list[str]:
    dns = r.dns
    lines = ["DNS resolution (all sources):", ""]
    if dns.local_resolver_ips:
        lines.append(f"  Local resolver A : {', '.join(dns.local_resolver_ips)}")
    if dns.doh_results:
        for prov, ips in dns.doh_results.items():
            lines.append(f"  DoH ({prov})     : {', '.join(ips) or 'none'}")
    if dns.all_resolved_ips:
        lines.append(f"  Union (CDN scan) : {', '.join(dns.all_resolved_ips[:6])}")
    if dns.dns_split_detected:
        lines.append(f"  ⚠ Split DNS      : {dns.dns_split_note}")
        lines.append(
            "    Different resolvers return different IPs — use union + HTTP headers for CDN detection."
        )
    return lines


def _http_fingerprint_summary(r: AnalysisResult) -> list[str]:
    conn = r.connectivity
    lines = ["HTTP fingerprint (domain probe):", ""]
    if not conn.http_probe_url and not conn.http_server_header:
        lines.append("  Not available.")
        return lines
    if conn.http_probe_url:
        lines.append(f"  Probed URL       : {conn.http_probe_url}")
    if conn.http_server_header:
        lines.append(f"  Server header    : {conn.http_server_header}")
    if conn.http_cdn_detected:
        lines.append(f"  CDN (from HTTP)  : {conn.http_cdn_detected}")
    if conn.http_panel_detected:
        lines.append(f"  Panel detected   : {conn.http_panel_detected}")
    if conn.http_reverse_proxy:
        lines.append(f"  Reverse proxy    : {conn.http_reverse_proxy}")
    elif conn.http_server_header and conn.http_cdn_detected:
        lines.append("  Reverse proxy    : none detected (CDN edge or direct Xray likely)")
    for k, v in (conn.http_probe_headers or {}).items():
        lines.append(f"  {k}: {v[:80]}")
    return lines


def _connectivity_summary(r: AnalysisResult) -> list[str]:
    conn = r.connectivity
    lines = ["Connectivity & transport tests:", ""]
    pairs = [
        ("DNS resolve", conn.dns_resolve, conn.dns_latency_ms),
        ("TCP connect", conn.tcp_connect, conn.tcp_latency_ms),
        ("TLS handshake", conn.tls_handshake, conn.tls_latency_ms),
        ("WebSocket upgrade", conn.websocket_upgrade, None),
        ("HTTP response", conn.http_response, conn.latency_ms),
    ]
    for label, status, ms in pairs:
        if status == TestStatus.PENDING:
            continue
        ms_txt = f" ({ms}ms)" if ms is not None else ""
        lines.append(f"  {label:<20}: {status.value}{ms_txt}")

    if conn.packet_loss_percent is not None:
        lines.append(f"  Packet loss          : {conn.packet_loss_percent:.1f}%")
    lb = conn.latency_benchmark
    if lb.samples:
        lines.append(
            f"  Latency benchmark    : min={lb.min_ms} avg={lb.avg_ms} "
            f"p95={lb.p95_ms} max={lb.max_ms} ms ({lb.samples} samples)"
        )
    if conn.websocket_upgrade == TestStatus.INVALID and conn.websocket_upgrade_note:
        lines.append(f"  WS upgrade note    : {conn.websocket_upgrade_note}")
    if r.xray_test.proxy_test == TestStatus.VALID and conn.websocket_upgrade == TestStatus.INVALID:
        lines.append(
            "  WS vs live test    : Xray proxy VALID despite WS probe INVALID — trust live test."
        )
    if not any(l.startswith("  DNS") or l.startswith("  TCP") for l in lines[2:]):
        lines.append("  (no connectivity measurements recorded)")
    return lines


def _latency_interpretation(r: AnalysisResult) -> list[str]:
    x = r.xray_test
    conn = r.connectivity
    lines = ["Latency interpretation:", ""]

    proxy_ms = x.proxy_latency_ms
    tcp_ms = conn.tcp_latency_ms

    if proxy_ms is not None:
        if proxy_ms < 150:
            grade = "excellent"
        elif proxy_ms < 350:
            grade = "good"
        elif proxy_ms < 600:
            grade = "moderate"
        else:
            grade = "slow"
        lines.append(f"  Proxy round-trip: {proxy_ms:.0f}ms — {grade} for interactive use.")
        if d := r.deployment.cdn_type:
            if proxy_ms > 500:
                lines.append(
                    f"  High latency is expected with {d} + plain WS + long routing; "
                    "not necessarily a dead node."
                )
    else:
        lines.append("  Proxy round-trip: N/A (live test not run or failed).")

    if tcp_ms is not None:
        lines.append(f"  TCP to edge/target: {tcp_ms:.0f}ms (DNS resolved endpoint only).")

    return lines


def _traceroute_summary(r: AnalysisResult) -> list[str]:
    tr = r.traceroute
    lines = ["Traceroute:", ""]
    if tr.hop_count:
        lines.append(f"  Hop count: {tr.hop_count}")
    if tr.hops:
        for hop in tr.hops[:8]:
            lat = f"{hop.latency_ms}ms" if hop.latency_ms is not None else "-"
            lines.append(f"  {hop.hop:>2}. {hop.ip or '*':<16} {lat:>8}  {hop.hostname or ''}")
        if len(tr.hops) > 8:
            lines.append(f"  ... +{len(tr.hops) - 8} more hops")
    elif tr.errors:
        lines.append(f"  Unavailable: {tr.errors[0]}")
    else:
        lines.append("  Not run or no hop data.")
    return lines


def _cert_transparency_summary(r: AnalysisResult) -> list[str]:
    ct = r.cert_transparency
    lines = ["Certificate Transparency (crt.sh):", ""]
    if not ct.domain:
        lines.append("  Skipped (no domain for CT lookup).")
        return lines
    lines.append(f"  Domain queried: {ct.domain}")
    lines.append(f"  Subdomains found: {ct.total_count}")
    for entry in ct.entries[:6]:
        lines.append(f"    • {entry.subdomain}")
    if ct.total_count > 6:
        lines.append(f"    ... +{ct.total_count - 6} more")
    if ct.errors:
        lines.append(f"  Errors: {'; '.join(ct.errors[:2])}")
    return lines


def _exit_intel_section(exit_intel: Optional[ExitIntelSnapshot]) -> list[str]:
    lines = ["Exit IP intelligence (live proxy test):", ""]
    if not exit_intel:
        lines.append("  Not available — enable Xray live proxy test.")
        return lines

    loc = format_country(exit_intel.country_code, exit_intel.country) or "?"
    lines.append(f"  IP           : {exit_intel.ip}")
    lines.append(f"  Country      : {loc}" + (f"  colo={exit_intel.colo}" if exit_intel.colo else ""))
    if exit_intel.asn:
        lines.append(f"  ASN          : {exit_intel.asn}")
    org = exit_intel.organization or exit_intel.isp
    if org:
        lines.append(f"  Provider     : {org}")
    if exit_intel.datacenter:
        lines.append(f"  Datacenter   : {exit_intel.datacenter}")
    lines.append(f"  Type         : {'datacenter/hosting' if exit_intel.is_datacenter else 'unknown/residential'}")
    if exit_intel.reputation is not None:
        lines.append(f"  Reputation   : {exit_intel.reputation}/100")
    return lines


def _stealth_profile(r: AnalysisResult) -> list[str]:
    """DPI, camouflage, origin exposure, and confidence calibration block."""
    dpi = r.dpi
    cam = r.camouflage
    origin = r.origin_exposure
    cal = r.confidence_calibration
    lines = [
        "1b) STEALTH & EXPOSURE PROFILE",
        "─" * 64,
        f"  DPI resistance       : [{score_bar(dpi.score)}]  {format_score(dpi.score)}  Grade {dpi.grade}"
        f"  ({dpi.detection_risk} detection risk)",
        f"  Traffic camouflage     : [{score_bar(cam.score)}]  {format_score(cam.score)}  Grade {cam.grade}"
        f"  ({cam.naturalness})",
        f"  Origin exposure risk   : [{score_bar(origin.risk_score)}]  {format_score(origin.risk_score)}"
        f"  ({origin.exposure_level})",
        f"  Inferred origin IP     : {origin.inferred_origin_ip or 'N/A'}",
        "",
        f"  {dpi.summary}",
        f"  {cam.summary}",
        f"  {origin.summary}",
        "",
        "  Confidence calibration :",
        f"  {cal.summary}",
    ]
    for insight in cal.insights[:6]:
        lines.append(
            f"    [{insight.confidence.value}] {insight.category}: {insight.title}"
            f" ({_pct(insight.calibrated_confidence)})"
        )
    lines.extend(["", "  Top DPI factors:"])
    lines.extend(format_risk_factors(dpi.factors, limit=4))
    lines.extend(["", "  Top camouflage layers:"])
    lines.extend(format_risk_factors(cam.layers, limit=4))
    if origin.factors:
        lines.extend(["", "  Origin exposure factors:"])
        lines.extend(format_risk_factors(origin.factors, limit=4))
    return lines


def _iran_context(r: AnalysisResult) -> list[str]:
    opt = r.optimization
    lines = ["Iran market & filtering context:", ""]
    if opt.iran_score or opt.grade != "—":
        lines.append(f"  Iran optimizer score : {opt.iran_score}/100  (Grade {opt.grade})")
        lines.append(f"  Sell readiness       : {opt.sell_readiness}%")
        if opt.verdict:
            lines.append(f"  Verdict              : {opt.verdict}")

    c = r.config
    risks: list[str] = []
    if not c.tls and not c.reality:
        risks.append("Plain HTTP/WebSocket — high DPI/blocking risk on Iranian ISPs")
    if c.transport_type == TransportType.WS:
        risks.append("WebSocket transport — fingerprintable; XHTTP/TLS preferred")
    if r.deployment.cdn_type == "ArvanCloud":
        risks.append("Arvan CDN — good for Iranian users (low latency to edge) but origin may be abroad")
    if risks:
        lines.append("  Filtering risks:")
        for risk in risks:
            lines.append(f"    • {risk}")

    if opt.actions:
        lines.append("  Top priority fixes:")
        for act in opt.actions[:3]:
            lines.append(f"    [P{act.priority_rank}] {act.title}")

    if not opt.iran_score and not risks:
        lines.append("  No Iran optimizer data for this profile.")
    return lines


def _security_actions(r: AnalysisResult) -> list[str]:
    lines = ["Prioritized security actions:", ""]
    for rec in r.security.recommendations[:5]:
        lines.append(f"  • {rec.title} (+{rec.score_impact}): {rec.description}")
    if not r.security.recommendations:
        lines.append("  No recommendations — profile looks acceptable.")
    return lines


def _dynamic_flow(tunnel_id: str, r: AnalysisResult) -> str:
    """Correct traffic-flow text for this config (fixes stale :443 templates)."""
    c = r.config
    d = r.deployment
    host = _front_host(c, r.dns.hostname)
    port = c.port
    exit_intel = _get_exit_intel(r)
    origin = _origin_country_hint(r, exit_intel) or "hidden origin"

    flows = {
        "reverse_proxy": f"Client → Nginx/Caddy :{port} → 127.0.0.1:Xray ({c.protocol.value})",
        "load_balancer": (
            f"Client → {d.cdn_type or 'CDN'} multi-edge ({len(r.dns.a_records)} A records) → origin"
            if d.cdn_type and len(r.dns.a_records) >= 2
            else TUNNEL_CATALOG.get(tunnel_id, {}).get("flow", "")
        ),
        "arvan_cdn": f"Client → Arvan edge (IR) → Origin VPS ({origin}) → Xray :{port}",
        "cdn_fronting": f"Client → {d.cdn_type or 'CDN'} edge → Origin ({origin}) → Xray",
        "direct_vps": f"Client → {host}:{port} → Xray inbound (direct)",
    }
    if tunnel_id in flows:
        return flows[tunnel_id]
    return TUNNEL_CATALOG.get(tunnel_id, {}).get("flow", "")


def _post_process_ranked(r: AnalysisResult, ranked: list[RankedScenario]) -> list[RankedScenario]:
    """Adjust confidence, dedupe, and downgrade misleading scenarios."""
    d = r.deployment
    seen_cdn_specific = any(
        s.tunnel_id.endswith("_cdn") and s.tunnel_id != "cdn_fronting" and s.confidence >= 0.70
        for s in ranked
    )

    out: list[RankedScenario] = []
    for s in ranked:
        conf = min(s.confidence, CONFIDENCE_CAP)

        if s.tunnel_id == "cdn_fronting" and seen_cdn_specific:
            conf = min(conf, 0.72)

        if d.cdn_type and s.tunnel_id == "direct_vps":
            conf = min(conf, 0.18)

        if s.tunnel_id == "load_balancer" and d.cdn_type and len(r.dns.a_records) >= 2:
            conf = min(conf, 0.32)
            out.append(RankedScenario(
                rank=s.rank, tunnel_id=s.tunnel_id, name="CDN multi-edge (anycast)",
                category=s.category, confidence=conf,
                traffic_flow=_dynamic_flow(s.tunnel_id, r),
                description="Multiple A records are CDN edge nodes (anycast), not separate origin servers.",
                evidence=s.evidence + ["cdn_multi_edge=likely_anycast"],
                setup_steps=s.setup_steps,
            ))
        else:
            out.append(RankedScenario(
                rank=s.rank, tunnel_id=s.tunnel_id, name=s.name, category=s.category,
                confidence=conf, traffic_flow=_dynamic_flow(s.tunnel_id, r) or s.traffic_flow,
                description=s.description, evidence=s.evidence, setup_steps=s.setup_steps,
                ruled_out=s.ruled_out, rule_out_reason=s.rule_out_reason,
            ))

    out.sort(key=lambda x: x.confidence, reverse=True)
    for i, s in enumerate(out, 1):
        s.rank = i
    return out


def _split_ranked_lists(
    ranked: list[RankedScenario],
) -> tuple[list[RankedScenario], list[RankedScenario]]:
    """When primary confidence is high, move <30% scenarios to low-probability bucket."""
    if not ranked:
        return [], []
    primary_conf = ranked[0].confidence
    if primary_conf < 0.80:
        return ranked, []

    main = [s for s in ranked if s.confidence >= LOW_SCENARIO_THRESHOLD]
    low = [s for s in ranked if s.confidence < LOW_SCENARIO_THRESHOLD]
    return main, low


# ── Implementation playbooks (per topology) ─────────────────────────────────

def _xray_inbound_sketch(c: ParsedConfig) -> list[str]:
    """Approximate server-side inbound JSON fields matching the client link."""
    transport = _effective_transport(c)
    sni = c.sni or ""
    host = c.host or sni
    short_id = c.short_id or ""
    lines = [
        "Server inbound sketch (match client link exactly):",
        "{",
        f'  "protocol": "{c.protocol.value.lower()}",',
        f'  "port": {c.port},',
        '  "listen": "127.0.0.1",  // or 0.0.0.0 if no reverse proxy',
        '  "settings": { ... clients/users matching UUID/password ... },',
        '  "streamSettings": {',
    ]
    if c.reality:
        lines.extend([
            '    "security": "reality",',
            '    "realitySettings": {',
            f'      "dest": "{c.sni or "TARGET:443"}",',
            f'      "serverNames": ["{sni}"],',
            f'      "privateKey": "<generated>",',
            f'      "shortIds": ["{short_id}"]',
            "    },",
        ])
    elif c.tls:
        lines.extend([
            '    "security": "tls",',
            '    "tlsSettings": {',
            f'      "serverName": "{host}",',
            f'      "alpn": {json.dumps((c.alpn or "h2,http/1.1").split(","))}',
            "    },",
        ])
    else:
        lines.append('    "security": "none",')

    net_map = {
        TransportType.TCP: "tcp", TransportType.WS: "ws", TransportType.GRPC: "grpc",
        TransportType.HTTPUPGRADE: "httpupgrade", TransportType.XHTTP: "xhttp",
        TransportType.QUIC: "quic",
    }
    net = net_map.get(transport, "tcp")
    lines.append(f'    "network": "{net}",')

    if transport == TransportType.WS:
        lines.extend([
            '    "wsSettings": {',
            f'      "path": "{c.path or "/"}",',
            f'      "headers": {{ "Host": "{host}" }}',
            "    }",
        ])
    elif transport == TransportType.GRPC:
        lines.extend([
            '    "grpcSettings": {',
            f'      "serviceName": "{c.service_name or "GRPC_SERVICE"}"',
            "    }",
        ])
    elif transport == TransportType.XHTTP:
        lines.extend([
            '    "xhttpSettings": {',
            f'      "path": "{c.path or "/"}",',
            f'      "host": "{host}"',
            "    }",
        ])
    elif transport == TransportType.HTTPUPGRADE:
        lines.extend([
            '    "httpupgradeSettings": {',
            f'      "path": "{c.path or "/"}",',
            f'      "host": "{host}"',
            "    }",
        ])

    lines.extend(["  }", "}"])
    return lines


def _arvan_origin_step(r: AnalysisResult) -> str:
    exit_intel = _get_exit_intel(r)
    origin = _origin_country_hint(r, exit_intel)
    if origin:
        org = f" ({exit_intel.organization})" if exit_intel and exit_intel.organization else ""
        return f"2. Set origin to a {origin} VPS{org} — live exit IP confirms foreign egress."
    return "2. Set origin server IP and enable CDN (country unknown without live test)."


def _reverse_proxy_listen_step(c: ParsedConfig) -> str:
    if c.tls:
        return f"2. Nginx/Caddy listens on 0.0.0.0:{c.port} — terminate TLS, forward to Xray."
    return f"2. Nginx/Caddy listens on 0.0.0.0:{c.port} (plain HTTP) — forward to Xray."


def _playbook(tunnel_id: str, r: AnalysisResult) -> list[str]:
    """Full implementation steps for a topology type."""
    c = r.config
    d = r.deployment
    dns = r.dns
    host = _front_host(c, dns.hostname)
    transport = _effective_transport(c)

    pb: dict[str, list[str]] = {
        "direct_vps": [
            "DIRECT VPS — full implementation",
            "1. Provision a VPS (any provider). Open firewall TCP {port} (+ UDP if QUIC/Hy2/TUIC).".format(port=c.port),
            f"2. Point DNS A record for {host} directly to VPS IP (no CDN proxy).",
            "3. Install Xray-core (or 3x-ui / Marzban panel).",
            f"4. Create inbound: {c.protocol.value} on port {c.port}, transport {transport.value}.",
            "5. If using TLS: install cert (Let's Encrypt) on inbound or reverse proxy.",
            "6. Distribute client link — address resolves to origin IP (origin is exposed).",
        ],
        "cdn_fronting": [
            "CDN FRONTING (generic) — full implementation",
            f"1. Origin VPS: install Xray inbound ({c.protocol.value}:{c.port}).",
            "2. Put a reverse proxy (Nginx/Caddy) in front if transport is WS/gRPC/XHTTP.",
            f"3. CDN panel: add domain {host}, set origin IP, enable CDN/proxy mode.",
            "4. DNS: domain resolves to CDN edge IPs (not origin).",
            "5. CDN rules: disable caching on tunnel path; allow WebSocket/gRPC pass-through.",
            "6. Verify: external DNS shows CDN IPs; origin IP not in public DNS.",
        ],
        "cloudflare_cdn": [
            "CLOUDFLARE CDN FRONTING — full implementation",
            f"1. Domain {host} on Cloudflare DNS with orange-cloud (Proxied) enabled.",
            "2. SSL/TLS mode: Full or Full (Strict) depending on origin certificate.",
            f"3. Origin VPS: Xray inbound + Nginx/Caddy for {transport.value} on port {c.port}.",
            "4. Cloudflare Network: enable HTTP/2; enable HTTP/3 if ALPN h3 in config.",
            "5. WebSocket: Cloudflare passes WS by default — set Nginx Upgrade headers.",
            "6. Optional: Cloudflare WAF rules to allow your path; disable Bot Fight for tunnel.",
            f"7. Client link address = {host}, SNI/Host must match panel settings.",
        ],
        "arvan_cdn": [
            "ARVAN CDN FRONTING — full implementation",
            f"1. Arvan panel → CDN → add domain {host}.",
            _arvan_origin_step(r),
            f"3. Origin: Xray inbound behind Nginx/Caddy for {transport.value}.",
            f"4. WS path {c.path or '/'} — configure Arvan to pass WebSocket to origin.",
            "5. SSL: Arvan can terminate TLS at edge OR pass-through to origin.",
            "6. Firewall on origin: allow Arvan edge IP ranges (or restrict to Arvan only).",
            "7. Client sees Arvan edge IPs in DNS — origin IP stays hidden.",
        ],
        "akamai_cdn": [
            "AKAMAI CDN — full implementation",
            f"1. Enterprise Akamai property for {host}.",
            "2. Origin hostname → your VPS; configure Akamai to forward WS/gRPC.",
            "3. Xray inbound on origin with reverse proxy.",
        ],
        "fastly_cdn": [
            "FASTLY CDN — full implementation",
            f"1. Fastly service for {host} → origin backend.",
            "2. Enable WebSocket support in Fastly VCL/service config.",
            "3. Xray + reverse proxy on origin VPS.",
        ],
        "cloudfront_cdn": [
            "AWS CLOUDFRONT — full implementation",
            f"1. CloudFront distribution → origin {host}.",
            "2. Origin protocol policy: match viewer; enable HTTP/2.",
            "3. Xray inbound on EC2/VPS origin.",
        ],
        "bunny_cdn": [
            "BUNNYCDN — full implementation",
            f"1. Bunny pull zone for {host} → origin IP.",
            "2. Enable WebSocket in Bunny edge rules.",
            "3. Xray on origin VPS.",
        ],
        "gcore_cdn": [
            "GCORE CDN — full implementation",
            f"1. Gcore CDN resource for {host}.",
            "2. Origin group → VPS IP; pass WS/gRPC.",
            "3. Xray inbound on origin.",
        ],
        "cloudflare_tunnel": [
            "CLOUDFLARE TUNNEL (cloudflared) — full implementation",
            "1. Install cloudflared on origin (no inbound port required on firewall).",
            f"2. Zero Trust → Public Hostname: {host} → http://localhost:<xray_port>.",
            f"3. Xray listens on localhost only (e.g. 127.0.0.1:{c.port}).",
            "4. cloudflared creates outbound tunnel to Cloudflare edge.",
            "5. Client connects to Cloudflare; no direct origin IP exposure.",
        ],
        "direct_xray_inbound": [
            "DIRECT XRAY INBOUND — full implementation",
            f"1. Install Xray-core or 3x-ui/Marzban on VPS.",
            f"2. Create inbound: {c.protocol.value} on 0.0.0.0:{c.port} (not 127.0.0.1).",
            f"3. Transport {transport.value}; TLS {'enabled' if c.tls else 'disabled'} on same port.",
            "4. No Nginx/Caddy required — Xray terminates TLS and handles WS directly.",
            "5. Firewall: open TCP {port} only.".format(port=c.port),
            "6. Common with 3x-ui when panel and inbound share the node.",
        ],
        "reverse_proxy": [
            "REVERSE PROXY (Nginx/Caddy/HAProxy) — full implementation",
            f"1. Xray inbound listens on 127.0.0.1:<internal_port> (not public).",
            _reverse_proxy_listen_step(c),
            f"3. Domain: {host}",
        ],
        "reverse_tunnel_frp": [
            "REVERSE TUNNEL (frp/nps/ngrok) — full implementation",
            "1. Relay VPS (public IP): run frps / nps server.",
            f"2. Relay exposes port {c.port} (what client connects to).",
            "3. Behind NAT/home server: run frpc/npc → forward to local Xray inbound.",
            "4. Xray runs on LAN machine; no public IP needed on Xray host.",
            f"5. Client link address = relay VPS ({c.address}:{c.port}).",
        ],
        "sni_fronting": [
            "SNI / IP FRONTING — full implementation",
            f"1. Client connects to IP {c.address} but TLS SNI = {c.sni}.",
            f"2. Server/CDN must accept SNI {c.sni} on that IP.",
            "3. Inbound streamSettings must list serverNames matching SNI.",
            "4. Used to reach CDN edge IP while presenting a different domain in TLS.",
        ],
        "host_sni_split": [
            "HOST ≠ SNI (domain fronting) — full implementation",
            f"1. TLS SNI: {c.sni} | HTTP Host header: {c.host}",
            "2. CDN or reverse proxy routes by Host header, not SNI alone.",
            "3. Client streamSettings: sni and host must differ as in link.",
            "4. Server inbound must accept the Host header value.",
        ],
        "xhttp_split": [
            "XHTTP SPLIT (separate up/downlink) — full implementation",
            f"1. Uplink path: {c.path or '/'} on primary address.",
            "2. downloadSettings in client config points to separate downlink path/host.",
            "3. Server: two XHTTP paths or CDN edges for upload vs download.",
            "4. REALITY + XHTTP → use stream-one mode in Xray 26+.",
        ],
        "reality_camouflage": [
            "REALITY CAMOUFLAGE — full implementation",
            f"1. Choose dest site for camouflage (e.g. {c.sni or 'www.google.com'}:443).",
            "2. Generate x25519 keypair: xray x25519 → privateKey on server, publicKey in client.",
            f"3. shortIds: ['{c.short_id or ''}']",
            f"4. serverNames: ['{c.sni or ''}']",
            "5. No real TLS certificate needed on server — handshake mimics dest site.",
            f"6. Transport: {transport.value}; flow: {c.flow or 'none'}.",
        ],
        "multi_hop": [
            "MULTI-HOP / RELAY CHAIN — full implementation",
            f"1. Entry node: {c.address}:{c.port} (what client sees).",
            "2. Entry Xray outbound → second relay VPS.",
            "3. Final hop → exit VPS with freedom outbound to internet.",
            "4. Each hop: VLESS/VMESS chain or gRPC relay.",
            "5. Not visible in single share link — requires server-side routing rules.",
        ],
        "wireguard_tunnel": [
            "WIREGUARD — full implementation",
            f"1. Server: wg0 interface, listen UDP {c.port}.",
            f"2. Endpoint: {c.address}:{c.port}",
            "3. Generate server/client keypair; set allowed_ips and persistent_keepalive.",
            "4. Enable ip_forward + NAT (iptables/nft) for full tunnel.",
            "5. Xray can run behind WG or on same VPS separately.",
        ],
        "openvpn_tunnel": [
            "OPENVPN — full implementation",
            f"1. OpenVPN server on {c.address}:{c.port} (TCP or UDP).",
            "2. Generate CA + server cert + client .ovpn profile.",
            "3. Push routes or full-tunnel depending on use case.",
        ],
        "hysteria2_quic": [
            "HYSTERIA2 (QUIC/UDP) — full implementation",
            f"1. Hy2 server listens UDP {c.port}.",
            f"2. Password/auth from link; obfuscation optional.",
            f"3. SNI: {c.sni or 'optional'}",
            "4. Firewall: UDP port must be open (not just TCP).",
            "5. Use sing-box or hysteria2 standalone binary on VPS.",
        ],
        "tuic_quic": [
            "TUIC (QUIC) — full implementation",
            f"1. TUIC server UDP {c.port}.",
            f"2. UUID/password from link; congestion control: bbr/cubic.",
            f"3. ALPN/SNI: {c.sni or 'optional'}",
            "4. sing-box or Marzban TUIC inbound.",
        ],
        "load_balancer": [
            "LOAD BALANCER / MULTI-IP — full implementation",
            "1. Multiple A records or CDN edges distribute traffic.",
            "2. Each backend runs identical Xray inbound config.",
            "3. Health-check removes failed nodes.",
            f"4. DNS returns: {', '.join((dns.a_records or [])[:4]) or 'multiple IPs'}.",
        ],
        "ssh_tunnel": [
            "SSH TUNNEL — full implementation",
            "1. SSH server on VPS; client: ssh -L localport:127.0.0.1:xrayport user@host.",
            "2. Xray inbound on localhost only.",
            "3. Usually for testing — not production scale.",
        ],
        "gost_relay": [
            "GOST RELAY CHAIN — full implementation",
            "1. GOST relay node forwards to upstream Xray.",
            f"2. Entry: {c.address}:{c.port}",
            "3. Chain: gost -L=:port -F=relay+tls://upstream:port",
        ],
    }

    steps = pb.get(tunnel_id, [
        f"Topology: {TUNNEL_CATALOG.get(tunnel_id, {}).get('name', tunnel_id)}",
        "See Setup Guide tab for data-driven steps.",
    ])

    # Enrich reverse_proxy playbook with transport-specific nginx hints
    if tunnel_id == "reverse_proxy":
        if transport == TransportType.WS and c.path:
            steps.extend([
                f"4. Nginx location {c.path}:",
                "     proxy_http_version 1.1;",
                "     proxy_set_header Upgrade $http_upgrade;",
                "     proxy_set_header Connection upgrade;",
                f"     proxy_set_header Host {c.host or host};",
                "     proxy_pass http://127.0.0.1:<xray_port>;",
            ])
        elif transport == TransportType.GRPC:
            steps.extend([
                f"4. Nginx grpc_pass for serviceName: {c.service_name or 'REQUIRED'}",
                "     grpc_set_header Host ...;",
            ])
        elif transport == TransportType.XHTTP and c.path:
            steps.extend([
                f"4. XHTTP path {c.path} → proxy_pass / grpc_pass per Xray XHTTP docs.",
                f"   Host header: {c.host or host}",
            ])

    return steps


# ── Scenario ranking ──────────────────────────────────────────────────────────

def _collect_evidence(r: AnalysisResult) -> list[str]:
    """Gather cross-tab evidence lines."""
    c, d, dns, conn, tls, x = r.config, r.deployment, r.dns, r.connectivity, r.tls, r.xray_test
    ev: list[str] = []

    ev.append(f"Link: {c.protocol.value} | { _effective_transport(c).value } | {_security_label(c)} | port {c.port}")
    ev.append(f"Address: {c.address}" + (" (direct IP)" if is_ip_address(c.address) else " (domain)"))

    if dns.a_records:
        ev.append(f"DNS A: {', '.join(dns.a_records[:4])}")
    if dns.cname_records:
        ev.append(f"DNS CNAME: {', '.join(dns.cname_records[:3])}")
    if d.cdn_type:
        ev.append(f"CDN detected: {d.cdn_type}")
    if d.cdn_backend_ips:
        ev.append(f"CDN edge IPs: {', '.join(d.cdn_backend_ips[:4])}")

    for ip in r.network[:3]:
        loc = format_country(ip.country_code, ip.country)
        parts = [f"IP {ip.ip}: {loc}"]
        if ip.asn:
            parts.append(ip.asn)
        if ip.cdn_detected:
            parts.append(f"CDN={ip.cdn_detected} ({_pct(ip.cdn_confidence)})")
        if ip.is_datacenter:
            parts.append("datacenter")
        ev.append(" | ".join(parts))

    if conn.tcp_connect != TestStatus.PENDING:
        ev.append(f"TCP connect: {conn.tcp_connect.value}" + (f" ({conn.tcp_latency_ms}ms)" if conn.tcp_latency_ms else ""))
    if conn.websocket_upgrade != TestStatus.PENDING:
        ev.append(f"WebSocket upgrade: {conn.websocket_upgrade.value}")
    if tls.enabled:
        ev.append(f"TLS: {tls.version or '?'} | {tls.certificate_subject or 'no subject'}")

    exit_ip, exit_ct, exit_colo = _exit_info(r)
    if exit_ip:
        ev.append(f"Live test exit IP: {exit_ip} ({exit_ct or '?'})" + (f" colo={exit_colo}" if exit_colo else ""))
    if _proxy_ok(r):
        ev.append(f"Proxy test: VALID ({x.proxy_latency_ms or '?'} ms)")

    if r.traceroute.hop_count:
        ev.append(f"Traceroute hops: {r.traceroute.hop_count}")

    ev.append(f"Edge route: {_format_edge_route(r)}")

    return ev


def _boost_confidence(tunnel_id: str, base: float, r: AnalysisResult) -> float:
    """Adjust confidence using live test and cross-signals (capped at CONFIDENCE_CAP)."""
    conf = base
    d = r.deployment
    exit_ip, exit_ct, _ = _exit_info(r)

    if tunnel_id.endswith("_cdn") or tunnel_id in ("cdn_fronting",):
        if d.cdn_type:
            conf = min(CONFIDENCE_CAP, conf + 0.03)
        if exit_ip and exit_ct:
            edge_ct = r.network[0].country_code if r.network else None
            if edge_ct and exit_ct != edge_ct:
                conf = min(CONFIDENCE_CAP, conf + 0.02)

    if tunnel_id == "direct_vps" and not d.cdn_type and not any(ip.cdn_detected for ip in r.network):
        conf = min(CONFIDENCE_CAP, conf + 0.05)

    if tunnel_id == "reality_camouflage" and r.config.reality:
        conf = max(conf, 0.90)

    if tunnel_id == "cloudflare_tunnel":
        if any("cfargotunnel" in (c or "").lower() for c in r.dns.cname_records):
            conf = max(conf, 0.88)

    return round(min(CONFIDENCE_CAP, conf), 2)


def _build_ranked_scenarios(r: AnalysisResult) -> list[RankedScenario]:
    """Merge tunnel_analysis matches + deployment guesses into one ranked list."""
    ta = r.tunnel_analysis
    seen: dict[str, RankedScenario] = {}

    for m in ta.detected_types:
        conf = _boost_confidence(m.tunnel_id, m.confidence, r)
        seen[m.tunnel_id] = RankedScenario(
            rank=0,
            tunnel_id=m.tunnel_id,
            name=m.name,
            category=m.category,
            confidence=conf,
            traffic_flow=m.traffic_flow,
            description=m.description,
            evidence=list(m.evidence),
            setup_steps=list(m.setup_steps),
        )

    for g in r.deployment.guesses:
        tid = _guess_to_tunnel_id(g.name)
        if not tid or tid in seen:
            if tid and tid in seen and g.confidence > seen[tid].confidence:
                seen[tid].confidence = _boost_confidence(tid, g.confidence, r)
                if g.description and g.description not in seen[tid].evidence:
                    seen[tid].evidence.append(g.description)
            continue
        cat = TUNNEL_CATALOG.get(tid, {})
        seen[tid] = RankedScenario(
            rank=0,
            tunnel_id=tid,
            name=cat.get("name", g.name),
            category=_category_for_id(tid),
            confidence=_boost_confidence(tid, g.confidence, r),
            traffic_flow=cat.get("flow", ""),
            description=cat.get("explain", g.description),
            evidence=[g.description] if g.description else [],
            setup_steps=[],
        )

    ranked = sorted(seen.values(), key=lambda s: s.confidence, reverse=True)
    return _post_process_ranked(r, ranked)


def _guess_to_tunnel_id(name: str) -> Optional[str]:
    mapping = {
        "Direct VPS": "direct_vps",
        "CDN Fronted": "cdn_fronting",
        "Cloudflare CDN": "cloudflare_cdn",
        "Arvan CDN": "arvan_cdn",
        "Akamai CDN": "akamai_cdn",
        "Fastly CDN": "fastly_cdn",
        "AWS CloudFront": "cloudfront_cdn",
        "BunnyCDN": "bunny_cdn",
        "Gcore CDN": "gcore_cdn",
        "Reverse Proxy": "reverse_proxy",
        "Cloudflare Tunnel": "cloudflare_tunnel",
        "SNI Fronting": "sni_fronting",
        "Reverse Tunnel": "reverse_tunnel_frp",
        "Multi Hop": "multi_hop",
    }
    return mapping.get(name)


def _category_for_id(tid: str) -> str:
    if "cdn" in tid or tid == "cdn_fronting":
        return "cdn"
    if tid in ("reverse_proxy",):
        return "reverse_proxy"
    if tid in ("reverse_tunnel_frp", "ssh_tunnel", "gost_relay", "cloudflare_tunnel"):
        return "tunnel_agent"
    if tid == "reality_camouflage":
        return "camouflage"
    if tid in ("wireguard_tunnel", "openvpn_tunnel", "hysteria2_quic", "tuic_quic"):
        return "protocol_tunnel"
    if tid in ("multi_hop", "load_balancer"):
        return "chain"
    if tid in ("sni_fronting", "host_sni_split", "xhttp_split"):
        return "fronting"
    return "direct"


def _build_architecture_layers(r: AnalysisResult, primary: Optional[RankedScenario]) -> list[str]:
    """Stacked architecture — exit IP is origin egress, not a separate mystery layer."""
    c = r.config
    d = r.deployment
    exit_intel = _get_exit_intel(r)
    origin_hint = _origin_country_hint(r, exit_intel) or "unknown region"

    ranked = _build_ranked_scenarios(r)
    active = [s for s in ranked if s.confidence >= 0.40]
    rp_layer = next((s for s in active if s.tunnel_id == "reverse_proxy"), None)
    camo_layer = next((s for s in active if s.category == "camouflage"), None)

    lines = ["Architecture stack (corrected — exit IP = origin egress):", ""]

    client = "Client"
    if r.tunnel.client_country:
        client += f" ({r.tunnel.client_country})"
    chain = [client]

    if d.cdn_type and r.network:
        net = r.network[0]
        edge_loc = format_country(net.country_code, net.country) or "?"
        chain.append(f"{d.cdn_type} edge — {net.ip} ({edge_loc})")
    elif r.network:
        net = r.network[0]
        chain.append(f"Target {net.ip} ({format_country(net.country_code, net.country)})")

    if d.cdn_type:
        org_suffix = ""
        if exit_intel and exit_intel.organization:
            org_suffix = f", {exit_intel.organization}"
        chain.append(f"Origin VPS — {origin_hint}{org_suffix} (IP hidden behind CDN)")

    if rp_layer and _effective_transport(c) in (
        TransportType.WS, TransportType.GRPC, TransportType.XHTTP, TransportType.HTTPUPGRADE,
    ):
        chain.append(f"Nginx/Caddy :{c.port} → 127.0.0.1:Xray")

    proto = c.protocol.value
    chain.append(f"Xray {'REALITY' if camo_layer else ''} inbound ({proto})".replace("  ", " "))

    if exit_intel:
        chain.append(f"Internet egress — {exit_intel.ip} ({origin_hint or '?'})")
    else:
        chain.append("Internet egress — unknown (run live test)")

    lines.append(f"  {chain[0]}")
    for node in chain[1:]:
        lines.extend(["     │", "     ▼", f"  {node}"])

    return lines


def _catalog_coverage(r: AnalysisResult, ranked: list[RankedScenario]) -> list[str]:
    """Show every known topology — applicable or ruled out."""
    ranked_ids = {s.tunnel_id: s for s in ranked}
    lines = [
        "Full topology catalog (all known deployment methods):",
        "",
    ]

    categories: dict[str, list[str]] = {
        "direct": [],
        "cdn": [],
        "reverse_proxy": [],
        "tunnel_agent": [],
        "camouflage": [],
        "fronting": [],
        "protocol_tunnel": [],
        "chain": [],
    }

    for tid, cat in TUNNEL_CATALOG.items():
        category = _category_for_id(tid)
        match = ranked_ids.get(tid)
        if match and match.confidence >= 0.30:
            status = f"APPLICABLE  {_pct(match.confidence)}  [{_bar(match.confidence)}]"
        else:
            reason = _rule_out_reason(tid, r)
            status = f"RULED OUT   — {reason}"

        line = f"  {cat['name']:<38} {status}"
        categories.setdefault(category, []).append(line)

    labels = {
        "direct": "── Direct connection ──",
        "cdn": "── CDN fronting (all providers) ──",
        "reverse_proxy": "── Reverse proxy layer ──",
        "tunnel_agent": "── Tunnel agents (cloudflared / frp / SSH / GOST) ──",
        "camouflage": "── Camouflage (REALITY) ──",
        "fronting": "── Fronting variants (SNI / Host split / XHTTP split) ──",
        "protocol_tunnel": "── Protocol-native tunnels ──",
        "chain": "── Multi-node / load balancing ──",
    }

    for cat_key, label in labels.items():
        if categories.get(cat_key):
            lines.append(label)
            lines.extend(categories[cat_key])
            lines.append("")

    return lines


def _rule_out_reason(tid: str, r: AnalysisResult) -> str:
    c, d = r.config, r.deployment
    cdn_ids = {
        "cloudflare_cdn", "arvan_cdn", "akamai_cdn", "fastly_cdn",
        "cloudfront_cdn", "bunny_cdn", "gcore_cdn", "cdn_fronting",
    }

    if tid in cdn_ids:
        if not d.cdn_type and not any(ip.cdn_detected for ip in r.network):
            return "no CDN signal in DNS/ASN"
        if tid == "arvan_cdn" and d.cdn_type and d.cdn_type != "ArvanCloud":
            return f"CDN is {d.cdn_type}, not Arvan"
        if tid == "cloudflare_cdn" and d.cdn_type and d.cdn_type != "Cloudflare":
            return f"CDN is {d.cdn_type}, not Cloudflare"
        return "CDN present but confidence below threshold"

    if tid == "direct_vps":
        if d.cdn_type or any(ip.cdn_detected for ip in r.network):
            return "CDN detected — not direct"
        return "weak direct-VPS signals"

    if tid == "cloudflare_tunnel":
        if not any("cfargotunnel" in (x or "").lower() for x in r.dns.cname_records):
            return "no cfargotunnel CNAME"
        return "confidence below threshold"

    if tid == "reality_camouflage":
        if not c.reality:
            return "security is not REALITY"
        return "confidence below threshold"

    if tid in ("wireguard_tunnel", "openvpn_tunnel", "hysteria2_quic", "tuic_quic"):
        proto_map = {
            "wireguard_tunnel": ProtocolType.WIREGUARD,
            "openvpn_tunnel": ProtocolType.OPENVPN,
            "hysteria2_quic": ProtocolType.HYSTERIA2,
            "tuic_quic": ProtocolType.TUIC,
        }
        if c.protocol != proto_map.get(tid):
            return f"protocol is {c.protocol.value}, not {proto_map[tid].value}"
        return "confidence below threshold"

    if tid == "reverse_tunnel_frp":
        remark = (c.remark or "").lower()
        if not any(w in remark for w in ("frp", "nps", "ngrok", "bore", "rathole")):
            return "no reverse-tunnel remark hint"
        return "confidence below threshold"

    if tid == "sni_fronting":
        if not (is_ip_address(c.address) and c.sni and c.sni != c.address):
            return "address is domain or SNI matches address"
        return "confidence below threshold"

    if tid == "host_sni_split":
        if not (c.host and c.sni and c.host != c.sni):
            return "host and SNI are equal or missing"
        return "confidence below threshold"

    if tid == "xhttp_split":
        if _effective_transport(c) != TransportType.XHTTP:
            return "transport is not XHTTP"
        return "no downloadSettings / dl hint"

    if tid == "load_balancer":
        if len(r.dns.a_records) < 2:
            return "single A record"
        if d.cdn_type:
            return "multiple A records are CDN anycast edges, not origin load balancing"
        return "confidence below threshold"

    if tid == "multi_hop":
        return "no relay/chain evidence (remark/traceroute)"

    return "signals do not match this config profile"


def _origin_geo_note(r: AnalysisResult, exit_intel: Optional[ExitIntelSnapshot]) -> list[str]:
    """Clarify edge vs origin vs exit geography."""
    lines = ["Geography interpretation (critical for CDN setups):", ""]
    d = r.deployment

    lines.append(f"  Edge route (corrected): {_format_edge_route(r)}")
    if d.cdn_type:
        lines.append(
            f"  ⚠ CDN EDGE ({d.cdn_type}) — NOT the origin VPS country."
        )

    if exit_intel:
        loc = format_country(exit_intel.country_code, exit_intel.country) or "?"
        lines.append(
            f"  Origin egress (live test): {exit_intel.ip} ({loc})"
            + (f" colo={exit_intel.colo}" if exit_intel.colo else "")
        )
        if exit_intel.organization:
            lines.append(f"  Egress provider: {exit_intel.organization}"
                         + (f" | {exit_intel.asn}" if exit_intel.asn else ""))

        if d.cdn_type and r.network:
            edge_ct = r.network[0].country_code
            exit_ct = exit_intel.country_code or exit_intel.country
            if exit_ct and edge_ct and exit_ct != edge_ct:
                lines.append(
                    f"  → Edge ({edge_ct}) vs egress ({exit_ct}): "
                    "strong signal that origin VPS is in the egress country."
                )
    else:
        lines.append("  Origin egress: unknown — run Xray live proxy test.")

    if d.cdn_type:
        lines.append("  Origin IP: hidden behind CDN (not in public DNS).")
    elif r.deployment.real_server_ip:
        lines.append(f"  Origin IP (direct): {r.deployment.real_server_ip}")

    return lines


# ── Main builder ──────────────────────────────────────────────────────────────

def build_result_summary(r: AnalysisResult) -> str:
    """Return the full English scenario report for the Result tab."""
    c = r.config
    d = r.deployment
    s = r.security
    dns = r.dns
    host = _front_host(c, dns.hostname)
    ranked = _build_ranked_scenarios(r)
    primary = ranked[0] if ranked else None
    main_ranked, low_ranked = _split_ranked_lists(ranked)
    evidence = _collect_evidence(r)
    exit_intel = _get_exit_intel(r)
    exit_ip, exit_ct, exit_colo = _exit_info(r)
    origin_alts = _build_origin_alternatives(r, exit_intel)

    lines: list[str] = []

    # ── Header + Verdict ──
    lines.extend([
        "RESULT — Comprehensive Scenario Analysis",
        "═" * 64,
        "",
        "VERDICT",
        "─" * 64,
        f"  {_build_verdict(r, primary, exit_intel)}",
        "",
        "This report synthesizes ALL analysis tabs (DNS, Network, TLS, Connectivity,",
        "Tunnel Detection, Deployment, Security, Xray Live Test, Traceroute, CT logs,",
        "Iran Optimizer) into ranked scenarios with full implementation guidance.",
        "",
    ])

    # ── Section 1: Executive profile ──
    lines.extend([
        "1) EXECUTIVE PROFILE",
        "─" * 64,
        f"  Protocol / Transport : {_transport_label(r)}",
        f"  Front domain / host  : {host}:{c.port}",
        f"  Link address         : {c.address}",
        f"  Security score       : {s.score}/100  (potential {s.potential_score}/100)",
        f"  Iran optimizer       : {r.optimization.iran_score}/100  (Grade {r.optimization.grade})",
        f"  Validation           : {'Valid' if r.validation.valid else 'Issues found'}",
        f"  CDN fronting         : {d.cdn_type or 'None detected'}",
        f"  Primary tunnel type  : {r.tunnel_analysis.primary_type or 'Unknown'}"
        f" ({_pct(r.tunnel_analysis.primary_confidence)})",
    ])

    if exit_ip:
        lines.append(f"  Live exit IP         : {exit_ip} ({exit_ct or '?'})"
                     + (f"  colo={exit_colo}" if exit_colo else ""))
        lines.append(f"  Proxy test           : {r.xray_test.proxy_test.value}"
                     + (f"  ({r.xray_test.proxy_latency_ms}ms)" if r.xray_test.proxy_latency_ms else ""))
    else:
        lines.append("  Live exit IP         : N/A — enable Xray live proxy test for egress data")

    if dns.a_records:
        lines.append(f"  DNS A (local)        : {', '.join(dns.local_resolver_ips or dns.a_records[:4])}")
    if dns.all_resolved_ips and dns.all_resolved_ips != (dns.local_resolver_ips or dns.a_records):
        lines.append(f"  DNS A (union)        : {', '.join(dns.all_resolved_ips[:6])}")
    if dns.dns_split_detected:
        lines.append(f"  DNS split detected   : yes")
    if r.connectivity.http_cdn_detected:
        lines.append(f"  CDN (HTTP header)    : {r.connectivity.http_cdn_detected}")
    if r.connectivity.http_panel_detected:
        lines.append(f"  Panel (HTTP)         : {r.connectivity.http_panel_detected}")
    if dns.cname_records:
        lines.append(f"  DNS CNAME            : {', '.join(dns.cname_records[:3])}")
    if d.cdn_backend_ips:
        lines.append(f"  CDN edge IPs         : {', '.join(d.cdn_backend_ips[:4])}")

    lines.append("")
    lines.extend(_stealth_profile(r))
    lines.append("")
    lines.extend(_origin_geo_note(r, exit_intel))
    lines.append("")
    lines.extend(_exit_intel_section(exit_intel))
    lines.append("")

    if origin_alts and d.cdn_type:
        lines.extend(["Origin location hypotheses (ranked):", ""])
        for alt in origin_alts:
            conf_txt = _pct(alt.confidence) if alt.confidence else "N/A"
            lines.append(f"  • {alt.name} [{conf_txt}]")
            lines.append(f"    {alt.explanation}")
        lines.append("")

    lines.extend(_dns_summary(r))
    lines.append("")
    lines.extend(_http_fingerprint_summary(r))
    lines.append("")
    lines.extend(_connectivity_summary(r))
    lines.append("")
    lines.extend(_latency_interpretation(r))
    lines.append("")
    lines.extend(_traceroute_summary(r))
    lines.append("")
    lines.extend(_cert_transparency_summary(r))
    lines.append("")

    # ── Section 2: Primary scenario (most likely) ──
    lines.extend([
        "2) MOST LIKELY SCENARIO (highest confidence)",
        "─" * 64,
    ])

    if primary:
        lines.extend([
            f"  Scenario   : {primary.name}",
            f"  Category   : {primary.category}",
            f"  Confidence : {_pct(primary.confidence)}  [{_bar(primary.confidence)}]",
            f"  Traffic    : {primary.traffic_flow}",
            f"  Summary    : {primary.description}",
            "",
            "  Why this is most likely:",
        ])
        for ev in (primary.evidence or evidence)[:12]:
            lines.append(f"    • {ev}")

        lines.extend(["", "  Full implementation playbook:"])
        playbook = _playbook(primary.tunnel_id, r)
        if primary.setup_steps:
            lines.append("  Config-specific steps (from analysis):")
            for step in primary.setup_steps:
                lines.append(f"    • {step}")
            lines.append("")
        for step in playbook:
            lines.append(f"  {step}")

        lines.extend(["", "  Server inbound configuration:"])
        for ln in _xray_inbound_sketch(c):
            lines.append(f"  {ln}")

        panels = _recommend_panels(c)
        if panels:
            lines.extend(["", "  Recommended panels / tools:"])
            for p in panels:
                lines.append(f"    • {p}")
    else:
        lines.append("  Unable to determine scenario — insufficient analysis data.")

    lines.append("")

    # ── Section 3: Architecture stack ──
    lines.extend([
        "3) ARCHITECTURE STACK (coexisting layers)",
        "─" * 64,
    ])
    lines.extend(_build_architecture_layers(r, primary))
    lines.append("")

    # ── Section 4: All ranked scenarios ──
    lines.extend([
        "4) RANKED SCENARIOS (applicable topologies)",
        "─" * 64,
        "",
    ])

    if main_ranked:
        for sc in main_ranked:
            lines.extend([
                f"  #{sc.rank}  {sc.name}",
                f"       Confidence : {_pct(sc.confidence)}  [{_bar(sc.confidence)}]  ({sc.category})",
                f"       Flow       : {sc.traffic_flow}",
                f"       About      : {sc.description}",
            ])
            if sc.evidence:
                lines.append(f"       Evidence   : {' | '.join(sc.evidence[:4])}")
            impl = _playbook(sc.tunnel_id, r)
            if impl:
                lines.append("       Quick setup:")
                for step in impl[1:4]:
                    lines.append(f"         → {step}")
            lines.append("")
    else:
        lines.append("  No scenarios ranked.")

    if low_ranked:
        lines.extend([
            "  ── Low probability scenarios (<30% — omitted from main list when primary >80%) ──",
            "",
        ])
        for sc in low_ranked:
            lines.append(
                f"  #{sc.rank}  {sc.name}  [{_pct(sc.confidence)}]  — unlikely for this profile"
            )
        lines.append("")

    # ── Section 5: Full catalog coverage ──
    lines.extend([
        "5) TOPOLOGY CATALOG COVERAGE",
        "─" * 64,
    ])
    lines.extend(_catalog_coverage(r, ranked))
    lines.append("")

    # ── Section 6: Reproducibility ──
    lines.extend([
        "6) REPRODUCIBILITY (from client link alone)",
        "─" * 64,
    ])
    rep = r.reproduction
    if rep.reproducible:
        lines.append("  Can reconstruct from link:")
        for item in rep.reproducible:
            val = f" = {item.value}" if item.value else ""
            lines.append(f"    ✓ {item.field}{val}")
    if rep.not_reproducible:
        lines.append("  Server-side only (NOT in link):")
        for item in rep.not_reproducible:
            reason = f" — {item.reason}" if item.reason else ""
            lines.append(f"    ✗ {item.field}{reason}")
    lines.append("")

    # ── Section 7: Unknowns ──
    lines.extend([
        "7) UNKNOWNS & ANALYSIS LIMITATIONS",
        "─" * 64,
        "  The following cannot be proven from external analysis alone:",
    ])
    seen_unknowns: set[str] = set()
    for u in list(d.uncertain_fields or []) + [
        "Origin VPS provider / datacenter (when CDN present)",
        "Panel type (Marzban / 3x-ui / manual)",
        "Outbound routing rules on server",
        "Warp / multi-hop chain beyond first hop",
        "Whether reverse tunnel (frp) is used without remark hint",
    ]:
        if u not in seen_unknowns:
            seen_unknowns.add(u)
            lines.append(f"    ✗ {u}")
    lines.append("")

    # ── Section 8: Build order ──
    lines.extend([
        "8) RECOMMENDED BUILD ORDER (replicate this setup)",
        "─" * 64,
    ])
    lines.extend(_build_order(r, primary, exit_intel))
    lines.append("")

    lines.extend([
        "9) IRAN MARKET & FILTERING CONTEXT",
        "─" * 64,
    ])
    lines.extend(_iran_context(r))
    lines.append("")

    lines.extend([
        "10) PRIORITIZED SECURITY ACTIONS",
        "─" * 64,
    ])
    lines.extend(_security_actions(r))
    lines.append("")

    # ── Section 11: Security warning ──
    if not c.tls and not c.reality:
        lines.extend([
            "11) SECURITY WARNING",
            "─" * 64,
            "  This config uses PLAIN transport (no TLS/REALITY).",
            "  Plain HTTP/WebSocket is trivially detectable and blockable.",
            "  Upgrade to TLS or REALITY before production use.",
            "  See Security Report and Best Config tabs for prioritized fixes.",
            "",
        ])

    if r.setup_guide and r.setup_guide.summary:
        lines.extend([
            "APPENDIX — Data-driven setup guide summary",
            "─" * 64,
            r.setup_guide.summary.strip(),
            "",
        ])

    return "\n".join(lines)


def _recommend_panels(c: ParsedConfig) -> list[str]:
    panels: list[str] = []
    if c.protocol in (ProtocolType.VLESS, ProtocolType.VMESS, ProtocolType.TROJAN, ProtocolType.SHADOWSOCKS):
        panels.append("3x-ui (MHSanaei) — visual inbound management")
        panels.append("Marzban — subscription-based reselling")
    if c.protocol == ProtocolType.HYSTERIA2:
        panels.append("sing-box / hysteria2 standalone")
    if c.protocol == ProtocolType.TUIC:
        panels.append("Marzban / sing-box — TUIC inbound")
    if c.protocol == ProtocolType.WIREGUARD:
        panels.append("wg-easy / native WireGuard")
    if c.protocol == ProtocolType.OPENVPN:
        panels.append("OpenVPN Access Server")
    if not panels:
        panels.append("Manual Xray-core configuration")
    return panels


def _build_order(
    r: AnalysisResult,
    primary: Optional[RankedScenario],
    exit_intel: Optional[ExitIntelSnapshot],
) -> list[str]:
    """Step-by-step build order for operator replicating the setup."""
    c = r.config
    d = r.deployment
    host = _front_host(c, r.dns.hostname)
    transport = _effective_transport(c)
    origin = _origin_country_hint(r, exit_intel)
    steps: list[str] = []

    steps.append("Step 1 — Choose your topology")
    if primary:
        steps.append(f"  Target scenario: {primary.name} ({_pct(primary.confidence)})")
    if d.cdn_type:
        steps.append(f"  CDN provider: {d.cdn_type}")
    else:
        steps.append("  Direct VPS (no CDN)")

    steps.append("")
    steps.append("Step 2 — Provision server(s)")
    if d.cdn_type:
        if origin:
            steps.append(f"  • Origin VPS in {origin} (inferred from live exit IP)")
        else:
            steps.append("  • Origin VPS — country TBD (run live test first)")
        steps.append(f"  • CDN account ({d.cdn_type}) — domain fronting layer")
    else:
        steps.append(f"  • VPS with public IP — open TCP {c.port}")
        if c.protocol in (ProtocolType.HYSTERIA2, ProtocolType.TUIC) or transport == TransportType.QUIC:
            steps.append(f"  • Also open UDP {c.port}")

    steps.append("")
    steps.append("Step 3 — Install and configure Xray inbound")
    steps.append(f"  • Protocol: {c.protocol.value} | Transport: {transport.value} | Port: {c.port}")
    if c.uuid:
        steps.append(f"  • Client UUID: {c.uuid}")
    if c.path and transport == TransportType.WS:
        steps.append(f"  • WebSocket path: {c.path}")
    if c.service_name and transport == TransportType.GRPC:
        steps.append(f"  • gRPC serviceName: {c.service_name}")
    if c.reality:
        steps.append(f"  • REALITY SNI: {c.sni or 'required'}")
        steps.append(f"  • Public key in link: {'yes' if c.public_key else 'missing'}")

    if transport in (TransportType.WS, TransportType.GRPC, TransportType.XHTTP, TransportType.HTTPUPGRADE):
        steps.append("")
        steps.append("Step 4 — Reverse proxy (Nginx/Caddy)")
        if c.tls:
            steps.append(f"  • Terminate TLS on :{c.port}, forward {transport.value} to 127.0.0.1:<xray_port>")
        else:
            steps.append(f"  • Plain HTTP on :{c.port} — forward {transport.value} to 127.0.0.1:<xray_port>")
            steps.append("  • No TLS on this link — consider upgrading before production")
        steps.append(f"  • Host header: {c.host or host}")

    if d.cdn_type:
        steps.append("")
        steps.append(f"Step 5 — CDN configuration ({d.cdn_type})")
        steps.append(f"  • Add domain {host} → origin VPS IP")
        steps.append("  • Enable CDN/proxy mode")
        steps.append("  • Pass WebSocket/gRPC; disable caching on tunnel paths")

    steps.append("")
    steps.append("Step 6 — DNS & verification")
    steps.append(f"  • Client link address: {c.address}:{c.port}")
    if d.cdn_type:
        steps.append("  • External DNS must show CDN edge IPs (not origin)")
    steps.append("  • Run Xray live test — confirm exit IP/country matches expected origin")

    steps.append("")
    steps.append("Step 7 — Distribute client config")
    steps.append("  • Export share link with exact UUID/path/SNI/Host matching server")
    if not c.tls and not c.reality:
        steps.append("  • ⚠ Upgrade to TLS/REALITY before wide distribution (Iran DPI risk)")

    return steps
