"""Detect and explain common tunnel / deployment topologies from analysis data."""

from __future__ import annotations

import json
import re
from typing import Optional

from backend.models import (
    ConnectivityResult,
    DeploymentAnalysis,
    DNSAnalysis,
    IPIntelligence,
    ParsedConfig,
    ProtocolType,
    TracerouteResult,
    TransportType,
    TunnelAnalysis,
    TunnelRoute,
    TunnelTypeMatch,
)
from utils.helpers import is_ip_address

# ── Tunnel catalog: what each tunnel IS (static education) ──────────────────

TUNNEL_CATALOG: dict[str, dict[str, str]] = {
    "direct_vps": {
        "name": "Direct VPS Connection",
        "flow": "Client → server IP/domain → Xray inbound",
        "explain": "Traffic goes directly to the server IP or a domain that resolves to the origin; no CDN or relay.",
    },
    "cdn_fronting": {
        "name": "CDN Fronting",
        "flow": "Client → CDN edge → origin (Xray behind CDN)",
        "explain": "The client connects to a CDN IP/domain; the CDN forwards requests to the origin VPS. The real server IP stays hidden.",
    },
    "cloudflare_cdn": {
        "name": "Cloudflare CDN Fronting",
        "flow": "Client → Cloudflare edge (104.x / 188.x) → origin VPS",
        "explain": "Domain on Cloudflare with orange proxy enabled; TLS between client and CF, then CF to origin.",
    },
    "arvan_cdn": {
        "name": "Arvan CDN Fronting",
        "flow": "Client → Arvan edge → origin VPS",
        "explain": "Arvan CDN in front of the server; DNS and SSL managed in the Arvan panel.",
    },
    "akamai_cdn": {
        "name": "Akamai CDN Fronting",
        "flow": "Client → Akamai edge → origin",
        "explain": "IP/ASN belongs to Akamai — enterprise CDN fronting.",
    },
    "fastly_cdn": {
        "name": "Fastly CDN Fronting",
        "flow": "Client → Fastly edge → origin",
        "explain": "Fastly IP/ASN seen in DNS resolution.",
    },
    "cloudfront_cdn": {
        "name": "AWS CloudFront Fronting",
        "flow": "Client → CloudFront → origin",
        "explain": "AWS CloudFront IP/ASN.",
    },
    "bunny_cdn": {
        "name": "BunnyCDN Fronting",
        "flow": "Client → Bunny edge → origin",
        "explain": "Bunny.net IP/ASN.",
    },
    "gcore_cdn": {
        "name": "Gcore CDN Fronting",
        "flow": "Client → Gcore edge → origin",
        "explain": "Gcore IP/ASN.",
    },
    "cloudflare_tunnel": {
        "name": "Cloudflare Tunnel (cloudflared)",
        "flow": "Client → Cloudflare → cloudflared agent → localhost Xray",
        "explain": "No inbound port open on the VPS; the cloudflared agent creates an outbound tunnel to Cloudflare.",
    },
    "reverse_proxy": {
        "name": "Reverse Proxy (Nginx/Caddy/HAProxy)",
        "flow": "Client → :443 Nginx → localhost:Xray",
        "explain": "Nginx/Caddy TLS termination or pass-through; forwards WebSocket/gRPC/XHTTP to Xray.",
    },
    "reverse_tunnel_frp": {
        "name": "Reverse Tunnel (frp/nps/ngrok)",
        "flow": "Client → VPS relay (public) ← agent behind NAT → local Xray",
        "explain": "The Xray server is behind NAT; frpc/npc connects to a relay VPS and publishes a relay port.",
    },
    "sni_fronting": {
        "name": "SNI / IP Fronting",
        "flow": "Client → IP/CDN with a different SNI domain",
        "explain": "Connection address differs from SNI/Host — the client hits a Cloudflare IP but SNI is the real subdomain.",
    },
    "host_sni_split": {
        "name": "Host ≠ SNI (Domain Fronting)",
        "flow": "TLS SNI is one domain, HTTP Host/header is another",
        "explain": "Split SNI and Host to bypass filtering or CDN rules.",
    },
    "xhttp_split": {
        "name": "XHTTP Split (separate upload/downlink)",
        "flow": "Upload on one path/connection — download on a separate path or CDN",
        "explain": "XHTTP packet-up/stream-up with downloadSettings; uplink and downlink may come from different edges.",
    },
    "reality_camouflage": {
        "name": "REALITY Camouflage Tunnel",
        "flow": "Client → REALITY handshake mimicking a real site → Xray",
        "explain": "No real cert on the server; handshake mimics visiting the destination site (e.g. google.com).",
    },
    "multi_hop": {
        "name": "Multi-hop / Relay Chain",
        "flow": "Client → Relay1 → Relay2 → origin",
        "explain": "Multiple relay layers; not visible in a single-node link but traceroute/remark may hint at it.",
    },
    "wireguard_tunnel": {
        "name": "WireGuard VPN Tunnel",
        "flow": "Client → WG UDP → server → routing",
        "explain": "Layer-3 WireGuard tunnel; Xray may run behind WG or separately.",
    },
    "openvpn_tunnel": {
        "name": "OpenVPN Tunnel",
        "flow": "Client → OpenVPN TCP/UDP → server",
        "explain": "Classic OpenVPN tunnel.",
    },
    "hysteria2_quic": {
        "name": "Hysteria2 (QUIC/UDP)",
        "flow": "Client → QUIC UDP → Hy2 server",
        "explain": "QUIC-based protocol with obfuscation; UDP must be open.",
    },
    "tuic_quic": {
        "name": "TUIC (QUIC)",
        "flow": "Client → QUIC → TUIC server",
        "explain": "TUIC protocol over QUIC.",
    },
    "load_balancer": {
        "name": "Load Balancer / Multi-IP",
        "flow": "Client → LB → one of several backends",
        "explain": "Multiple A records or CDN edges; traffic is distributed.",
    },
    "ssh_tunnel": {
        "name": "SSH Tunnel (Port Forward)",
        "flow": "Client → SSH -L/-R → local Xray",
        "explain": "Port forwarding via SSH; usually for testing or temporary setup.",
    },
    "gost_relay": {
        "name": "GOST / Relay Chain",
        "flow": "Client → GOST relay → Xray",
        "explain": "Multi-layer relay using GOST or similar tools.",
    },
}


def _effective_transport(config: ParsedConfig) -> TransportType:
    if config.transport_type != TransportType.UNKNOWN:
        return config.transport_type
    raw = str(config.extra.get("type") or config.extra.get("net") or "").lower()
    mapping = {
        "tcp": TransportType.TCP, "ws": TransportType.WS, "grpc": TransportType.GRPC,
        "httpupgrade": TransportType.HTTPUPGRADE, "http": TransportType.HTTPUPGRADE,
        "xhttp": TransportType.XHTTP, "splithttp": TransportType.XHTTP, "quic": TransportType.QUIC,
    }
    return mapping.get(raw, TransportType.UNKNOWN)


def _remark_lower(config: ParsedConfig) -> str:
    return (config.remark or "").lower()


def _has_download_settings(config: ParsedConfig) -> bool:
    if re.search(r"\bdl[=:]", _remark_lower(config)):
        return True
    extra = config.extra.get("downloadSettings") or config.extra.get("download")
    return bool(extra)


def _match(
    key: str,
    confidence: float,
    evidence: list[str],
    setup_steps: list[str],
) -> TunnelTypeMatch:
    cat = TUNNEL_CATALOG[key]
    return TunnelTypeMatch(
        tunnel_id=key,
        name=cat["name"],
        category=_category_for(key),
        confidence=round(confidence, 2),
        evidence=evidence,
        traffic_flow=cat["flow"],
        description=cat["explain"],
        setup_steps=setup_steps,
    )


def _category_for(key: str) -> str:
    if "cdn" in key or key == "cdn_fronting":
        return "cdn"
    if key in ("reverse_proxy",):
        return "reverse_proxy"
    if key in ("reverse_tunnel_frp", "ssh_tunnel", "gost_relay", "cloudflare_tunnel"):
        return "tunnel_agent"
    if key in ("reality_camouflage",):
        return "camouflage"
    if key in ("wireguard_tunnel", "openvpn_tunnel", "hysteria2_quic", "tuic_quic"):
        return "protocol_tunnel"
    if key in ("multi_hop", "load_balancer"):
        return "chain"
    if key in ("sni_fronting", "host_sni_split", "xhttp_split"):
        return "fronting"
    return "direct"


def _cdn_setup_steps(cdn_name: str, config: ParsedConfig, dns: DNSAnalysis) -> list[str]:
    host = dns.hostname or config.sni or config.host
    steps = []
    if host:
        steps.append(f"DNS: {host} → origin IP + CDN {cdn_name} enabled.")
    if config.path:
        steps.append(f"inbound path = {config.path}")
    if config.sni or config.host:
        steps.append(f"SNI/Host = {config.sni or config.host}")
    return steps


def analyze_tunnels(
    config: ParsedConfig,
    dns: DNSAnalysis,
    network: list[IPIntelligence],
    connectivity: ConnectivityResult,
    deployment: DeploymentAnalysis,
    traceroute: TracerouteResult,
    tunnel: TunnelRoute,
) -> TunnelAnalysis:
    """Detect all applicable tunnel types with evidence from analysis."""
    matches: list[TunnelTypeMatch] = []
    c = config
    transport = _effective_transport(c)
    remark = _remark_lower(c)
    cdn_ips = [ip for ip in network if ip.cdn_detected]
    primary_cdn = deployment.cdn_type

    # ── Protocol-native tunnels ──
    if c.protocol == ProtocolType.WIREGUARD:
        matches.append(_match("wireguard_tunnel", 0.95, [
            f"protocol={c.protocol.value}", f"endpoint={c.address}:{c.port}",
        ], [f"Endpoint {c.address}:{c.port} — keys from link conf file."]))

    if c.protocol == ProtocolType.OPENVPN:
        matches.append(_match("openvpn_tunnel", 0.95, [
            f"protocol={c.protocol.value}", f"server={c.address}:{c.port}",
        ], [f"Server {c.address}:{c.port} — .ovpn profile."]))

    if c.protocol == ProtocolType.HYSTERIA2:
        matches.append(_match("hysteria2_quic", 0.95, [
            f"protocol={c.protocol.value}", f"port={c.port}",
        ] + ([f"sni={c.sni}"] if c.sni else []),
        [f"Hy2 port {c.port}", "UDP open"] + ([f"SNI {c.sni}"] if c.sni else [])))

    if c.protocol == ProtocolType.TUIC:
        matches.append(_match("tuic_quic", 0.95, [
            f"protocol={c.protocol.value}", f"port={c.port}",
        ], [f"TUIC port {c.port}"] + ([f"SNI {c.sni}"] if c.sni else [])))

    # ── REALITY ──
    if c.reality:
        ev = ["security=reality"] + ([f"sni={c.sni}"] if c.sni else [])
        if c.public_key:
            ev.append("pbk present")
        steps = [f"REALITY inbound — SNI {c.sni or '—'}"]
        if c.public_key:
            steps.append(f"Public Key: {c.public_key}")
        if transport == TransportType.XHTTP:
            steps.append("XHTTP + REALITY → stream-one")
        matches.append(_match("reality_camouflage", 0.92, ev, steps))

    # ── CDN types (from network intelligence) ──
    detected_cdns: set[str] = set()
    for ip in network:
        if ip.cdn_detected and ip.cdn_confidence >= 0.55:
            detected_cdns.add(ip.cdn_detected)

    if cdn_ips or primary_cdn or detected_cdns:
        cdn_conf = 0.55
        if cdn_ips:
            cdn_conf = min(0.95, max(ip.cdn_confidence for ip in cdn_ips) + 0.05)
        ev = [f"cdn_type={primary_cdn or '—'}"]
        if deployment.cdn_backend_ips:
            ev.append(f"cdn_ips={', '.join(deployment.cdn_backend_ips[:4])}")
        if is_ip_address(c.address) and c.sni:
            ev.append(f"link_ip={c.address} + sni={c.sni}")
        matches.append(_match("cdn_fronting", cdn_conf, ev,
            _cdn_setup_steps(primary_cdn or "CDN", c, dns)))

    cdn_key_map = {
        "Cloudflare": "cloudflare_cdn",
        "ArvanCloud": "arvan_cdn",
        "Akamai": "akamai_cdn",
        "Fastly": "fastly_cdn",
        "CloudFront": "cloudfront_cdn",
        "Bunny": "bunny_cdn",
        "Gcore": "gcore_cdn",
    }
    for cdn_name in detected_cdns:
        key = cdn_key_map.get(cdn_name)
        if key:
            ips = [ip.ip for ip in network if ip.cdn_detected == cdn_name]
            asn = next((ip.asn for ip in network if ip.cdn_detected == cdn_name and ip.asn), None)
            ev = [f"cdn={cdn_name}"] + ([f"ips={', '.join(ips[:3])}"] if ips else [])
            if asn:
                ev.append(f"asn={asn}")
            conf = max((ip.cdn_confidence for ip in network if ip.cdn_detected == cdn_name), default=0.7)
            matches.append(_match(key, min(0.98, conf + 0.05), ev,
                _cdn_setup_steps(cdn_name, c, dns)))

    # ── Cloudflare Tunnel (cloudflared) ──
    cf_tunnel_cnames = [r for r in dns.cname_records if "cfargotunnel.com" in r.lower()]
    if cf_tunnel_cnames:
        matches.append(_match("cloudflare_tunnel", 0.88, [
            f"CNAME={cf_tunnel_cnames[0]}",
        ], [
            f"Zero Trust Public Hostname: {c.sni or dns.hostname or '—'}",
            f"cloudflared → localhost:{c.port}",
        ] + ([f"path={c.path}"] if c.path else [])))

    # ── Direct VPS ──
    if not cdn_ips and not primary_cdn:
        vps_conf = 0.45
        ev = []
        if is_ip_address(c.address):
            vps_conf = 0.75
            ev.append(f"direct_ip={c.address}")
        net = network[0] if network else None
        if net and net.is_datacenter:
            vps_conf = max(vps_conf, 0.70)
            ev.append(f"datacenter={net.organization or net.isp}")
        if not is_ip_address(c.address) and dns.a_records and not cdn_ips:
            vps_conf = max(vps_conf, 0.60)
            ev.append(f"dns_a={dns.a_records[0]}")
        if vps_conf >= 0.45:
            steps = [f"Xray inbound on {c.address}:{c.port}"]
            if net:
                steps.append(f"ISP: {net.organization or net.isp} ({net.asn or '—'})")
            matches.append(_match("direct_vps", vps_conf, ev, steps))

    # ── Reverse Proxy ──
    rp_conf = next((g.confidence for g in deployment.guesses if g.name == "Reverse Proxy"), 0.0)
    if transport in (TransportType.WS, TransportType.XHTTP, TransportType.GRPC, TransportType.HTTPUPGRADE):
        rp_conf = max(rp_conf, 0.50)
    if connectivity.http_response.value == "Valid":
        rp_conf = max(rp_conf, 0.65)
    if rp_conf >= 0.45:
        ev = [f"transport={transport.value}", f"rp_heuristic={int(rp_conf * 100)}%"]
        if connectivity.http_response.value != "Pending":
            ev.append(f"http_test={connectivity.http_response.value}")
        host = c.sni or c.host or dns.hostname
        steps = [f"Nginx/Caddy on {host or c.address}:{c.port}"]
        if c.path and transport == TransportType.WS:
            steps.append(f"location {c.path} → proxy_pass localhost")
        elif c.path and transport == TransportType.XHTTP:
            steps.append(f"XHTTP path {c.path} → grpc_pass/proxy_pass")
        matches.append(_match("reverse_proxy", rp_conf, ev, steps))

    # ── Reverse tunnel (frp/nps) — remark or weak signals ──
    frp_hints = [w for w in ("frp", "nps", "ngrok", "bore", "rathole", "nat") if w in remark]
    frp_conf = 0.25
    if frp_hints:
        frp_conf = 0.72
    elif c.port not in (443, 8443, 2053, 2083, 80, 8080, 8880) and not cdn_ips:
        frp_conf = 0.38
    if frp_conf >= 0.35:
        ev = ([f"remark_hint={frp_hints[0]}"] if frp_hints else [f"nonstandard_port={c.port}"])
        matches.append(_match("reverse_tunnel_frp", frp_conf, ev, [
            f"Relay VPS: {c.address}:{c.port}",
            "frpc/npc local → publish to relay",
        ]))

    # ── SNI / IP fronting ──
    if is_ip_address(c.address) and c.sni and c.sni != c.address:
        ev = [f"connect_ip={c.address}", f"sni={c.sni}"]
        if dns.a_records:
            ev.append(f"dns_resolve={dns.a_records[0]}")
        matches.append(_match("sni_fronting", 0.85, ev, [
            f"Client IP {c.address} + SNI {c.sni}",
            "inbound must accept this SNI",
        ]))

    if c.host and c.sni and c.host != c.sni:
        matches.append(_match("host_sni_split", 0.80, [
            f"host={c.host}", f"sni={c.sni}",
        ], [
            f"TLS SNI: {c.sni}",
            f"HTTP Host/header: {c.host}",
        ]))

    # ── XHTTP split ──
    if transport == TransportType.XHTTP and (_has_download_settings(c) or "dl=" in remark or "dl:" in remark):
        ev = ["transport=XHTTP", "downloadSettings/remark dl hint"]
        if c.alpn:
            ev.append(f"alpn={c.alpn}")
        steps = [f"XHTTP path {c.path or '—'}"]
        if c.alpn:
            steps.append(f"ALPN uplink: {c.alpn}")
        dl_hint = re.search(r"dl[=:](\S+)", remark)
        if dl_hint:
            steps.append(f"Download ALPN/path (remark): {dl_hint.group(1)}")
        matches.append(_match("xhttp_split", 0.78, ev, steps))

    # ── Multi-hop ──
    mh_conf = 0.15
    ev = []
    if traceroute.hop_count and traceroute.hop_count >= 14:
        mh_conf = 0.42
        ev.append(f"traceroute_hops={traceroute.hop_count}")
    if any(w in remark for w in ("relay", "chain", "multi", "hop", "warp")):
        mh_conf = max(mh_conf, 0.55)
        ev.append("remark relay/chain hint")
    if mh_conf >= 0.35:
        matches.append(_match("multi_hop", mh_conf, ev, [
            "Multiple VPS relays in series",
            f"Current link endpoint={c.address}:{c.port}",
        ]))

    # ── Load balancer / multi-A ──
    if len(dns.a_records) >= 2:
        unique_asn = {ip.asn for ip in network if ip.asn}
        matches.append(_match("load_balancer", 0.55, [
            f"dns_a_count={len(dns.a_records)}",
            f"a_records={', '.join(dns.a_records[:4])}",
        ] + ([f"asns={', '.join(sorted(unique_asn))}"] if unique_asn else []),
        [f"Multiple IPs: {', '.join(dns.a_records[:3])}", "health-check or CDN LB"]))

    # ── SSH / GOST from remark ──
    if "ssh" in remark or c.port == 22:
        matches.append(_match("ssh_tunnel", 0.50, [f"port={c.port}"], ["SSH -L/-R forward"]))
    if "gost" in remark:
        matches.append(_match("gost_relay", 0.65, ["remark gost"], ["GOST relay chain"]))

    # Sort by confidence, dedupe by tunnel_id (keep highest)
    by_id: dict[str, TunnelTypeMatch] = {}
    for m in matches:
        if m.tunnel_id not in by_id or m.confidence > by_id[m.tunnel_id].confidence:
            by_id[m.tunnel_id] = m
    sorted_matches = sorted(by_id.values(), key=lambda x: x.confidence, reverse=True)

    # Build traffic flow from analysis
    if tunnel.route_display:
        traffic_flow = tunnel.route_display
        if deployment.cdn_type:
            traffic_flow += f" → CDN {deployment.cdn_type}"
        traffic_flow += f" → Xray :{c.port}"
    else:
        flow_parts = ["Client"]
        if primary_cdn or (cdn_ips and cdn_ips[0].cdn_detected):
            cdn_label = primary_cdn or cdn_ips[0].cdn_detected
            edge_ip = deployment.cdn_backend_ips[0] if deployment.cdn_backend_ips else (cdn_ips[0].ip if cdn_ips else c.address)
            flow_parts.append(f"{cdn_label} ({edge_ip})")
        elif network:
            flow_parts.append(f"{network[0].ip}")
        else:
            flow_parts.append(c.address)
        flow_parts.append(f"Xray :{c.port}")
        traffic_flow = " → ".join(flow_parts)

    primary = sorted_matches[0] if sorted_matches else None
    return TunnelAnalysis(
        primary_type=primary.name if primary else "Unknown",
        primary_tunnel_id=primary.tunnel_id if primary else "",
        primary_confidence=primary.confidence if primary else 0.0,
        traffic_flow=traffic_flow,
        detected_types=sorted_matches,
    )
