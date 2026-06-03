"""Data-driven server setup guide — every line derived from analysis results."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from backend.models import (
    ConnectivityResult,
    DeploymentAnalysis,
    DeploymentSetupGuide,
    DNSAnalysis,
    IPIntelligence,
    ParsedConfig,
    ProtocolType,
    SetupGuideSection,
    TLSAnalysis,
    TracerouteResult,
    TransportType,
    TunnelAnalysis,
    TunnelRoute,
    XrayTestResult,
)
from utils.helpers import is_ip_address


@dataclass
class GuideContext:
    config: ParsedConfig
    deployment: DeploymentAnalysis
    tls: TLSAnalysis
    dns: DNSAnalysis
    network: list[IPIntelligence]
    connectivity: ConnectivityResult
    tunnel: TunnelRoute
    traceroute: TracerouteResult
    xray_test: Optional[XrayTestResult] = None
    tunnel_analysis: Optional[TunnelAnalysis] = None


def _effective_transport(config: ParsedConfig) -> TransportType:
    if config.transport_type != TransportType.UNKNOWN:
        return config.transport_type
    raw = str(config.extra.get("type") or config.extra.get("net") or "").lower()
    mapping = {
        "tcp": TransportType.TCP,
        "ws": TransportType.WS,
        "websocket": TransportType.WS,
        "grpc": TransportType.GRPC,
        "httpupgrade": TransportType.HTTPUPGRADE,
        "http": TransportType.HTTPUPGRADE,
        "xhttp": TransportType.XHTTP,
        "splithttp": TransportType.XHTTP,
        "quic": TransportType.QUIC,
    }
    return mapping.get(raw, TransportType.UNKNOWN)


def _parse_xhttp_extra(config: ParsedConfig) -> dict[str, Any]:
    raw = config.extra.get("extra")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}
    return {}


def _fmt_list(items: list[str], limit: int = 6) -> str:
    if not items:
        return ""
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def _primary_guess(ctx: GuideContext) -> tuple[str, float, str]:
    if not ctx.deployment.guesses:
        return "Unknown", 0.0, ""
    top = ctx.deployment.guesses[0]
    return top.name, top.confidence, top.description


def _top_network(ctx: GuideContext) -> Optional[IPIntelligence]:
    return ctx.network[0] if ctx.network else None


def _build_infrastructure_facts(ctx: GuideContext) -> list[str]:
    c, d, t, dns, conn = ctx.config, ctx.deployment, ctx.tls, ctx.dns, ctx.connectivity
    facts: list[str] = []
    transport = _effective_transport(c)

    facts.append(f"Protocol: {c.protocol.value} | Transport: {transport.value} | Link port: {c.port}")
    if c.remark:
        facts.append(f"Config remark: {c.remark}")

    facts.append(f"Link address: {c.address}" + (" (IP)" if is_ip_address(c.address) else " (domain)"))

    if dns.hostname:
        facts.append(f"DNS resolve for {dns.hostname}:")
        if dns.a_records:
            facts.append(f"  A: {_fmt_list(dns.a_records)}")
        if dns.aaaa_records:
            facts.append(f"  AAAA: {_fmt_list(dns.aaaa_records)}")
        if dns.cname_records:
            facts.append(f"  CNAME: {_fmt_list(dns.cname_records)}")
        if dns.ttl is not None:
            facts.append(f"  TTL: {dns.ttl}s")

    if d.cdn_type:
        facts.append(f"Detected CDN: {d.cdn_type}")
        if d.cdn_backend_ips:
            facts.append(f"  CDN IPs (from DNS): {_fmt_list(d.cdn_backend_ips)}")
    if d.real_server_ip:
        facts.append(f"Link IP (real_server_ip): {d.real_server_ip}")

    net = _top_network(ctx)
    if net:
        loc = f"{net.city}, {net.country}" if net.city and net.country else (net.country or "")
        facts.append(
            f"IP infrastructure {net.ip}: {net.organization or net.isp or '—'}"
            + (f" | {net.asn}" if net.asn else "")
            + (f" | {loc}" if loc else "")
            + (" | datacenter" if net.is_datacenter else "")
        )

    if ctx.tunnel.route_display:
        facts.append(f"Tunnel route: {ctx.tunnel.route_display}")

    if conn.tcp_connect.value != "Pending":
        facts.append(
            f"TCP {c.address}:{c.port} → {conn.tcp_connect.value}"
            + (f" ({conn.tcp_latency_ms}ms)" if conn.tcp_latency_ms else "")
        )
    if t.enabled:
        facts.append(
            f"TLS {t.version or '—'} | cipher {t.cipher_suite or '—'}"
            + (f" | SNI {t.sni_used}" if t.sni_used else "")
        )
        if t.certificate_subject:
            facts.append(f"  Certificate: {t.certificate_subject} | Issuer: {t.certificate_issuer or '—'}")
        if t.days_until_expiry is not None:
            facts.append(f"  Expires in: {t.days_until_expiry} days")

    scenario, conf, _ = _primary_guess(ctx)
    facts.append(f"Deploy scenario (heuristic): {scenario} — confidence {int(conf * 100)}%")

    if ctx.traceroute.hop_count:
        facts.append(f"Traceroute hop count: {ctx.traceroute.hop_count}")

    xt = ctx.xray_test
    if xt and xt.proxy_test.value not in ("Pending", "Skipped"):
        facts.append(f"Real proxy test: {xt.proxy_test.value}" + (f" — {xt.summary}" if xt.summary else ""))
        if xt.exit_ip:
            facts.append(f"  Tunnel exit IP: {xt.exit_ip} ({xt.exit_country or '?'})")

    return facts


def _build_summary(ctx: GuideContext) -> str:
    c = ctx.config
    transport = _effective_transport(c)
    scenario, conf, desc = _primary_guess(ctx)
    sec = "REALITY" if c.reality else ("TLS" if c.tls else "No TLS/Reality")

    parts = [
        f"Based on analysis, this node matches scenario «{scenario}» (confidence {int(conf * 100)}%).",
        f"Profile: {c.protocol.value} + {transport.value} + {sec} on port {c.port}.",
    ]
    if desc:
        parts.append(desc)
    if ctx.deployment.cdn_type:
        parts.append(f"CDN active: {ctx.deployment.cdn_type}.")
    if is_ip_address(c.address) and c.sni and c.sni != c.address:
        parts.append(
            f"Client connects to IP {c.address} but SNI/Host is «{c.sni}» — "
            "server inbound must be configured with the same SNI/Host."
        )
    return " ".join(parts)


def _recommend_panels(ctx: GuideContext) -> list[str]:
    p = ctx.config.protocol
    panels: list[str] = []
    if p in (ProtocolType.VLESS, ProtocolType.VMESS, ProtocolType.TROJAN, ProtocolType.SHADOWSOCKS):
        panels.append("3x-ui (MHSanaei) — inbound with same protocol + transport")
        panels.append("Marzban — suitable for subscription reselling")
    if p == ProtocolType.HYSTERIA2:
        panels.append("3x-ui (Hysteria2 inbound) or sing-box / hysteria2 standalone")
    if p == ProtocolType.TUIC:
        panels.append("Marzban / sing-box — TUIC inbound")
    if p == ProtocolType.WIREGUARD:
        panels.append("WireGuard native (wg-easy / MikroTik / Linux wg-quick)")
    if p == ProtocolType.OPENVPN:
        panels.append("OpenVPN Access Server or ovpn profile on VPS")
    if not panels:
        panels.append("Manual Xray-core — protocol in link not fully supported")
    return panels


def _auth_steps(ctx: GuideContext) -> list[str]:
    c = ctx.config
    steps: list[str] = []
    if c.protocol in (ProtocolType.VLESS, ProtocolType.VMESS):
        if c.uuid:
            steps.append(f"UUID/ID: {c.uuid}")
        else:
            steps.append("UUID not in link — obtain from server panel or provider.")
        if c.flow:
            steps.append(f"Flow: {c.flow}")
        if c.protocol == ProtocolType.VMESS and c.encryption:
            steps.append(f"VMess security/encryption: {c.encryption}")
    elif c.protocol == ProtocolType.TROJAN:
        if c.password:
            steps.append("Password: (present in link — use same value in panel)")
        else:
            steps.append("Password not in link.")
    elif c.protocol == ProtocolType.SHADOWSOCKS:
        if c.encryption:
            steps.append(f"Method: {c.encryption}")
        if c.password:
            steps.append("Password: present in link")
    elif c.protocol == ProtocolType.HYSTERIA2:
        if c.password:
            steps.append("Hy2 auth password: present in link")
        if c.sni:
            steps.append(f"SNI: {c.sni}")
    elif c.protocol == ProtocolType.TUIC:
        if c.uuid:
            steps.append(f"UUID: {c.uuid}")
        if c.password:
            steps.append("Token/password: present in link")
    return steps


def _transport_steps(ctx: GuideContext) -> list[str]:
    c = ctx.config
    t = _effective_transport(c)
    steps: list[str] = []

    if t == TransportType.UNKNOWN:
        steps.append(
            "Transport not identified in parse. Link type/network param: "
            f"{c.extra.get('type') or c.extra.get('net') or '—'}"
        )
        return steps

    steps.append(f"Network/Transmission: {t.value}")

    if t == TransportType.XHTTP:
        if c.path:
            steps.append(f"Path: {c.path}")
        if c.host:
            steps.append(f"Host: {c.host}")
        elif c.sni:
            steps.append(f"Host (from SNI): {c.sni}")
        mode = c.extra.get("mode")
        if mode:
            steps.append(f"Mode: {mode}")
        else:
            if c.reality:
                steps.append("Predicted Xray mode: stream-one (REALITY + XHTTP)")
            elif c.tls and c.alpn and "h2" in c.alpn.replace(" ", ""):
                steps.append("Predicted Xray mode: stream-up (TLS + ALPN h2)")
            else:
                steps.append("Predicted Xray mode: auto (packet-up or stream-up)")
        nested = _parse_xhttp_extra(c)
        headers = nested.get("headers") if isinstance(nested.get("headers"), dict) else None
        if headers:
            for hk, hv in headers.items():
                steps.append(f"Extra XHTTP header: {hk}: {hv}")
    elif t == TransportType.WS:
        if c.path:
            steps.append(f"WS Path: {c.path}")
        host = c.host or c.sni
        if host:
            steps.append(f"Host header: {host}")
    elif t == TransportType.GRPC:
        if c.service_name:
            steps.append(f"gRPC serviceName: {c.service_name}")
        else:
            steps.append("serviceName not in link — get from server inbound settings.")
    elif t == TransportType.HTTPUPGRADE:
        if c.path:
            steps.append(f"Path: {c.path}")
        if c.host or c.sni:
            steps.append(f"Host: {c.host or c.sni}")
    elif t == TransportType.QUIC:
        if c.sni:
            steps.append(f"QUIC SNI: {c.sni}")

    return steps


def _security_steps(ctx: GuideContext) -> list[str]:
    c, t = ctx.config, ctx.tls
    steps: list[str] = []

    if c.reality:
        steps.append("Security: REALITY")
        if c.sni:
            steps.append(f"Server Name / Dest (SNI): {c.sni}")
        if c.public_key:
            steps.append(f"Public Key (pbk): {c.public_key}")
        else:
            steps.append("Public Key not in link — generate on server with xray x25519.")
        if c.short_id is not None and c.short_id != "":
            steps.append(f"Short ID: {c.short_id}")
        if c.fingerprint:
            steps.append(f"Fingerprint: {c.fingerprint}")
    elif c.tls:
        steps.append("Security: TLS")
        sni = c.sni or c.host
        if sni:
            steps.append(f"SNI: {sni}")
        if c.alpn:
            steps.append(f"ALPN: {c.alpn}")
        if c.fingerprint:
            steps.append(f"uTLS fingerprint: {c.fingerprint}")
        steps.append(f"allowInsecure in link: {'yes' if c.allow_insecure else 'no'}")
        if t.enabled:
            if t.certificate_subject:
                steps.append(f"Current server cert (from handshake): {t.certificate_subject}")
            if t.certificate_issuer:
                steps.append(f"Issuer: {t.certificate_issuer}")
            if t.days_until_expiry is not None:
                steps.append(f"Cert validity: {t.days_until_expiry} days")
            if t.fingerprint_sha256:
                steps.append(f"SHA256 cert: {t.fingerprint_sha256}")
    else:
        steps.append("Security: none — TLS/Reality not enabled in link.")

    return steps


def _panel_3xui(ctx: GuideContext) -> list[str]:
    c = ctx.config
    steps = [
        "Inbounds → Add Inbound (or edit inbound with same UUID/path)",
        f"Protocol: {c.protocol.value}",
        f"Listen Port: {c.port}",
    ]
    steps.extend(_auth_steps(ctx))
    steps.extend(_transport_steps(ctx))
    steps.extend(_security_steps(ctx))
    steps.append("Save → Restart Xray")
    if c.raw_url:
        steps.append("Compare panel Client Link with raw_url from this analysis.")
    return steps


def _panel_marzban(ctx: GuideContext) -> list[str]:
    c = ctx.config
    if c.protocol not in (ProtocolType.VLESS, ProtocolType.VMESS, ProtocolType.TROJAN,
                          ProtocolType.SHADOWSOCKS, ProtocolType.HYSTERIA2, ProtocolType.TUIC):
        return []
    steps = [
        f"Marzban — {c.protocol.value} on port {c.port}",
    ]
    steps.extend(_auth_steps(ctx))
    steps.extend(_transport_steps(ctx))
    steps.extend(_security_steps(ctx))
    steps.append("New user → subscription link or share link")
    return steps


def _manual_xray(ctx: GuideContext) -> list[str]:
    c = ctx.config
    if c.protocol in (ProtocolType.WIREGUARD, ProtocolType.OPENVPN):
        return [
            f"Protocol {c.protocol.value} is not implemented with Xray-core.",
            "Use the protocol-specific scenario section in the guide above.",
        ]
    if c.protocol in (ProtocolType.HYSTERIA2, ProtocolType.TUIC):
        steps = [
            f"{c.protocol.value} — prefer sing-box or dedicated daemon (not classic Xray inbound).",
            f"Listen Port: {c.port}",
        ]
        steps.extend(_auth_steps(ctx))
        steps.extend(_transport_steps(ctx))
        steps.extend(_security_steps(ctx))
        return steps

    steps = [
        "Install: bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install",
        f"/usr/local/etc/xray/config.json — inbound on port {c.port}",
        f"protocol: {c.protocol.value}",
    ]
    steps.extend(_auth_steps(ctx))
    steps.extend(_transport_steps(ctx))
    steps.extend(_security_steps(ctx))
    steps.append("systemctl enable --now xray")
    steps.append("Server inbound must match client link parameters (above).")
    if c.raw_url:
        steps.append("Compare client link with raw_url from this analysis.")
    return steps


def _scenario_cloudflare(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    cf_conf = next((g.confidence for g in ctx.deployment.guesses if g.name == "Cloudflare CDN"), 0)
    if ctx.deployment.cdn_type != "Cloudflare" and cf_conf < 0.55:
        return None

    c, dns, d = ctx.config, ctx.dns, ctx.deployment
    host = dns.hostname or c.sni or c.host
    if not host:
        return None

    steps = [f"Analyzed domain/SNI: {host} | Cloudflare CDN confidence: {int(cf_conf * 100)}%"]
    if dns.a_records:
        steps.append(f"DNS (A): {_fmt_list(dns.a_records)}")
    if dns.aaaa_records:
        steps.append(f"DNS (AAAA): {_fmt_list(dns.aaaa_records)}")

    if is_ip_address(c.address):
        resolved = dns.a_records[0] if dns.a_records else "—"
        steps.append(
            f"Link address {c.address} — domain resolves to {resolved}; "
            "both are in Cloudflare range (CDN fronting)."
        )

    steps.append(f"Cloudflare DNS → record {host} → origin VPS IP with Proxy enabled.")
    steps.append("SSL/TLS → Full or Full (Strict) depending on origin cert.")

    if ctx.tls.certificate_issuer and "Let's Encrypt" in ctx.tls.certificate_issuer:
        steps.append(f"Handshake cert: {ctx.tls.certificate_issuer} — Full (Strict) once valid on origin.")

    transport = _effective_transport(c)
    if transport == TransportType.XHTTP:
        alpn = (c.alpn or "").replace(" ", "")
        if "h2" in alpn:
            steps.append("Cloudflare Network → HTTP/2 (ALPN h2 in config).")
        if "h3" in alpn:
            steps.append("Cloudflare Network → HTTP/3 (ALPN h3 in config).")
        if c.path:
            steps.append(f"Path «{c.path}» + Host «{c.host or c.sni}» must match inbound.")

    if d.cdn_backend_ips:
        steps.append(f"CDN IPs in analysis: {_fmt_list(d.cdn_backend_ips)}")

    steps.append("Origin VPS IP is not in client link — get from DNS (proxy-off) or hosting panel.")
    return ("Cloudflare CDN Setup", steps)


def _scenario_arvan(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    arvan_conf = next((g.confidence for g in ctx.deployment.guesses if g.name == "Arvan CDN"), 0)
    if ctx.deployment.cdn_type != "ArvanCloud" and arvan_conf < 0.55:
        return None

    c, dns = ctx.config, ctx.dns
    host = dns.hostname or c.sni or c.host
    if not host:
        return None

    steps = [f"Domain: {host} | Arvan confidence: {int(arvan_conf * 100)}%"]
    if dns.a_records:
        steps.append(f"DNS A: {_fmt_list(dns.a_records)}")
    steps.append(f"Arvan panel → CDN → {host} → origin IP + CDN enabled.")
    if c.path:
        steps.append(f"Inbound path: {c.path}")
    return ("Arvan CDN Setup", steps)


def _scenario_origin_server(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    c, d, net = ctx.config, ctx.deployment, _top_network(ctx)
    vps_conf = next((g.confidence for g in ctx.deployment.guesses if g.name == "Direct VPS"), 0)
    behind_cdn = bool(d.cdn_type)

    if not net and not d.real_server_ip and not is_ip_address(c.address):
        return None

    title = "Origin Server (VPS)" if not behind_cdn else "Origin Server (Behind CDN)"
    steps: list[str] = []

    if behind_cdn:
        steps.append(f"CDN {d.cdn_type} in front of origin — client link IP is CDN edge, not VPS.")
    elif vps_conf >= 0.45:
        steps.append(f"Direct VPS — heuristic confidence {int(vps_conf * 100)}%.")

    origin = d.real_server_ip or (c.address if is_ip_address(c.address) else None)
    if origin:
        steps.append(f"Link IP / real_server_ip: {origin}")

    if net:
        loc = ", ".join(x for x in [net.city, net.country] if x)
        steps.append(
            f"Resolved IP {net.ip}: {net.organization or net.isp or '—'}"
            + (f" | {net.asn}" if net.asn else "")
            + (f" | {loc}" if loc else "")
        )
        if net.is_datacenter:
            steps.append("IP type: datacenter/hosting")
        if net.cdn_detected:
            steps.append(f"CDN on IP: {net.cdn_detected} ({int(net.cdn_confidence * 100)}%)")

    steps.append(f"Origin firewall: TCP {c.port} open")
    proto = c.protocol
    if proto in (ProtocolType.HYSTERIA2, ProtocolType.TUIC) or _effective_transport(c) == TransportType.QUIC:
        steps.append(f"UDP {c.port} must also be open ({proto.value}/QUIC).")

    return (title, steps)


def _scenario_reverse_proxy(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    c = ctx.config
    transport = _effective_transport(c)
    if transport not in (TransportType.WS, TransportType.XHTTP, TransportType.GRPC, TransportType.HTTPUPGRADE):
        return None

    conf = next((g.confidence for g in ctx.deployment.guesses if g.name == "Reverse Proxy"), 0)
    if conf < 0.45 and ctx.connectivity.http_response.value != "Valid":
        return None

    host = c.sni or c.host or ctx.dns.hostname
    if not host:
        return None

    steps = [
        f"Reverse Proxy confidence: {int(conf * 100)}% | domain {host} | link port {c.port}",
    ]

    if transport == TransportType.WS and c.path:
        steps.extend([
            f"Nginx location {c.path}:",
            "  proxy_http_version 1.1 + Upgrade/Connection headers",
            f"  proxy_set_header Host {host};",
            "  proxy_pass → Xray inbound listen port on localhost (not visible in client link).",
        ])
    elif transport == TransportType.XHTTP and c.path:
        steps.extend([
            f"XHTTP path «{c.path}» + Host «{c.host or host}»:",
            "  Nginx/Caddy in front of Xray — grpc_pass or proxy_pass (VLESS-XHTTP docs)",
            "  XHTTP mode: stream-up/packet-up usually has separate up/down paths.",
        ])
    elif transport == TransportType.GRPC:
        if c.service_name:
            steps.append(f"gRPC serviceName: {c.service_name}")
        else:
            steps.append("serviceName not in link.")
        steps.append("grpc_pass grpc://127.0.0.1:<listen_port_inbound>")

    if ctx.connectivity.http_response.value == "Valid":
        steps.append(f"HTTP test: Valid (status {ctx.connectivity.http_status_code})")
    elif ctx.connectivity.http_response.value == "Invalid":
        steps.append("HTTP test: Invalid — path may be Xray-only.")

    return ("Reverse Proxy (Nginx/Caddy)", steps)


def _scenario_cf_tunnel(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    c = ctx.config
    cnames = ctx.dns.cname_records
    cf_tunnel_hints = [r for r in cnames if "cfargotunnel" in r.lower()]
    conf = next((g.confidence for g in ctx.deployment.guesses if "Cloudflare Tunnel" in g.name), 0)
    if conf < 0.5 and not cf_tunnel_hints:
        return None

    steps = [f"Cloudflare Tunnel confidence: {int(conf * 100)}%"]
    if cf_tunnel_hints:
        steps.append(f"CNAME: {_fmt_list(cf_tunnel_hints)}")
    host = c.sni or ctx.dns.hostname
    if host:
        steps.append(f"Public Hostname in Zero Trust: {host}")
    if c.path:
        steps.append(f"Path: {c.path}")
    steps.append("cloudflared on origin → localhost:<inbound_port>")
    return ("Cloudflare Tunnel (cloudflared)", steps)


def _scenario_reverse_tunnel(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    conf = next((g.confidence for g in ctx.deployment.guesses if g.name == "Reverse Tunnel"), 0)
    if conf < 0.35:
        return None
    c = ctx.config
    steps = [
        f"Possible frp/nps — confidence {int(conf * 100)}% (not confirmed from link alone).",
        f"Relay VPS: {c.address}:{c.port}",
        "frpc on LAN → frps on VPS → local_port = Xray inbound",
    ]
    return ("Reverse Tunnel (frp/nps)", steps)


def _scenario_reality(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    c = ctx.config
    if not c.reality:
        return None
    steps = ["REALITY inbound — no traditional TLS cert on server:"]
    if c.sni:
        steps.append(f"Dest/SNI camouflage: {c.sni}")
    if c.public_key:
        steps.append(f"Public Key (pbk): {c.public_key}")
    else:
        steps.append("Public Key not in link.")
    if c.short_id is not None:
        steps.append(f"Short ID: {c.short_id if c.short_id else '(empty)'}")
    if c.fingerprint:
        steps.append(f"Fingerprint: {c.fingerprint}")
    transport = _effective_transport(c)
    if transport == TransportType.XHTTP:
        steps.append("REALITY + XHTTP → default Xray mode: stream-one")
    elif transport == TransportType.TCP and c.flow:
        steps.append(f"REALITY + TCP + flow: {c.flow}")
    return ("REALITY", steps)


def _scenario_wireguard(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    c = ctx.config
    if c.protocol != ProtocolType.WIREGUARD:
        return None
    return ("WireGuard", [
        f"Endpoint: {c.address}:{c.port}",
        "Keys/allowed_ips from link conf file",
        "wg0 on server + UDP open + ip_forward",
    ])


def _scenario_openvpn(ctx: GuideContext) -> Optional[tuple[str, list[str]]]:
    c = ctx.config
    if c.protocol != ProtocolType.OPENVPN:
        return None
    return ("OpenVPN", [
        f"Server: {c.address}:{c.port}",
        "ca/cert/key inside .ovpn profile",
    ])


def _tunnel_types_section(ctx: GuideContext) -> SetupGuideSection:
    ta = ctx.tunnel_analysis
    if not ta or not ta.detected_types:
        return SetupGuideSection(
            title="Tunnel Type Detection",
            steps=["Could not determine tunnel type from current data — check DNS/Network analysis."],
        )

    lines = [
        f"Primary tunnel: {ta.primary_type} ({int(ta.primary_confidence * 100)}%)",
        f"Traffic flow: {ta.traffic_flow}",
        "",
        "── Detected tunnel types (evidence-based) ──",
    ]
    for t in ta.detected_types:
        lines.append("")
        lines.append(f"▸ {t.name} — confidence {int(t.confidence * 100)}% [{t.category}]")
        lines.append(f"  Description: {t.description}")
        lines.append(f"  Flow: {t.traffic_flow}")
        if t.evidence:
            lines.append(f"  Evidence: {' | '.join(t.evidence)}")
        if t.setup_steps:
            lines.append("  Setup (from this config data):")
            for s in t.setup_steps:
                lines.append(f"    • {s}")
    return SetupGuideSection(title="Tunnel Type Detection", steps=lines)


def _deployment_guesses_section(ctx: GuideContext) -> SetupGuideSection:
    lines = ["Deploy heuristic ranking (from Network/DNS analysis):"]
    for g in ctx.deployment.guesses:
        lines.append(f"  • {g.name}: {int(g.confidence * 100)}% — {g.description}")
    if ctx.deployment.uncertain_fields:
        lines.append("Uncertain fields:")
        for u in ctx.deployment.uncertain_fields:
            lines.append(f"  ✗ {u}")
    return SetupGuideSection(title="Deploy Type Detection", steps=lines)


def _build_checklist(ctx: GuideContext) -> list[str]:
    c = ctx.config
    items: list[str] = []
    if c.uuid:
        items.append(f"UUID = {c.uuid}")
    if c.path:
        items.append(f"Path = {c.path}")
    sni = c.sni or c.host
    if sni:
        items.append(f"SNI/Host = {sni}")
    items.append(f"Port {c.port} open on origin")
    if ctx.deployment.cdn_type:
        items.append(f"CDN {ctx.deployment.cdn_type}: DNS + SSL with origin cert")
    if ctx.tls.days_until_expiry is not None and ctx.tls.days_until_expiry < 30:
        items.append(f"Renew cert ({ctx.tls.days_until_expiry} days)")
    xt = ctx.xray_test
    if xt and xt.proxy_test.value == "Valid":
        items.append("Proxy test: Valid ✓")
    elif xt and xt.proxy_test.value not in ("Pending", "Skipped"):
        items.append(f"Proxy test: {xt.proxy_test.value}")
    return items


def _build_tips(ctx: GuideContext) -> list[str]:
    c = ctx.config
    tips: list[str] = []
    if _effective_transport(c) == TransportType.WS:
        tips.append("WebSocket deprecated in Xray 26+ — consider XHTTP.")
    if is_ip_address(c.address) and not ctx.deployment.cdn_type:
        tips.append(f"Direct IP {c.address} — origin exposed.")
    return tips


def build_deployment_setup_guide(
    config: ParsedConfig,
    deployment: DeploymentAnalysis,
    tls: TLSAnalysis,
    dns: DNSAnalysis,
    network: list[IPIntelligence],
    connectivity: ConnectivityResult,
    tunnel: TunnelRoute,
    traceroute: TracerouteResult,
    xray_test: Optional[XrayTestResult] = None,
    tunnel_analysis: Optional[TunnelAnalysis] = None,
) -> DeploymentSetupGuide:
    ctx = GuideContext(
        config=config, deployment=deployment, tls=tls, dns=dns, network=network,
        connectivity=connectivity, tunnel=tunnel, traceroute=traceroute,
        xray_test=xray_test, tunnel_analysis=tunnel_analysis,
    )

    guess_name, guess_conf, _ = _primary_guess(ctx)
    if tunnel_analysis is not None:
        scenario = tunnel_analysis.primary_type
        conf = tunnel_analysis.primary_confidence
    else:
        scenario = guess_name
        conf = guess_conf
    facts = _build_infrastructure_facts(ctx)
    sections: list[SetupGuideSection] = [
        SetupGuideSection(title="Infrastructure Profile", steps=facts),
        _tunnel_types_section(ctx),
        _deployment_guesses_section(ctx),
        SetupGuideSection(title=f"Primary Scenario: {scenario} ({int(conf * 100)}%)", steps=[_build_summary(ctx)]),
    ]

    scenario_fns = [
        _scenario_cloudflare, _scenario_arvan, _scenario_origin_server,
        _scenario_reverse_proxy, _scenario_cf_tunnel, _scenario_reverse_tunnel,
        _scenario_reality, _scenario_wireguard, _scenario_openvpn,
    ]
    added: set[str] = set()
    for fn in scenario_fns:
        result = fn(ctx)
        if result and result[0] not in added:
            sections.append(SetupGuideSection(title=result[0], steps=result[1]))
            added.add(result[0])

    if config.protocol in (ProtocolType.VLESS, ProtocolType.VMESS, ProtocolType.TROJAN,
                           ProtocolType.SHADOWSOCKS, ProtocolType.HYSTERIA2, ProtocolType.TUIC):
        sections.append(SetupGuideSection(title="3x-ui Panel Setup", steps=_panel_3xui(ctx)))
        marzban = _panel_marzban(ctx)
        if marzban:
            sections.append(SetupGuideSection(title="Marzban Panel Setup", steps=marzban))

    sections.append(SetupGuideSection(title="Manual Xray-core Install", steps=_manual_xray(ctx)))

    return DeploymentSetupGuide(
        summary=_build_summary(ctx),
        detected_scenario=scenario,
        scenario_confidence=conf,
        infrastructure_facts=facts,
        recommended_panels=_recommend_panels(ctx),
        sections=sections,
        checklist=_build_checklist(ctx),
        tips=_build_tips(ctx),
    )
