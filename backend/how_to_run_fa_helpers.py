"""Shared English step blocks for How to Run."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend.deployment_guide import GuideContext
from backend.models import ProtocolType, TransportType

if TYPE_CHECKING:
    from backend.how_to_run import RunValues


def _ph(label: str) -> str:
    return f"<{label}>"


def arch(desc: str) -> list[str]:
    return [f"Architecture: {desc}", ""]


def phase(n: int, title: str) -> list[str]:
    return [f"── Phase {n}: {title} ──", ""]


def steps_vps_purchase(v: RunValues) -> list[str]:
    udp = ""
    if v.protocol in (ProtocolType.HYSTERIA2, ProtocolType.TUIC) or v.transport == TransportType.QUIC:
        udp = f"  • Also open UDP port {v.port}.\n"
    return [
        "  1. Buy a VPS outside Iran (Hetzner / OVH / Contabo / Netcup).",
        "  2. Minimum plan: 1 vCPU, 2 GB RAM, 20 GB SSD — Ubuntu 22.04 or Debian 12.",
        "  3. Region: Germany, Netherlands, or Finland — test with Multi-Region Ping in the app.",
        f"  4. Note the public IP → {v.origin_ip}",
        f"  5. Firewall: ufw allow {v.port}/tcp",
        udp.rstrip(),
        f"  6. SSH: ssh root@{_ph('origin-vps-ip')}",
        "  7. ufw enable — only open 22, panel port, and tunnel port.",
    ]


def steps_panel_install() -> list[str]:
    return [
        "  1. Install 3x-ui (MHSanaei / Sanaei — latest release):",
        "     bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)",
        f"  2. Panel URL: https://{_ph('origin-vps-ip')}:{_ph('panel-port')}",
        "  3. Change the default password — enable fail2ban on SSH.",
        "  4. Workflow: Inbounds → Add Inbound (+)",
    ]


def steps_domain_register(v: RunValues) -> list[str]:
    return [
        f"  1. Analyzed domain: {v.domain}",
        "  2. .ir → nic.ir (IRNIC) | .com/.net → IRNIC or an international registrar.",
        "  3. Domain must be Active — .ir may take up to 24 business hours for IRNIC approval.",
        "  4. Use a clean domain — run DNS Health in the app before go-live.",
        "  5. Do not publish origin IP in public DNS before CDN is ready.",
    ]


def steps_inbound_3xui(v: RunValues, ctx: GuideContext) -> list[str]:
    c = ctx.config
    lines = [
        f"  Protocol        : {v.protocol.value}",
        f"  Port            : {v.port}",
        "  Listen IP       : empty (=0.0.0.0) | behind Nginx → 127.0.0.1",
        f"  UUID            : {v.uuid}",
    ]
    if c.protocol == ProtocolType.TROJAN:
        lines.append("  Password        : same value as in the share link")
    if c.protocol == ProtocolType.SHADOWSOCKS:
        lines.append(f"  Method          : {c.encryption or 'from link'}")
    if v.flow:
        lines.append(f"  Flow            : {v.flow}")
    lines.append(f"  Network         : {v.transport.value}")
    if v.transport == TransportType.WS:
        lines += [f"  Path            : {v.path}", f"  Host            : {v.host_header}"]
    elif v.transport == TransportType.GRPC:
        lines.append(f"  serviceName     : {v.service_name}")
    elif v.transport in (TransportType.XHTTP, TransportType.HTTPUPGRADE):
        lines += [f"  Path            : {v.path}", f"  Host            : {v.host_header}"]
        if c.reality:
            lines.append("  Mode            : stream-one")
        elif c.tls and "h2" in v.alpn.replace(" ", ""):
            lines.append("  Mode            : stream-up")
    if c.reality:
        lines += [
            "  Security        : REALITY",
            f"  Dest            : {v.sni}:443",
            f"  Server Names    : {v.sni}",
            f"  Short IDs       : {v.short_id}",
            f"  Fingerprint     : {v.fingerprint}",
            f"  Private Key     : {_ph('server-PrivateKey')}  (xray x25519)",
        ]
    elif c.tls:
        lines += [
            "  Security        : TLS",
            f"  SNI             : {v.sni}",
            f"  ALPN            : {v.alpn}",
            "  Certificate     : acme.sh / Let's Encrypt",
        ]
    lines += ["  Save → Restart Xray → compare Client Link with the analyzed raw_url."]
    return lines


def steps_nginx_front(v: RunValues) -> list[str]:
    internal = _ph("xray-internal-port")
    base = [
        f"  1. Xray inbound on 127.0.0.1:{internal} (not public IP).",
        f"  2. Nginx/Caddy on 0.0.0.0:{v.port} — cert for {v.domain}.",
        f"  3. certbot or acme.sh — valid cert for Full (Strict) CDN mode.",
    ]
    if v.transport == TransportType.WS:
        base += [
            f"  4. location {v.path} {{",
            "       proxy_http_version 1.1;",
            "       proxy_set_header Upgrade $http_upgrade;",
            "       proxy_set_header Connection upgrade;",
            f"       proxy_set_header Host {v.host_header};",
            f"       proxy_pass http://127.0.0.1:{internal};",
            "     }",
        ]
    elif v.transport == TransportType.GRPC:
        base += [
            f"  4. grpc_pass grpc://127.0.0.1:{internal};",
            f"     grpc_set_header Host {v.host_header};",
            f"     serviceName: {v.service_name}",
        ]
    elif v.transport == TransportType.XHTTP:
        base += [
            f"  4. path {v.path} → proxy_pass / grpc_pass per XHTTP Xray docs",
            f"     Host: {v.host_header}",
        ]
    else:
        base.append(f"  4. proxy_pass → 127.0.0.1:{internal}")
    base.append("  5. nginx -t && systemctl reload nginx")
    return base


def steps_cdn_edge_settings(v: RunValues) -> list[str]:
    return [
        "  SSL/TLS:",
        "    • Full or Full (Strict) — with cert on origin use Strict.",
        "  Caching:",
        f"    • Off / Bypass on tunnel path: {v.path}",
        "  WebSocket / HTTP/2:",
        "    • WebSocket: ON | HTTP/2: ON if inbound ALPN includes h2.",
        "  WAF / Bot:",
        "    • Disable strict WAF on tunnel path or add an exception.",
        "  Compression:",
        "    • Off for WS/gRPC/XHTTP.",
    ]


def steps_client_link(v: RunValues, *, use_domain: bool = True) -> list[str]:
    addr = v.domain if use_domain else v.link_address
    return [
        f"  address (link)  : {addr}",
        f"  port            : {v.port}",
        f"  UUID/Password   : {v.uuid}",
        f"  SNI             : {v.sni}",
        f"  Host            : {v.host_header}",
        f"  Path            : {v.path}",
        f"  Transport       : {v.transport.value}",
        "  Panel Client Link must match the analyzed raw_url byte-for-byte.",
    ]


def steps_verify(v: RunValues, *, cdn: bool = False) -> list[str]:
    lines = [
        f"  ☐ TCP/UDP port {v.port} reachable from outside",
        "  ☐ Live Xray Test in app: Valid",
        "  ☐ Real test from your ISP/country (not ping only)",
        "  ☐ UUID / Path / SNI / Host match the share link",
    ]
    if cdn:
        lines.insert(0, "  ☐ Public DNS shows CDN edge IP — not leaked origin IP")
        lines.append("  ☐ Cache and WAF bypassed on tunnel path")
    if v.protocol not in (ProtocolType.WIREGUARD, ProtocolType.OPENVPN):
        lines.append("  ☐ cert > 30 days (if TLS — not REALITY)")
    return lines


def steps_arvan_cdn_panel(v: RunValues) -> list[str]:
    return [
        "  1. panel.arvancloud.ir — sign up, verify identity, CDN Free (start) / Growth (high traffic).",
        f"  2. CDN → Add Domain → {v.domain}",
        "  3. Copy the two Arvan NS records — they differ per domain.",
        "  4. nic.ir (.ir domain): My Domains → edit delegation rows → Arvan NS1/NS2.",
        "  5. NS propagation: 1–48 hours — wait until CDN is Active.",
        "  6. If .ir NS fails: Arvan CDN → DNS → change NS → try .net/.com suffix.",
        f"  7. DNS Record: Type A | Name @ or sub | Value {v.origin_ip} | CDN Proxy: ON",
    ] + steps_cdn_edge_settings(v)


def steps_cloudflare_panel(v: RunValues) -> list[str]:
    return [
        "  1. dash.cloudflare.com — Add Site → {domain}".format(domain=v.domain),
        "  2. Replace registrar NS with Cloudflare NS.",
        f"  3. DNS → A → {v.domain} → {v.origin_ip} → Proxied (orange cloud).",
        "  4. SSL/TLS → Full (Strict) with origin cert | Full without origin cert.",
        "  5. Network → WebSockets ON | HTTP/2 ON | HTTP/3 if ALPN h3.",
        f"  6. Cache Rules → Bypass cache for path {v.path}.",
        "  7. Security → Bot Fight OFF on path | WAF exception.",
        "  8. From Iran: use Clean IP Finder + DNS Health in the app.",
    ]


def steps_origin_inbound(v: RunValues, *, direct_public: bool = False) -> list[str]:
    listen = f"0.0.0.0:{v.port}" if direct_public else f"127.0.0.1:{_ph('xray-internal-port')} + Nginx on {v.port}"
    return [
        f"  1. inbound {v.protocol.value} + {v.transport.value}",
        f"  2. Listen: {listen}",
        "  3. Fill the 3x-ui inbound fields exactly as listed below.",
    ]


def merge(*parts: list[str]) -> list[str]:
    out: list[str] = []
    for p in parts:
        out.extend(p)
    return out
