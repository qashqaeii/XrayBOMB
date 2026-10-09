"""English user-facing copy for the How to Run tab."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend import how_to_run_fa_helpers as H
from backend.deployment_guide import GuideContext
from backend.models import SetupGuideSection

if TYPE_CHECKING:
    from backend.how_to_run import RunValues


def _ph(label: str) -> str:
    return f"<{label}>"


CATALOG_FA: dict[str, dict[str, str]] = {
    "direct_vps": {
        "name": "Direct VPS",
        "flow": "Client → server IP/domain → Xray inbound",
        "explain": "Traffic goes directly to origin IP or domain; no CDN or relay.",
    },
    "cdn_fronting": {
        "name": "CDN Fronting (generic)",
        "flow": "Client → CDN edge → origin (Xray behind CDN)",
        "explain": "Client connects to CDN IP/domain; CDN forwards to the main VPS.",
    },
    "cloudflare_cdn": {
        "name": "Cloudflare CDN Fronting",
        "flow": "Client → Cloudflare edge → VPS origin",
        "explain": "Domain on Cloudflare with orange proxy; TLS to CF then CF to origin.",
    },
    "arvan_cdn": {
        "name": "Arvan CDN Fronting",
        "flow": "Client → Arvan edge → VPS origin",
        "explain": "Arvan CDN in front of server; DNS and SSL in Arvan panel.",
    },
    "akamai_cdn": {
        "name": "Akamai CDN Fronting",
        "flow": "Client → Akamai edge → origin",
        "explain": "IP/ASN belongs to Akamai — enterprise CDN.",
    },
    "fastly_cdn": {
        "name": "Fastly CDN Fronting",
        "flow": "Client → Fastly POP → origin",
        "explain": "Fastly IP/ASN visible in DNS.",
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
        "flow": "Client → Cloudflare → cloudflared → localhost:Xray",
        "explain": "Inbound port not exposed on VPS; agent connects outbound to CF.",
    },
    "reverse_proxy": {
        "name": "Reverse Proxy (Nginx/Caddy/HAProxy)",
        "flow": "Client → Nginx :443 → localhost:Xray",
        "explain": "Nginx/Caddy TLS or pass-through; forwards WS/gRPC/XHTTP to Xray.",
    },
    "direct_xray_inbound": {
        "name": "Direct Xray Inbound (public port)",
        "flow": "Client → Xray on :port",
        "explain": "Xray listens on 0.0.0.0 — common with 3x-ui without Nginx.",
    },
    "reverse_tunnel_frp": {
        "name": "Reverse Tunnel (frp/nps/ngrok)",
        "flow": "Client → relay VPS ← agent behind NAT → local Xray",
        "explain": "Xray server behind NAT; frpc connects to public VPS and publishes port.",
    },
    "sni_fronting": {
        "name": "SNI / IP Fronting",
        "flow": "Client → IP/CDN with different SNI",
        "explain": "Connection address differs from SNI/Host.",
    },
    "host_sni_split": {
        "name": "Host ≠ SNI (Domain Fronting)",
        "flow": "TLS SNI one domain — HTTP Host another",
        "explain": "Split SNI and Host to bypass CDN/filter rules.",
    },
    "xhttp_split": {
        "name": "XHTTP Split (separate upload/download)",
        "flow": "Upload on one path — download on another path/edge",
        "explain": "XHTTP with downloadSettings; uplink and downlink may differ.",
    },
    "reality_camouflage": {
        "name": "REALITY Camouflage",
        "flow": "Client → handshake mimics real site → Xray",
        "explain": "No real cert on server; handshake looks like visiting dest.",
    },
    "multi_hop": {
        "name": "Multi-hop / Relay Chain",
        "flow": "Client → Relay1 → Relay2 → origin",
        "explain": "Multiple relay layers; not visible in a single share link.",
    },
    "wireguard_tunnel": {
        "name": "WireGuard VPN",
        "flow": "Client → UDP WireGuard → server → routing",
        "explain": "Layer 3 tunnel; Xray can run behind WireGuard.",
    },
    "openvpn_tunnel": {
        "name": "OpenVPN",
        "flow": "Client → OpenVPN TCP/UDP → server",
        "explain": "Classic OpenVPN tunnel.",
    },
    "hysteria2_quic": {
        "name": "Hysteria2 (QUIC/UDP)",
        "flow": "Client → QUIC UDP → Hy2 server",
        "explain": "QUIC with obfuscation; UDP must be open.",
    },
    "tuic_quic": {
        "name": "TUIC (QUIC)",
        "flow": "Client → QUIC → TUIC server",
        "explain": "TUIC over QUIC.",
    },
    "load_balancer": {
        "name": "Load Balancer / Multi-IP",
        "flow": "Client → LB → one of several backends",
        "explain": "Multiple A records or multiple origins in CDN/LB.",
    },
    "ssh_tunnel": {
        "name": "SSH Tunnel (Port Forward)",
        "flow": "Client → SSH -L/-R → local Xray",
        "explain": "SSH port forward — usually for testing.",
    },
    "gost_relay": {
        "name": "GOST Relay Chain",
        "flow": "Client → GOST relay → Xray",
        "explain": "Multi-layer relay with GOST.",
    },
}


def intro_lines(v: RunValues, scenario: str, conf: float) -> list[str]:
    return [
        "How to Run — Implementation Guide",
        "=" * 58,
        "",
        "This guide covers only the scenario detected by analysis, step by step.",
        "Follow the phases in order — other scenarios are not included here.",
        "",
        f"Detected scenario: {scenario} (confidence {int(conf * 100)}%)",
        "",
        "── Values from the client link ──",
        f"  Link address    : {v.link_address}",
        f"  Protocol        : {v.protocol.value}",
        f"  Transport       : {v.transport.value}",
        f"  Port            : {v.port}",
        f"  Domain / SNI    : {v.domain}",
        f"  Path            : {v.path}",
        f"  Host            : {v.host_header}",
        "",
        "── Values you must provide ──",
        f"  Origin VPS IP   : {v.origin_ip}",
        "  (Origin IP is not in the link — get it from VPS panel or DNS without CDN.)",
        "",
        "No fake IPs or domains — only analysis data or <> placeholders.",
        "",
    ]


def _origin_layer(v: RunValues, ctx: GuideContext) -> list[str]:
    if v.needs_reverse_proxy:
        return H.merge(
            H.phase(4, "Reverse Proxy on Origin"),
            H.steps_nginx_front(v),
        )
    return H.merge(
        H.phase(4, "Direct inbound on Origin"),
        [
            f"  1. Listen 0.0.0.0:{v.port} — no Nginx.",
            "  2. Fill the 3x-ui inbound fields below.",
            f"  3. ufw allow {v.port}/tcp",
        ],
    )


def section_arvan(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Arvan CDN Fronting",
        steps=H.merge(
            H.arch("Client (IR) → Arvan edge → VPS origin → Xray"),
            H.phase(1, "Arvan account, domain, and CDN"),
            H.steps_arvan_cdn_panel(v),
            H.phase(2, "VPS Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.phase(3, "Xray Inbound"),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "Origin Firewall"),
            [
                "  1. Allow Arvan edge IP ranges (see docs.arvancloud.ir).",
                "  2. Temporarily allow all — then restrict.",
            ],
            H.phase(6, "Client Link"),
            H.steps_client_link(v, use_domain=True),
            H.phase(7, "Verify"),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_cloudflare(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Cloudflare CDN Fronting",
        steps=H.merge(
            H.arch("Client → Cloudflare edge → origin VPS → Xray"),
            H.phase(1, "Cloudflare DNS and CDN"),
            H.steps_cloudflare_panel(v),
            H.phase(2, "VPS Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.phase(3, "Inbound"),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "Cloudflare extras"),
            [
                "  1. Origin Certificate (optional) — 15-year cert in SSL/TLS → Origin Server.",
                "  2. Page Rule legacy or Cache Rule — Bypass on path.",
                "  3. From Iran: use Clean IP Finder in the app.",
            ],
            H.phase(6, "Client Link"),
            H.steps_client_link(v),
            H.phase(7, "Verify"),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_cdn_generic(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    cdn = v.cdn_type or "CDN"
    return SetupGuideSection(
        title=f"Scenario: CDN Fronting ({cdn})",
        steps=H.merge(
            H.arch(f"Client → {cdn} edge → origin → Xray"),
            H.phase(1, "Domain and CDN"),
            H.steps_domain_register(v),
            [
                f"  5. Add domain {v.domain} in {cdn} panel.",
                f"  6. Origin: {v.origin_ip}:{v.port} — CDN/Proxy ON.",
                f"  7. NS or CNAME per {cdn} panel.",
            ],
            H.steps_cdn_edge_settings(v),
            H.phase(2, "VPS Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.phase(3, "Inbound"),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_direct_vps(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Direct VPS",
        steps=H.merge(
            H.arch("Client → origin IP/domain → Xray (no CDN)"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.phase(2, "DNS (optional)"),
            [
                f"  1. A record: {v.domain} → {v.origin_ip} — CDN off / grey.",
                "  2. Or set link address = direct IP.",
            ],
            H.phase(3, "Direct inbound"),
            H.steps_inbound_3xui(v, ctx),
            [
                f"  Listen IP: empty (0.0.0.0:{v.port})",
                "  TLS: acme.sh | REALITY: no cert needed",
            ],
            H.phase(4, "Client Link"),
            H.steps_client_link(v, use_domain=not v.link_address.startswith("<")),
            H.phase(5, "Verify and risk"),
            H.steps_verify(v, cdn=False),
            [
                "  ⚠ Origin IP exposed — REALITY or CDN recommended for Iran.",
            ],
        ),
    )


def section_reality(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: REALITY Camouflage",
        steps=H.merge(
            H.arch("Client → handshake mimics real site → Xray REALITY"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.phase(2, "x25519 keys"),
            [
                "  1. SSH → xray x25519",
                "  2. PrivateKey → inbound | PublicKey → pbk= in client link",
                f"  3. Public Key from analysis: {v.public_key}",
            ],
            H.phase(3, "Choose Dest"),
            [
                f"  1. Dest/SNI: {v.sni}:443 — must be online and respond on 443.",
                "  2. Common sites: www.google.com, www.microsoft.com — test REALITY probe.",
                "  3. If VPS IP is blocked by dest → REALITY fails.",
            ],
            H.phase(4, "3x-ui inbound"),
            H.steps_inbound_3xui(v, ctx),
            H.phase(5, "Client Link"),
            H.steps_client_link(v),
            H.phase(6, "Verify"),
            H.steps_verify(v),
            ["  ☐ REALITY probe in analysis: Valid"],
        ),
    )


def section_reverse_proxy(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Reverse Proxy (Nginx/Caddy)",
        steps=H.merge(
            H.arch("Client → Nginx/Caddy :443 → 127.0.0.1:Xray"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            H.phase(2, "Internal Xray"),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            [f"  Listen IP: 127.0.0.1:{_ph('xray-internal-port')}"],
            H.phase(3, "Nginx/Caddy"),
            H.steps_nginx_front(v),
            H.phase(4, "CDN (optional)"),
            [
                f"  1. CDN → A → {v.origin_ip} — origin exposes only Nginx.",
                f"  2. Cache bypass path {v.path}",
            ],
            H.phase(5, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=False),
        ),
    )


def section_cf_tunnel(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Cloudflare Tunnel (cloudflared)",
        steps=H.merge(
            H.arch("Client → CF edge → cloudflared (outbound) → localhost:Xray"),
            H.phase(1, "Cloudflare Zero Trust"),
            [
                "  1. one.dash.cloudflare.com → Zero Trust → Networks → Tunnels.",
                "  2. Create tunnel → choose name → Install connector.",
                "  3. cloudflared service install <TOKEN> on VPS.",
            ],
            H.phase(2, "Public Hostname"),
            [
                f"  1. Public Hostname: {v.domain}",
                f"  2. Service: http://127.0.0.1:{v.port}",
                f"  3. Path (if needed): {v.path}",
            ],
            H.phase(3, "Xray localhost-only"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            [f"  Listen: 127.0.0.1:{v.port} — ufw inbound {v.port} not required."],
            H.phase(4, "Client Link"),
            H.steps_client_link(v),
            H.phase(5, "Verify"),
            H.steps_verify(v, cdn=True),
            ["  ☐ cloudflared active: systemctl status cloudflared"],
        ),
    )


def section_direct_xray(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Direct Xray Inbound",
        steps=H.merge(
            H.arch("Client → Xray directly on 0.0.0.0:port"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.phase(2, "Public inbound"),
            H.steps_inbound_3xui(v, ctx),
            [f"  Empty Listen IP → 0.0.0.0:{v.port}"],
            H.phase(3, "With CDN"),
            [
                f"  1. CDN forwards directly to port {v.port}.",
                f"  2. Cache/WAF bypass on {v.path}.",
            ],
            H.phase(4, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=bool(v.cdn_type)),
        ),
    )


from backend.how_to_run_fa_extended import (
    section_akamai,
    section_bunny,
    section_cloudfront,
    section_fastly,
    section_gcore,
    section_gost_relay,
    section_host_sni_split,
    section_hysteria2,
    section_load_balancer,
    section_multi_hop,
    section_openvpn,
    section_reverse_tunnel,
    section_sni_fronting,
    section_ssh_tunnel,
    section_tuic,
    section_wireguard,
    section_xhttp_split,
)


def section_checklist(v: RunValues) -> SetupGuideSection:
    steps: list[str] = []
    if v.behind_cdn:
        steps.extend([
            "☐ Public DNS shows CDN IP (not leaked origin IP)",
            "☐ Cache/WAF off on tunnel path",
        ])
    steps.extend([
        f"☐ Port {v.port} reachable from outside",
        "☐ UUID/Path/SNI/Host match the share link",
        "☐ Live Xray Test: Valid",
        "☐ Real test from your ISP",
    ])
    return SetupGuideSection(title="Final Checklist", steps=steps)


SCENARIO_SECTIONS_FA: dict[str, callable] = {
    "direct_vps": lambda v, c: section_direct_vps(v, c),
    "cdn_fronting": lambda v, c: (
        section_arvan(v, c) if v.cdn_type == "ArvanCloud"
        else section_cloudflare(v, c) if v.cdn_type == "Cloudflare"
        else section_cdn_generic(v, c)
    ),
    "cloudflare_cdn": lambda v, c: section_cloudflare(v, c),
    "arvan_cdn": lambda v, c: section_arvan(v, c),
    "akamai_cdn": lambda v, c: section_akamai(v, c),
    "fastly_cdn": lambda v, c: section_fastly(v, c),
    "cloudfront_cdn": lambda v, c: section_cloudfront(v, c),
    "bunny_cdn": lambda v, c: section_bunny(v, c),
    "gcore_cdn": lambda v, c: section_gcore(v, c),
    "cloudflare_tunnel": lambda v, c: section_cf_tunnel(v, c),
    "reverse_proxy": lambda v, c: section_reverse_proxy(v, c),
    "direct_xray_inbound": lambda v, c: section_direct_xray(v, c),
    "reverse_tunnel_frp": lambda v, c: section_reverse_tunnel(v, c),
    "sni_fronting": lambda v, c: section_sni_fronting(v, c),
    "host_sni_split": lambda v, c: section_host_sni_split(v, c),
    "xhttp_split": lambda v, c: section_xhttp_split(v, c),
    "reality_camouflage": lambda v, c: section_reality(v, c),
    "multi_hop": lambda v, c: section_multi_hop(v, c),
    "wireguard_tunnel": lambda v, c: section_wireguard(v, c),
    "openvpn_tunnel": lambda v, c: section_openvpn(v, c),
    "hysteria2_quic": lambda v, c: section_hysteria2(v, c),
    "tuic_quic": lambda v, c: section_tuic(v, c),
    "load_balancer": lambda v, c: section_load_balancer(v, c),
    "ssh_tunnel": lambda v, c: section_ssh_tunnel(v, c),
    "gost_relay": lambda v, c: section_gost_relay(v, c),
}
