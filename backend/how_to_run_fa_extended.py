"""Extended English scenario sections — imported by how_to_run_fa."""

from __future__ import annotations

from typing import TYPE_CHECKING

from backend import how_to_run_fa_helpers as H
from backend.deployment_guide import GuideContext
from backend.models import SetupGuideSection

if TYPE_CHECKING:
    from backend.how_to_run import RunValues


def _ph(label: str) -> str:
    return f"<{label}>"


def _origin_layer(v: RunValues, ctx: GuideContext) -> list[str]:
    if v.needs_reverse_proxy:
        return H.merge(H.phase(4, "Reverse Proxy on Origin"), H.steps_nginx_front(v))
    return H.merge(
        H.phase(4, "Direct inbound"),
        [
            f"  Listen 0.0.0.0:{v.port}",
            "  3x-ui inbound — fill fields exactly as listed.",
        ],
    )


def section_akamai(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Akamai CDN Fronting",
        steps=H.merge(
            H.arch("Client → Akamai edge → origin → Xray"),
            H.phase(1, "Akamai Property"),
            [
                "  1. control.akamai.com — Property Manager.",
                f"  2. Hostname: {v.domain}",
                f"  3. Origin: {v.origin_ip}:{v.port} HTTPS.",
                "  4. Cert at edge — Akamai managed.",
            ],
            H.steps_cdn_edge_settings(v),
            H.phase(2, "Origin VPS"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_fastly(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Fastly CDN Fronting",
        steps=H.merge(
            H.arch("Client → Fastly POP → origin → Xray"),
            H.phase(1, "Fastly Service"),
            [
                "  1. manage.fastly.com → Create Service.",
                f"  2. Domain: {v.domain} → Host {v.origin_ip}:{v.port}.",
            ],
            H.steps_cdn_edge_settings(v),
            H.phase(2, "Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(4, "WebSocket/VCL"),
            [f"  Bypass cache {v.path} | WebSocket enabled."],
            H.phase(5, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_cloudfront(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: AWS CloudFront Fronting",
        steps=H.merge(
            H.arch("Client → CloudFront → origin → Xray"),
            H.phase(1, "Distribution"),
            [
                f"  Alternate domain: {v.domain}",
                f"  Origin: {v.origin_ip}:{v.port}",
                "  ACM us-east-1 | HTTP/2 ON.",
            ],
            H.phase(2, "Cache"),
            [f"  Path {v.path}* → CachingDisabled."],
            H.phase(3, "Origin VPS"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_bunny(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: BunnyCDN Fronting",
        steps=H.merge(
            H.arch("Client → Bunny edge → origin → Xray"),
            H.phase(1, "Pull Zone"),
            [
                f"  panel.bunny.net → hostname {v.domain}",
                f"  Origin: https://{v.origin_ip}:{v.port}",
            ],
            H.phase(2, "Edge Rules"),
            [f"  Cache off {v.path} | WebSocket if WS."],
            H.phase(3, "Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_gcore(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Gcore CDN Fronting",
        steps=H.merge(
            H.arch("Client → Gcore edge → origin → Xray"),
            H.phase(1, "Gcore CDN"),
            [
                f"  Resource {v.domain}",
                f"  Origin group {v.origin_ip}:{v.port}",
            ],
            H.steps_cdn_edge_settings(v),
            H.phase(2, "Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(4, "Link and verify"),
            H.steps_client_link(v),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_reverse_tunnel(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Reverse Tunnel (frp/nps/ngrok)",
        steps=H.merge(
            H.arch("Client → relay VPS ← frpc behind NAT → local Xray"),
            H.phase(1, "Relay VPS (frps)"),
            H.steps_vps_purchase(v),
            [
                f"  frps.ini: bind_port={v.port}",
                "  token=<secret> tls_enable=true",
                "  systemctl enable frps",
            ],
            H.phase(2, "frpc behind NAT"),
            [
                f"  server_addr={v.link_address} server_port={v.port}",
                f"  local_ip=127.0.0.1 local_port={_ph('local-xray-port')}",
                f"  remote_port={v.port}",
            ],
            H.phase(3, "Local Xray"),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            H.phase(4, "Client Link"),
            [f"  address={v.link_address} port={v.port}"],
            H.phase(5, "Verify"),
            H.steps_verify(v),
            ["  ☐ frpc log: start proxy success"],
        ),
    )


def section_sni_fronting(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: SNI / IP Fronting",
        steps=H.merge(
            H.arch("address ≠ SNI — connect to IP/CDN with different SNI"),
            H.phase(1, "Values"),
            [f"  address={v.link_address}", f"  SNI={v.sni}"],
            H.phase(2, "Inbound"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(4, "CDN"),
            ["  CDN must accept SNI on the edge IP."],
            H.phase(5, "Verify"),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_host_sni_split(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Host ≠ SNI (Domain Fronting)",
        steps=H.merge(
            H.arch("TLS SNI and HTTP Host differ"),
            H.phase(1, "Values"),
            [f"  SNI={v.sni}", f"  Host={v.host_header}"],
            H.phase(2, "Origin"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(4, "Nginx Host header"),
            [f"  proxy_set_header Host {v.host_header};"],
            H.phase(5, "Verify"),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_xhttp_split(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: XHTTP Split",
        steps=H.merge(
            H.arch("Separate uplink/downlink"),
            H.phase(1, "Uplink"),
            [f"  path={v.path} host={v.host_header}"],
            H.phase(2, "Downlink"),
            ["  downloadSettings in client — separate path/host."],
            H.phase(3, "Server"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            _origin_layer(v, ctx),
            H.phase(5, "CDN cache off on both paths"),
            H.steps_verify(v, cdn=True),
        ),
    )


def section_multi_hop(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Multi-hop / Relay Chain",
        steps=H.merge(
            H.arch("entry → relay → exit → internet"),
            H.phase(1, "Entry"),
            [f"  {v.link_address}:{v.port} — inbound chain UUID."],
            H.phase(2, "Relay VPS"),
            ["  outbound VLESS/gRPC → next hop."],
            H.phase(3, "Exit"),
            ["  freedom outbound."],
            H.phase(4, "Each node"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            H.phase(5, "Verify exit IP"),
            ["  ☐ Live test exit country matches expectation."],
        ),
    )


def section_load_balancer(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Load Balancer / Multi-IP",
        steps=H.merge(
            H.arch("LB or multiple A records → backends"),
            H.phase(1, "Detection"),
            ["  Multiple CDN A records (anycast) ≠ origin LB — check analysis."],
            H.phase(2, "LB setup"),
            [
                f"  Each backend: identical inbound on port {v.port}",
                "  health check on tunnel path | WS stickiness.",
            ],
            H.phase(3, "Node"),
            H.steps_vps_purchase(v),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            H.phase(4, "Verify"),
            H.steps_verify(v),
        ),
    )


def section_ssh_tunnel(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: SSH Tunnel",
        steps=H.merge(
            H.arch("SSH -L → Xray localhost"),
            H.phase(1, "SSH server"),
            H.steps_vps_purchase(v),
            H.phase(2, "Xray"),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            [f"  Listen 127.0.0.1:{v.port}"],
            H.phase(3, "Port forward"),
            [
                f"  ssh -N -L 1080:127.0.0.1:{v.port} user@{v.link_address}",
                "  Client → 127.0.0.1:1080",
            ],
            H.phase(4, "Limitation"),
            ["  Testing only — not for production."],
        ),
    )


def section_gost_relay(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: GOST Relay",
        steps=H.merge(
            H.arch("GOST relay → upstream Xray"),
            H.phase(1, "Relay VPS"),
            H.steps_vps_purchase(v),
            [
                f"  gost -L=tcp://:{v.port} -F=relay+tls://{_ph('upstream-ip')}:{v.port}",
            ],
            H.phase(2, "Upstream"),
            H.steps_panel_install(),
            H.steps_inbound_3xui(v, ctx),
            H.phase(3, "Verify"),
            H.steps_verify(v),
        ),
    )


def section_wireguard(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: WireGuard VPN",
        steps=H.merge(
            H.arch("UDP WG → routing/NAT"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            [f"  ufw allow {v.port}/udp"],
            H.phase(2, "wg0"),
            [
                "  apt install wireguard",
                f"  ListenPort={v.port}",
                f"  Endpoint={v.link_address}:{v.port}",
                "  wg genkey / pubkey | Peer keys from conf.",
            ],
            H.phase(3, "NAT"),
            ["  ip_forward=1 | MASQUERADE"],
            H.phase(4, "Verify"),
            [f"  ☐ UDP {v.port} OK"],
        ),
    )


def section_openvpn(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: OpenVPN",
        steps=H.merge(
            H.arch("OpenVPN TCP/UDP"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            [f"  ufw allow {v.port}"],
            H.phase(2, "PKI + server"),
            [
                "  easy-rsa or openvpn-install",
                f"  port {v.port} | client .ovpn",
            ],
            H.phase(3, "Verify"),
            ["  ☐ connect OK | egress = VPS"],
        ),
    )


def section_hysteria2(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: Hysteria2 (QUIC)",
        steps=H.merge(
            H.arch("QUIC UDP Hy2"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            [f"  ufw allow {v.port}/udp"],
            H.phase(2, "Hy2 inbound"),
            [
                f"  3x-ui Hysteria2 port {v.port}",
                f"  SNI {v.sni} | password from link",
            ],
            H.phase(3, "ISP test"),
            [f"  ☐ UDP {v.port} from your mobile ISP"],
        ),
    )


def section_tuic(v: RunValues, ctx: GuideContext) -> SetupGuideSection:
    return SetupGuideSection(
        title="Scenario: TUIC (QUIC)",
        steps=H.merge(
            H.arch("QUIC TUIC"),
            H.phase(1, "VPS"),
            H.steps_vps_purchase(v),
            [f"  ufw allow {v.port}/udp"],
            H.phase(2, "Inbound"),
            [
                f"  Marzban/sing-box port {v.port}",
                f"  UUID {v.uuid}",
            ],
            H.phase(3, "Verify"),
            H.steps_verify(v),
        ),
    )
