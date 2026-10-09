"""How to Run tab — orchestration and English content via how_to_run_fa."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from backend.deployment_guide import GuideContext, _effective_transport, _primary_guess
from backend.models import (
    DeploymentSetupGuide,
    ProtocolType,
    SetupGuideSection,
    TransportType,
)
from utils.helpers import is_ip_address


@dataclass(frozen=True)
class RunValues:
    domain: str
    link_address: str
    origin_ip: str
    port: int
    path: str
    host_header: str
    sni: str
    transport: TransportType
    protocol: ProtocolType
    uuid: str
    flow: str
    service_name: str
    public_key: str
    short_id: str
    fingerprint: str
    alpn: str
    cdn_type: str
    behind_cdn: bool
    needs_reverse_proxy: bool
    panel_detected: str


def _ph(label: str) -> str:
    return f"<{label}>"


def _resolve_values(ctx: GuideContext) -> RunValues:
    c, d, dns, conn = ctx.config, ctx.deployment, ctx.dns, ctx.connectivity
    transport = _effective_transport(c)

    domain = c.sni or c.host or dns.hostname or ""
    if not domain or is_ip_address(domain):
        domain = _ph("your-domain")

    origin = d.real_server_ip or ""
    if not origin and is_ip_address(c.address) and not d.cdn_type:
        origin = c.address
    if not origin:
        origin = _ph("origin-vps-ip")

    path = c.path or "/"
    host = c.host or c.sni or (domain if not domain.startswith("<") else _ph("Host-header"))
    sni = c.sni or (domain if not domain.startswith("<") else _ph("SNI"))

    return RunValues(
        domain=domain,
        link_address=c.address,
        origin_ip=origin,
        port=c.port,
        path=path,
        host_header=host,
        sni=sni,
        transport=transport,
        protocol=c.protocol,
        uuid=c.uuid or _ph("panel-uuid"),
        flow=c.flow or "",
        service_name=c.service_name or _ph("serviceName"),
        public_key=c.public_key or _ph("PublicKey-from-xray-x25519"),
        short_id=c.short_id if c.short_id is not None else _ph("ShortId"),
        fingerprint=c.fingerprint or "chrome",
        alpn=c.alpn or "h2,http/1.1",
        cdn_type=d.cdn_type or "",
        behind_cdn=bool(d.cdn_type),
        needs_reverse_proxy=transport in (
            TransportType.WS, TransportType.GRPC, TransportType.XHTTP, TransportType.HTTPUPGRADE,
        ) and not (conn.http_panel_detected and not conn.http_reverse_proxy),
        panel_detected=conn.http_panel_detected or "3x-ui (MHSanaei)",
    )


def _pick_primary_tunnel_id(ctx: GuideContext) -> tuple[str, float, str]:
    ta = ctx.tunnel_analysis
    if ta and ta.primary_tunnel_id:
        return ta.primary_tunnel_id, ta.primary_confidence, ta.primary_type or ta.primary_tunnel_id
    if ta and ta.detected_types:
        top = max(ta.detected_types, key=lambda m: m.confidence)
        return top.tunnel_id, top.confidence, top.name
    guess_name, conf, _ = _primary_guess(ctx)
    tid_map = {
        "Arvan CDN": "arvan_cdn",
        "Cloudflare CDN": "cloudflare_cdn",
        "CDN Fronted": "cdn_fronting",
        "Direct VPS": "direct_vps",
        "Reverse Proxy": "reverse_proxy",
    }
    return tid_map.get(guess_name, "direct_vps"), conf, guess_name


def _primary_scenario_section(
    ctx: GuideContext,
    v: RunValues,
    tid: str,
    builders: dict[str, Callable],
) -> SetupGuideSection:
    from backend import how_to_run_fa as fa

    if ctx.config.reality:
        return fa.section_reality(v, ctx)
    builder = builders.get(tid)
    if builder:
        return builder(v, ctx)
    return fa.section_direct_vps(v, ctx)


def build_how_to_run_sections(ctx: GuideContext) -> list[SetupGuideSection]:
    from backend import how_to_run_fa as fa

    v = _resolve_values(ctx)
    tid, conf, scenario_label = _pick_primary_tunnel_id(ctx)
    primary = _primary_scenario_section(ctx, v, tid, fa.SCENARIO_SECTIONS_FA)

    return [
        SetupGuideSection(title="Introduction", steps=fa.intro_lines(v, scenario_label, conf)),
        primary,
        fa.section_checklist(v),
    ]


def render_how_to_run(sections: list[SetupGuideSection]) -> str:
    lines: list[str] = []
    for sec in sections:
        lines.extend(["", f"── {sec.title} ──", ""])
        for step in sec.steps:
            lines.append(step)
    return "\n".join(lines).strip()


def attach_how_to_run(guide: DeploymentSetupGuide, ctx: GuideContext) -> DeploymentSetupGuide:
    sections = build_how_to_run_sections(ctx)
    return guide.model_copy(update={
        "how_to_run_sections": sections,
        "how_to_run_text": render_how_to_run(sections),
    })
