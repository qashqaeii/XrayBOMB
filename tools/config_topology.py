"""Config topology mapper — infrastructure detection from config text."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.config_parser import parse_input
from backend.security import build_reproduction_guide
from backend.tunnel_detection import TUNNEL_CATALOG
from dns_analyzer.resolver import analyze_dns
from network.cdn_detector import lookup_ip_intelligence
from tools.datacenter_registry import identify_provider
from tools.ip_probe import resolve_host
from utils.helpers import is_ip_address


async def map_config_topology(
    text: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    text = text.strip()
    if not text:
        return "Paste share link(s) or Xray JSON."

    if progress:
        progress("Parsing...")
    configs = parse_input(text)
    if not configs:
        return "No configs parsed."

    c = configs[0]
    lines = [
        "Xray Infrastructure Mapper",
        "═" * 58,
        "",
        f"  Protocol : {c.protocol.value if c.protocol else '—'}",
        f"  Address  : {c.address}:{c.port}",
        f"  Transport: {c.transport_type.value if c.transport_type else '—'}",
        f"  Security : {'REALITY' if c.reality else ('TLS' if c.tls else 'none')}",
        "",
    ]

    # DNS + IP intelligence
    front = c.sni or c.host or (c.address if not is_ip_address(c.address) else None)
    dns_ips: list[str] = []
    cdn_name = None
    dc_name = None

    if front and not is_ip_address(front):
        if progress:
            progress(f"DNS lookup {front}...")
        dns = await analyze_dns(front)
        dns_ips = list(dns.all_resolved_ips or dns.a_records or [])[:4]
        if dns.cname_records:
            lines.append("── DNS ──")
            for cn in dns.cname_records[:3]:
                lines.append(f"  CNAME: {cn}")
                low = cn.lower()
                if "cloudflare" in low:
                    cdn_name = "Cloudflare"
                elif "arvan" in low:
                    cdn_name = "ArvanCloud"
            lines.append("")

    connect_ip = c.address
    if is_ip_address(c.address):
        probe_ip = c.address
    else:
        if progress:
            progress("Resolving address...")
        probe_ip = await resolve_host(c.address)
        connect_ip = probe_ip or c.address

    if probe_ip and progress:
        progress(f"IP intelligence {probe_ip}...")
    intel = None
    if probe_ip:
        intel = await lookup_ip_intelligence(probe_ip)
        if intel.cdn_detected and intel.cdn_confidence >= 0.55:
            cdn_name = cdn_name or intel.cdn_detected
        providers = identify_provider(asn=intel.asn or "", isp=intel.isp or "", org=intel.organization or "")
        for p in providers:
            if p.tunnel_origin:
                dc_name = p.name
                break
        if not dc_name and intel.is_datacenter:
            dc_name = intel.organization or intel.isp

    # Topology diagram
    lines.extend(["── Detected topology ──", ""])
    client = "Iran User (your network)"
    steps = [client]

    if cdn_name:
        steps.append(cdn_name)
    elif front and dns_ips and not intel:
        steps.append(f"DNS → {', '.join(dns_ips[:2])}")

    if dc_name:
        steps.append(dc_name)
    elif intel and intel.is_datacenter:
        steps.append(intel.organization or "Origin VPS")
    elif probe_ip:
        steps.append(f"Origin ({probe_ip})")

    proto = c.protocol.value.upper() if c.protocol else "Xray"
    if c.reality:
        steps.append(f"Xray REALITY ({proto})")
    else:
        steps.append(f"Xray Core ({proto})")

    for i, node in enumerate(steps):
        if i == 0:
            lines.append(f"  {node}")
        else:
            lines.append("     │")
            lines.append("     ▼")
            lines.append(f"  {node}")

    lines.extend(["", "── Layer summary ──"])
    lines.append(f"  Frontend : {cdn_name or 'none (direct)'}")
    lines.append(f"  Origin   : {dc_name or intel.organization if intel else 'unknown'}")
    if probe_ip:
        lines.append(f"  IP       : {probe_ip}  ASN: {intel.asn if intel else '—'}")
    lines.append(f"  Protocol : {proto} + {c.transport_type.value if c.transport_type else 'tcp'}")
    lines.append(f"  TLS edge : {'REALITY camouflage' if c.reality else ('TLS' if c.tls else 'plain')}")

    # Reproduction guide
    if progress:
        progress("Building reproduction guide...")
    guide = build_reproduction_guide(c)
    lines.extend(["", "── Config Reproduction Engine ──"])
    if guide.reproducible:
        lines.append("")
        lines.append("  Reproducible from link:")
        for item in guide.reproducible[:8]:
            val = f" = {item.value}" if item.value else ""
            lines.append(f"    ✓ {item.field}{val}")
    if guide.not_reproducible:
        lines.append("")
        lines.append("  Server-side only (not in link):")
        for item in guide.not_reproducible[:8]:
            reason = f" — {item.reason}" if item.reason else ""
            lines.append(f"    ✗ {item.field}{reason}")

    # Tunnel catalog hint
    if c.reality:
        cat = TUNNEL_CATALOG.get("reality_camouflage", {})
        if cat:
            lines.extend(["", "── Tunnel type ──", f"  {cat.get('name', 'REALITY')}", f"  {cat.get('flow', '')}"])

    lines.extend([
        "",
        "  Run full analysis in main tab for traceroute + connectivity tests.",
    ])
    return "\n".join(lines)


def map_config_topology_sync(**kwargs) -> str:
    return asyncio.run(map_config_topology(**kwargs))
