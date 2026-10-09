"""Datacenter fingerprint — identify hosting provider from IP."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from network.cdn_detector import lookup_ip_intelligence
from tools.datacenter_registry import REGISTRY, identify_provider
from tools.ip_probe import resolve_host
from utils.helpers import is_ip_address


PROVIDER_NAMES = (
    "OVH", "Hetzner", "Leaseweb", "DigitalOcean", "Contabo",
    "Scaleway", "Vultr", "Linode", "AWS", "Azure",
)


async def fingerprint_datacenter(
    target: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    target = target.strip()
    if not target:
        return "Enter IP or hostname."

    ip = target if is_ip_address(target) else None
    if not ip:
        if progress:
            progress(f"Resolving {target}...")
        ip = await resolve_host(target)
    if not ip:
        return f"Could not resolve: {target}"

    if progress:
        progress(f"Looking up {ip}...")
    intel = await lookup_ip_intelligence(ip)
    matches = identify_provider(
        asn=intel.asn or "",
        isp=intel.isp or "",
        org=intel.organization or "",
    )

    lines = [
        "Datacenter Fingerprint",
        "═" * 58,
        "",
        f"  Target : {target}",
        f"  IP     : {ip}",
        "",
        "── WHOIS / Geo ──",
        f"  ASN         : {intel.asn or '—'}",
        f"  ISP         : {intel.isp or '—'}",
        f"  Organization: {intel.organization or '—'}",
        f"  Country     : {intel.country_code or '—'} {intel.country or ''}",
        f"  City        : {intel.city or '—'}",
        f"  Datacenter  : {'yes' if intel.is_datacenter else 'no'}",
        f"  CDN         : {intel.cdn_detected or 'none'}",
        "",
        "── Registry match ──",
    ]

    if matches:
        for m in matches[:5]:
            role = m.category
            tunnel = "origin OK" if m.tunnel_origin else ("CDN front" if m.cdn_front else "—")
            lines.append(f"  {m.name:<22} [{role}]  tunnel: {tunnel}")
    else:
        lines.append("  No catalog match — may be smaller host or residential")

    lines.extend([
        "",
        "  Run VPS Pre-Deploy Validator after purchase for measured route quality.",
    ])
    return "\n".join(lines)


def fingerprint_datacenter_sync(**kwargs) -> str:
    return asyncio.run(fingerprint_datacenter(**kwargs))
