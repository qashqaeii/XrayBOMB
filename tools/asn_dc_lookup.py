"""ASN and datacenter identification — live lookup only."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

import httpx

from backend.intelligence import analyze_threat_intel
from dns_analyzer.resolver import reverse_dns
from network.cdn_detector import lookup_ip_intelligence
from network.geo import lookup_geo_ip
from tools.datacenter_registry import identify_provider
from tools.ip_probe import resolve_host

_HTTP = {"timeout": 12.0, "trust_env": False, "follow_redirects": True}


async def _ipwho(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get(f"https://ipwho.is/{ip}")
            r.raise_for_status()
            data = r.json()
            if data.get("success"):
                return data
    except Exception:
        pass
    return {}


async def lookup_asn_dc(
    target: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    target = target.strip()
    if not target:
        return "Enter IP or hostname."

    if progress:
        progress(f"Resolving {target}...")
    ip = await resolve_host(target)
    if not ip:
        return f"Resolution failed: {target}"

    if progress:
        progress("Fetching network identity (ipwho.is + geo)...")
    who, geo, intel = await asyncio.gather(
        _ipwho(ip),
        lookup_geo_ip(ip, refresh=True),
        lookup_ip_intelligence(ip, {}),
    )
    threat = analyze_threat_intel(intel)
    ptr = await reverse_dns(ip)

    conn = who.get("connection") or {}
    asn_raw = conn.get("asn") or geo.get("asn") or intel.asn or ""
    isp = conn.get("isp") or geo.get("isp") or intel.isp or ""
    org = conn.get("org") or geo.get("organization") or ""
    providers = identify_provider(asn=str(asn_raw), isp=isp, org=org)

    lines = [
        "ASN & Datacenter Identifier",
        "═" * 58,
        "",
        f"  Input        : {target}",
        f"  IPv4         : {ip}",
        "",
        "── ipwho.is ──",
        f"  Country      : {who.get('country', '-')} ({who.get('country_code', '?')})",
        f"  Region/City  : {who.get('region', '-')} / {who.get('city', '-')}",
        f"  ASN          : {conn.get('asn', '-')}",
        f"  ISP          : {conn.get('isp', '-')}",
        f"  Org          : {conn.get('org', '-')}",
        f"  Domain       : {conn.get('domain', '-')}",
        "",
        "── Geo fallback ──",
        f"  Source       : {geo.get('source', 'none')}",
        f"  ISP          : {geo.get('isp', '-')}",
        f"  ASN          : {geo.get('asn', '-')}",
        "",
        "── Hosting classification ──",
        f"  Datacenter   : {intel.is_datacenter or threat.is_datacenter}",
        f"  CDN          : {intel.cdn_detected or 'none'}",
        f"  Hosting      : {getattr(intel, 'is_hosting', '-')}",
        f"  Blocklists   : {', '.join(threat.blocklist_hits) or 'none'}",
        f"  PTR          : {', '.join(ptr) or 'none'}",
        "",
        "── Provider catalog match ──",
    ]
    if providers:
        for p in providers:
            role = "tunnel origin" if p.tunnel_origin else ("CDN" if p.cdn_front else p.category)
            lines.append(f"  • {p.name} — {role}")
    else:
        lines.append("  • No match in VPS/CDN catalog")

    lines.extend([
        "",
        "── Tunnel use hint ──",
    ])
    if threat.blocklist_hits:
        lines.append("  BLOCKLISTED — replace IP before deploying tunnel.")
    elif intel.cdn_detected:
        lines.append(f"  CDN edge ({intel.cdn_detected}) — not a typical VPS origin.")
    elif intel.is_datacenter or threat.is_datacenter:
        lines.append("  Datacenter IP — suitable as VPS/tunnel origin if ports open.")
    else:
        lines.append("  Classification uncertain — run VPS Pre-Deploy Validator.")
    lines.append("")
    return "\n".join(lines)


def lookup_asn_dc_sync(**kwargs) -> str:
    return asyncio.run(lookup_asn_dc(**kwargs))
