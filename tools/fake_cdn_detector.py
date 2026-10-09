"""Fake CDN detector — CDN claim vs actual IP classification."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from dns_analyzer.resolver import analyze_dns, reverse_dns
from network.cdn_detector import detect_cdn, lookup_ip_intelligence
from tools.ip_probe import resolve_host
from utils.helpers import is_ip_address


async def detect_fake_cdn(
    domain: str,
    claimed_cdn: str = "Cloudflare",
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    domain = domain.strip().lower()
    if not domain or is_ip_address(domain):
        return "Enter a domain name (front domain / SNI)."

    if progress:
        progress(f"Analyzing {domain}...")
    dns = await analyze_dns(domain)
    ips = list(dns.all_resolved_ips or dns.a_records or [])
    if not ips:
        ip = await resolve_host(domain)
        if ip:
            ips = [ip]

    if not ips:
        return f"No IPs resolved for {domain}"

    lines = [
        "Fake CDN Detector",
        "═" * 58,
        "",
        f"  Domain       : {domain}",
        f"  Expected CDN : {claimed_cdn}",
        "",
    ]

    if dns.cname_records:
        lines.append("── CNAME chain ──")
        for c in dns.cname_records:
            lines.append(f"  {c}")
        lines.append("")

    real_cdn_hits = 0
    origin_hits = 0
    reverse_proxy_hints = 0

    for ip in ips[:6]:
        if progress:
            progress(f"Checking {ip}...")
        ptr = await reverse_dns(ip)
        intel = await lookup_ip_intelligence(ip, ptr)
        cdn, conf = detect_cdn(ip, intel.organization or intel.isp, ptr, intel.asn)

        lines.append(f"── IP {ip} ──")
        lines.append(f"  ASN  : {intel.asn or '—'}")
        lines.append(f"  Org  : {intel.organization or intel.isp or '—'}")
        lines.append(f"  rDNS : {', '.join(ptr[:2]) if ptr else 'none'}")
        lines.append(f"  Detected CDN: {cdn or 'none'} (heuristic {conf * 100:.0f}%)")

        claimed_match = cdn and claimed_cdn.lower() in cdn.lower()
        if claimed_match and conf >= 0.55:
            real_cdn_hits += 1
            lines.append("  → Matches claimed CDN ✓")
        elif intel.is_datacenter and not cdn:
            origin_hits += 1
            lines.append("  → Direct datacenter/VPS — NOT a CDN edge")
        elif cdn and not claimed_match:
            lines.append(f"  → Different CDN ({cdn}) — config may be mislabeled")
        else:
            reverse_proxy_hints += 1
            lines.append("  → Unknown / possible reverse proxy")

        # SNI split hint
        if ptr and any(k in " ".join(ptr).lower() for k in ("nginx", "caddy", "apache")):
            lines.append("  ⚠ rDNS suggests reverse proxy on origin")
        lines.append("")

    lines.append("── Verdict ──")
    if real_cdn_hits == len(ips[:6]) and real_cdn_hits > 0:
        lines.append(f"  ✓ Real {claimed_cdn} CDN — IPs match CDN signatures")
    elif origin_hits >= len(ips[:6]) // 2 + 1:
        lines.append("  ✗ Fake CDN — domain resolves to VPS/datacenter, not CDN edge")
        lines.append("  → Client connects directly to origin; SNI camouflage only")
    elif reverse_proxy_hints:
        lines.append("  ⚠ Inconclusive — may be reverse proxy or mixed setup")
    else:
        lines.append("  ⚠ Partial CDN — verify orange-cloud / CDN panel settings")

    lines.extend([
        "",
        "  Compare link IP vs DNS A record — mismatch often means fake CDN front.",
    ])
    return "\n".join(lines)


def detect_fake_cdn_sync(**kwargs) -> str:
    return asyncio.run(detect_fake_cdn(**kwargs))
