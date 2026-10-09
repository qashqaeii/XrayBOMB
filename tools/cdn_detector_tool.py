"""CDN detector tool — identify CDN from domain or IP."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from dns_analyzer.resolver import analyze_dns, reverse_dns
from network.cdn_detector import detect_cdn, lookup_ip_intelligence
from tools.ip_probe import resolve_host
from tools.output_labels import HEURISTIC
from utils.helpers import is_ip_address


async def detect_cdn_for_target(
    target: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    target = target.strip().lower()
    if not target:
        return "Enter a domain or IP address."

    lines = [
        "CDN Detector",
        "═" * 58,
        "",
        "  Detection uses ASN/rDNS/CIDR heuristics — not packet capture.",
        "",
        f"  Target: {target}",
        "",
    ]

    ips: list[str] = []
    cnames: list[str] = []

    if is_ip_address(target):
        ips = [target]
    else:
        if progress:
            progress(f"Resolving {target}...")
        dns = await analyze_dns(target)
        ips = list(dns.all_resolved_ips or dns.a_records or [])
        cnames = dns.cname_records or []
        if cnames:
            lines.extend(["── DNS CNAME ──"])
            for c in cnames[:5]:
                lines.append(f"  {c}")
            lines.append("")

    if not ips:
        ip = await resolve_host(target)
        if ip:
            ips = [ip]

    if not ips:
        return "\n".join(lines + ["  No IPs resolved."])

    lines.append("── Detection results ──")
    detected: dict[str, float] = {}

    for ip in ips[:8]:
        if progress:
            progress(f"Analyzing {ip}...")
        ptr = await reverse_dns(ip)
        info = await lookup_ip_intelligence(ip, ptr)
        cdn, conf = detect_cdn(
            ip,
            info.organization or info.isp,
            ptr or cnames,
            info.asn,
        )
        ptr_str = ", ".join(ptr[:2]) if ptr else "none"
        lines.append(f"  IP       : {ip}")
        lines.append(f"  ASN      : {info.asn or '—'}")
        lines.append(f"  Org      : {info.organization or info.isp or '—'}")
        lines.append(f"  rDNS     : {ptr_str}")
        if cdn:
            lines.append(f"  CDN      : {cdn} (heuristic {conf * 100:.0f}%)")
            detected[cdn] = max(detected.get(cdn, 0), conf)
        else:
            lines.append("  CDN      : none detected (likely origin / VPS)")
        if info.is_datacenter:
            lines.append(f"  DC       : {info.datacenter or 'datacenter/hosting'}")
        lines.append("")

    lines.append("── Summary ──")
    if detected:
        best = max(detected, key=detected.get)
        lines.append(f"  Primary CDN: {best} (heuristic {detected[best] * 100:.0f}%)")
        others = [c for c in detected if c != best]
        if others:
            lines.append(f"  Also seen  : {', '.join(others)}")
    else:
        lines.append("  No CDN signature — direct origin or unknown provider")

    lines.extend([
        "",
        "  Supported: Cloudflare, ArvanCloud, Akamai, Fastly, CloudFront, Bunny, Gcore",
    ])
    return "\n".join(lines)


def detect_cdn_for_target_sync(**kwargs) -> str:
    return asyncio.run(detect_cdn_for_target(**kwargs))
