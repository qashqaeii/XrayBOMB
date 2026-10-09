"""DNS health tool — local vs DoH, Iran filtering hints."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from dns_analyzer.resolver import analyze_dns, reverse_dns
from utils.helpers import is_ip_address


async def analyze_dns_health(
    hostname: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    hostname = hostname.strip().lower()
    if not hostname or is_ip_address(hostname):
        return "Enter a domain name (not an IP)."

    if progress:
        progress(f"Querying DNS for {hostname}...")
    dns = await analyze_dns(hostname)

    lines = [
        f"DNS Health — {hostname}",
        "═" * 52,
        "",
        f"  TTL        : {dns.ttl or 'N/A'}",
        f"  DNSSEC     : {dns.dnssec if dns.dnssec is not None else 'N/A'}",
        "",
        "── Records ──",
        f"  A          : {', '.join(dns.a_records) or 'none'}",
        f"  AAAA       : {', '.join(dns.aaaa_records) or 'none'}",
        f"  CNAME      : {', '.join(dns.cname_records) or 'none'}",
        f"  MX         : {', '.join(dns.mx_records[:3]) or 'none'}",
    ]

    if dns.all_resolved_ips:
        if progress:
            progress("Reverse DNS + CDN check...")
        lines.append("")
        lines.append("── Resolved IPs ──")
        for rip in dns.all_resolved_ips[:6]:
            lines.append(f"  {rip}")
        ptr = await reverse_dns(dns.all_resolved_ips[0])
        lines.append("")
        lines.append("── Reverse DNS ──")
        lines.append(f"  {dns.all_resolved_ips[0]} → {', '.join(ptr) or 'none'}")

    if getattr(dns, "txt_records", None):
        lines.extend(["", "── TXT ──"])
        for txt in (dns.txt_records or [])[:5]:
            lines.append(f"  {txt[:120]}")

    # CDN hint from nameservers in errors or common patterns
    ns_hint = ""
    for rec in (dns.cname_records or []):
        low = rec.lower()
        if "cloudflare" in low:
            ns_hint = "Cloudflare (CNAME)"
        elif "arvan" in low:
            ns_hint = "Arvan Cloud (CNAME)"
    if ns_hint:
        lines.extend(["", "── CDN hint ──", f"  {ns_hint}"])

    if dns.doh_results:
        lines.extend(["", "── DoH comparison (filtering check) ──"])
        local_a = set(dns.a_records)
        poison = False
        for provider, ips in dns.doh_results.items():
            lines.append(f"  {provider:<12}: {', '.join(ips) or 'none'}")
            if ips and set(ips) != local_a:
                poison = True
        lines.extend(["", "── Iran filtering analysis ──"])
        if poison:
            lines.append("  ⚠ Local DNS differs from DoH — possible ISP DNS filtering/poisoning.")
            lines.append("  → Use DoH on client or Cloudflare DNS-only with clean IP.")
        else:
            lines.append("  ✓ Local and DoH records match (no obvious DNS tampering).")

    if dns.errors:
        lines.extend(["", "── Errors ──"])
        for e in dns.errors:
            lines.append(f"  • {e}")

    lines.extend([
        "",
        "── Tips (Iran) ──",
        "  • For CF clean IP: set A record after Clean IP Finder scan.",
        "  • Low TTL (300) helps when swapping IPs during filtering.",
        "  • CNAME to CDN is normal — check proxied vs DNS-only mode.",
    ])
    return "\n".join(lines)


def analyze_dns_health_sync(**kwargs) -> str:
    return asyncio.run(analyze_dns_health(**kwargs))
