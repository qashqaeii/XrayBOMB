"""Anycast vs unicast detector — repeated DNS resolution."""

from __future__ import annotations

import asyncio
import socket
from typing import Callable, Optional

import dns.asyncresolver

from dns_analyzer.resolver import _doh_lookup
from tools.output_labels import MEASURED
from utils.helpers import is_ip_address


async def _resolve_many(hostname: str, rounds: int) -> list[str]:
    ips: list[str] = []
    resolver = dns.asyncresolver.Resolver()
    for _ in range(rounds):
        try:
            ans = await resolver.resolve(hostname, "A")
            ips.extend(str(r) for r in ans)
        except Exception:
            pass
        await asyncio.sleep(0.05)
    return ips


async def detect_anycast(
    hostname: str,
    rounds: int = 10,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    hostname = hostname.strip().lower()
    if not hostname or is_ip_address(hostname):
        return "Enter a domain name (not a bare IP)."

    if progress:
        progress(f"Resolving {hostname} × {rounds}...")
    local_ips = await _resolve_many(hostname, rounds)
    unique_local = sorted(set(local_ips))

    if progress:
        progress("DoH resolution...")
    doh = await _doh_lookup(hostname)
    doh_sets = {k: sorted(set(v)) for k, v in doh.items()}

    lines = [
        "Anycast Detector",
        "═" * 58,
        "",
        f"  Domain : {hostname}",
        f"  Rounds : {rounds} (system resolver) {MEASURED}",
        "",
        "── System resolver ──",
        f"  Total answers : {len(local_ips)}",
        f"  Unique IPs    : {len(unique_local)}",
    ]
    for ip in unique_local[:12]:
        cnt = local_ips.count(ip)
        lines.append(f"    {ip}  (seen {cnt}×)")
    if len(unique_local) > 12:
        lines.append(f"    ... +{len(unique_local) - 12} more")

    lines.append("")
    lines.append("── DoH resolvers ──")
    for prov, ips in doh_sets.items():
        lines.append(f"  {prov:<12}: {', '.join(ips) or 'none'} ({len(ips)} unique)")

    lines.extend(["", "── Analysis ──"])
    if len(unique_local) > 1:
        lines.append("  ✓ Multiple A records / rotating answers → anycast or load-balanced CDN likely")
    elif len(unique_local) == 1:
        lines.append("  • Single stable A → unicast or fixed origin (common for VPS)")
    else:
        lines.append("  ✗ No A records from system resolver")

    doh_unique = set()
    for ips in doh_sets.values():
        doh_unique.update(ips)
    if doh_unique and unique_local and doh_unique != set(unique_local):
        lines.append("  ⚠ System vs DoH differ — GeoDNS, ISP rewrite, or resolver split")

    lines.extend([
        "",
        "  Anycast cannot be confirmed without routing to each IP separately.",
        "  Use MTR Visualizer on each unique IP for path comparison.",
    ])
    return "\n".join(lines)


def detect_anycast_sync(**kwargs) -> str:
    return asyncio.run(detect_anycast(**kwargs))
