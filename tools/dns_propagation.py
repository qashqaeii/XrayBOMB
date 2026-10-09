"""DNS propagation monitor — compare resolvers."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

import dns.asyncresolver
import httpx

from utils.helpers import is_ip_address

RESOLVERS = {
    "System (local)": None,
    "Cloudflare DoH": "https://cloudflare-dns.com/dns-query",
    "Google DoH": "https://dns.google/resolve",
    "Quad9 DoH": "https://dns.quad9.net:5053/dns-query",
    "OpenDNS DoH": "https://doh.opendns.com/dns-query",
}


async def _local_a(hostname: str) -> list[str]:
    try:
        answers = await dns.asyncresolver.Resolver().resolve(hostname, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


async def _doh_a(hostname: str, base_url: str) -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=10, trust_env=False) as client:
            if "resolve" in base_url:
                url = f"{base_url}?name={hostname}&type=A"
                r = await client.get(url, headers={"Accept": "application/dns-json"})
                data = r.json()
                return [a.get("data", "") for a in data.get("Answer", []) if a.get("type") == 1]
            url = f"{base_url}?name={hostname}&type=A"
            r = await client.get(url, headers={"Accept": "application/dns-json"})
            data = r.json()
            return [a.get("data", "") for a in data.get("Answer", []) if a.get("type") == 1]
    except Exception:
        return []


async def monitor_dns_propagation(
    hostname: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    hostname = hostname.strip().lower()
    if not hostname or is_ip_address(hostname):
        return "Enter a domain name."

    lines = [
        "DNS Propagation Monitor",
        "═" * 58,
        "",
        f"  Domain: {hostname}",
        "",
        f"  {'Resolver':<18} {'A records'}",
        "  " + "─" * 50,
    ]

    all_sets: list[set[str]] = []
    for name, url in RESOLVERS.items():
        if progress:
            progress(f"Querying {name}...")
        if url is None:
            ips = await _local_a(hostname)
        else:
            ips = await _doh_a(hostname, url)
        lines.append(f"  {name:<18} {', '.join(ips) or 'none'}")
        if ips:
            all_sets.append(set(ips))

    lines.extend(["", "── Analysis ──"])
    if not all_sets:
        lines.append("  No A records from any resolver.")
    elif len({frozenset(s) for s in all_sets}) == 1:
        lines.append("  ✓ All resolvers agree — fully propagated / consistent")
    else:
        lines.append("  ⚠ Resolver mismatch — propagation in progress or ISP rewrite")
        lines.append("  → Compare with DNS Health for Iran filtering diagnosis")

    return "\n".join(lines)


def monitor_dns_propagation_sync(**kwargs) -> str:
    return asyncio.run(monitor_dns_propagation(**kwargs))
