"""GeoDNS analyzer — compare DNS answers across resolvers."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from dns_analyzer.resolver import reverse_dns
from tools.dns_propagation import RESOLVERS, _doh_a, _local_a
from tools.output_labels import MEASURED
from utils.helpers import is_ip_address


async def analyze_geodns(
    hostname: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    hostname = hostname.strip().lower()
    if not hostname or is_ip_address(hostname):
        return "Enter a domain name."

    lines = [
        "GeoDNS Analyzer",
        "═" * 58,
        "",
        f"  Domain: {hostname}",
        f"  Compares resolver answers {MEASURED} — different sets may indicate GeoDNS or ISP rewrite.",
        "",
        f"  {'Resolver':<18} {'Unique A records'}",
        "  " + "─" * 50,
    ]

    all_sets: list[frozenset[str]] = []
    resolver_names: list[str] = []
    for name, url in RESOLVERS.items():
        if progress:
            progress(f"Query {name}...")
        if url is None:
            ips = await _local_a(hostname)
        else:
            ips = await _doh_a(hostname, url)
        uniq = sorted(set(ips))
        lines.append(f"  {name:<18} {', '.join(uniq) or 'none'}")
        if uniq:
            all_sets.append(frozenset(uniq))
            resolver_names.append(name)

    lines.extend(["", "── Geo / routing hints ──"])
    if not all_sets:
        lines.append("  No A records from any resolver.")
    elif len({s for s in all_sets}) == 1:
        lines.append("  ✓ All resolvers return same A set — no GeoDNS split detected")
    else:
        lines.append("  ⚠ Resolver-specific A records — possible GeoDNS or regional anycast")
        for i, s in enumerate(all_sets):
            others = set().union(*(all_sets[:i] + all_sets[i + 1:]))
            only = set(s) - others
            if only:
                lines.append(f"    Only on {resolver_names[i]}: {', '.join(sorted(only))}")

    if progress and all_sets:
        progress("Reverse DNS on first IP...")
    first_ip = next(iter(all_sets[0])) if all_sets else None
    if first_ip:
        ptr = await reverse_dns(first_ip)
        lines.extend(["", "── Sample IP rDNS ──", f"  {first_ip} → {', '.join(ptr) or 'none'}"])

    return "\n".join(lines)


def analyze_geodns_sync(**kwargs) -> str:
    return asyncio.run(analyze_geodns(**kwargs))
