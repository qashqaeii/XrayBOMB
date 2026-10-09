"""DNSSEC validator — DS/DNSKEY presence and resolver validation."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

import dns.asyncresolver
import dns.flags

from tools.output_labels import MEASURED
from utils.helpers import is_ip_address


async def _query(hostname: str, rdtype: str) -> list[str]:
    try:
        ans = await dns.asyncresolver.Resolver().resolve(hostname, rdtype)
        return [str(r) for r in ans]
    except Exception:
        return []


async def validate_dnssec(
    hostname: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    hostname = hostname.strip().lower().rstrip(".")
    if not hostname or is_ip_address(hostname):
        return "Enter a domain name."

    lines = [
        "DNSSEC Validator",
        "═" * 58,
        "",
        f"  Domain: {hostname}",
        f"  Checks via system resolver {MEASURED}",
        "",
    ]

    if progress:
        progress("Query DS/DNSKEY...")
    ds = await _query(hostname, "DS")
    dnskey = await _query(hostname, "DNSKEY")

    lines.extend([
        "── Records ──",
        f"  DS records   : {len(ds)}",
        f"  DNSKEY       : {len(dnskey)}",
    ])
    if ds:
        lines.append(f"  DS sample    : {ds[0][:100]}")
    if dnskey:
        lines.append(f"  DNSKEY sample: {dnskey[0][:100]}")

    lines.extend(["", "── Validation ──"])
    if ds or dnskey:
        lines.append("  ✓ DNSSEC signing data present (DS or DNSKEY at zone)")
    else:
        lines.append("  ✗ No DS/DNSKEY — zone likely unsigned from this resolver's view")

    try:
        if progress:
            progress("Validate A with EDNS DO bit...")
        resolver = dns.asyncresolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)
        await resolver.resolve(hostname, "A")
        lines.append("  ✓ A record OK with DO — resolver did not mark response BOGUS")
    except Exception as exc:
        msg = str(exc).lower()
        if "bogus" in msg:
            lines.append(f"  ✗ BOGUS DNSSEC chain: {exc}")
        elif "nxdomain" in msg:
            lines.append("  ✗ NXDOMAIN")
        else:
            lines.append(f"  • Note: {exc}")

    lines.extend([
        "",
        "  Full chain trust depends on your resolver's trust anchor configuration.",
    ])
    return "\n".join(lines)


def validate_dnssec_sync(**kwargs) -> str:
    return asyncio.run(validate_dnssec(**kwargs))
