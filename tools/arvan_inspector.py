"""ArvanCloud inspector — POP, route, ASN, cache hints."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

import httpx

from dns_analyzer.resolver import analyze_dns, reverse_dns
from network.cdn_detector import detect_cdn, lookup_ip_intelligence
from tools.ip_probe import probe_host, resolve_host
from tools.output_labels import HEURISTIC, MEASURED
from utils.helpers import is_ip_address

_HTTP = {"timeout": 12.0, "trust_env": False, "follow_redirects": True}

ARVAN_ASNS = ("AS202468", "AS50810", "202468", "50810")
ARVAN_KEYWORDS = ("arvan", "arvancloud", "afranet", "parspack")


async def inspect_arvan(
    domain: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    domain = domain.strip().lower()
    if not domain or is_ip_address(domain):
        return "Enter a domain on Arvan (or suspected Arvan front)."

    if progress:
        progress(f"DNS {domain}...")
    dns = await analyze_dns(domain)
    ips = list(dns.all_resolved_ips or dns.a_records or [])

    lines = [
        "ArvanCloud Inspector",
        "═" * 58,
        "",
        f"  Domain: {domain}",
        "",
        "── DNS ──",
        f"  A      : {', '.join(ips) or 'none'}",
        f"  CNAME  : {', '.join(dns.cname_records) or 'none'}",
        f"  TTL    : {dns.ttl or '—'}",
    ]

    arvan_dns = any(
        any(k in (c or "").lower() for k in ARVAN_KEYWORDS)
        for c in (dns.cname_records or [])
    )
    if arvan_dns:
        lines.append("  ✓ Arvan CNAME pattern detected")

    if not ips:
        ip = await resolve_host(domain)
        if ip:
            ips = [ip]

    headers_seen: dict[str, str] = {}
    if ips:
        lines.extend(["", "── Edge IP analysis ──"])
        for ip in ips[:4]:
            if progress:
                progress(f"Analyze {ip}...")
            ptr = await reverse_dns(ip)
            intel = await lookup_ip_intelligence(ip, ptr)
            cdn, conf = detect_cdn(ip, intel.organization or intel.isp, ptr, intel.asn)
            asn = (intel.asn or "").upper()
            is_arvan = any(a.replace("AS", "") in asn for a in ARVAN_ASNS) or (
                cdn and "arvan" in cdn.lower()
            )
            lines.append(f"  IP {ip}")
            lines.append(f"    ASN  : {intel.asn or '—'}  {'[Arvan]' if is_arvan else ''}")
            lines.append(f"    Org  : {intel.organization or intel.isp or '—'}")
            lines.append(f"    CDN  : {cdn or 'none'} {HEURISTIC}")
            lines.append(f"    rDNS : {', '.join(ptr[:2]) if ptr else 'none'}")

    if progress:
        progress("HTTP headers...")
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.head(f"https://{domain}")
            for h in ("server", "x-cache", "x-cdn", "x-arvan", "x-sid", "via", "cf-ray"):
                if h in r.headers:
                    headers_seen[h] = r.headers[h]
    except Exception as exc:
        lines.extend(["", f"  HTTP probe failed: {exc}"])

    if headers_seen:
        lines.extend(["", f"── HTTP headers {MEASURED} ──"])
        for k, v in headers_seen.items():
            lines.append(f"  {k}: {v[:100]}")

    if progress and ips:
        progress("Route probe...")
        probe = await probe_host(domain, port=443, samples=4)
        lines.extend([
            "",
            f"── Route from your network {MEASURED} ──",
            f"  Avg / P95  : {probe.avg_ms or '—'} / {probe.p95_ms or '—'} ms",
            f"  Loss       : {probe.packet_loss_pct:.0f}%",
            f"  Score      : {probe.score}/100",
        ])

    lines.extend([
        "",
        "  Arvan POP codes appear in panel/docs — not always in public HTTP headers.",
        "  Confirm in Arvan dashboard: CDN → domain → DNS orange cloud.",
    ])
    return "\n".join(lines)


def inspect_arvan_sync(**kwargs) -> str:
    return asyncio.run(inspect_arvan(**kwargs))
