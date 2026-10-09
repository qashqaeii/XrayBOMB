"""National CDN analyzer — Arvan, Afranet, Asiatech, Pars Online patterns."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from dns_analyzer.resolver import analyze_dns, reverse_dns
from network.cdn_detector import detect_cdn, lookup_ip_intelligence
from tools.ip_probe import resolve_host
from tools.output_labels import HEURISTIC
from utils.helpers import is_ip_address

NATIONAL_CDN_SIGNATURES: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("Arvan Cloud (ابر آروان)", ("arvan", "arvancloud"), ("AS202468", "202468")),
    ("Afranet / Efranet", ("afranet", "efranet"), ("AS25184", "25184")),
    ("Asiatech", ("asiatech",), ("AS25184", "16322")),
    ("Pars Online / Parspack", ("parsonline", "parspack", "pars"), ("AS16322",)),
    ("Hostiran", ("hostiran",), ()),
    ("IRCDN / Respina", ("respina", "ircdn"), ()),
)


def _match_national(name: str, keywords: tuple[str, ...], asns: tuple[str, ...], blob: str, asn: str) -> bool:
    if any(k in blob for k in keywords):
        return True
    asn_n = asn.upper().replace("AS", "")
    return any(a.replace("AS", "") == asn_n for a in asns)


async def analyze_national_cdn(
    target: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    target = target.strip().lower()
    if not target:
        return "Enter domain or IP."

    lines = [
        "National CDN Analyzer",
        "═" * 58,
        "",
        f"  Target: {target}",
        f"  Detection: DNS CNAME/NS + ASN/org heuristics {HEURISTIC}",
        "",
    ]

    cnames: list[str] = []
    ns_hints: list[str] = []
    ips: list[str] = []

    if is_ip_address(target):
        ips = [target]
    else:
        if progress:
            progress(f"DNS {target}...")
        dns = await analyze_dns(target)
        ips = list(dns.all_resolved_ips or dns.a_records or [])
        cnames = dns.cname_records or []
        for c in cnames:
            low = c.lower()
            for label, kws, _ in NATIONAL_CDN_SIGNATURES:
                if any(k in low for k in kws):
                    ns_hints.append(f"{label} (CNAME: {c})")

    if not ips:
        ip = await resolve_host(target)
        if ip:
            ips = [ip]

    if cnames:
        lines.extend(["── CNAME ──"])
        for c in cnames:
            lines.append(f"  {c}")
        lines.append("")

    detected: list[str] = list(ns_hints)

    for ip in ips[:6]:
        if progress:
            progress(f"Check {ip}...")
        ptr = await reverse_dns(ip)
        intel = await lookup_ip_intelligence(ip, ptr)
        blob = f"{intel.organization} {intel.isp} {' '.join(ptr)}".lower()
        asn = intel.asn or ""
        for label, kws, asn_list in NATIONAL_CDN_SIGNATURES:
            if _match_national(label, kws, asn_list, blob, asn):
                if label not in detected:
                    detected.append(label)
        cdn, _ = detect_cdn(ip, intel.organization, ptr, asn)
        lines.append(f"  IP {ip}  ASN {intel.asn or '—'}  CDN:{cdn or 'none'}")

    lines.extend(["", "── Detected national CDN / hosting ──"])
    if detected:
        for d in detected:
            lines.append(f"  ✓ {d}")
    else:
        lines.append("  None — likely foreign CDN or direct VPS")

    lines.extend([
        "",
        "  IR national CDNs are for in-country landing — not a substitute for EU origin.",
        "  Pair with Fake CDN Detector if front domain claims Cloudflare.",
    ])
    return "\n".join(lines)


def analyze_national_cdn_sync(**kwargs) -> str:
    return asyncio.run(analyze_national_cdn(**kwargs))
