"""VPS pre-deploy validator — live checks before installing Xray."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.intelligence import analyze_threat_intel
from dns_analyzer.resolver import reverse_dns
from network.cdn_detector import lookup_ip_intelligence
from tools.datacenter_registry import identify_provider
from tools.ip_probe import probe_ip, resolve_host
from tools.port_scanner import scan_ports_async


async def validate_vps_deploy(
    target: str,
    *,
    port: int = 443,
    sni: str = "www.cloudflare.com",
    samples: int = 8,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    target = target.strip()
    if not target:
        return "Enter VPS IP or hostname."

    if progress:
        progress(f"Resolving {target}...")
    ip = await resolve_host(target)
    if not ip:
        return f"DNS resolution failed: {target}"

    if progress:
        progress(f"Live probe {ip}:{port}...")
    probe = await probe_ip(ip, port=port, sni=sni, samples=samples)

    if progress:
        progress("Threat intel + DC registry...")
    intel = await lookup_ip_intelligence(ip, {})
    threat = analyze_threat_intel(intel)
    providers = identify_provider(
        asn=intel.asn or "",
        isp=intel.isp or probe.isp or "",
        org=getattr(intel, "organization", "") or "",
    )

    if progress:
        progress("Port scan (443, 22, 8443)...")
    port_report = await scan_ports_async(ip, (22, 443, 8443, 2053), progress=None)

    if progress:
        progress("Reverse DNS...")
    ptr = await reverse_dns(ip)

    checks: list[tuple[str, bool, str]] = [
        ("TCP reachable on deploy port", probe.tcp_ok, f"port {port}"),
        ("TLS handshake with SNI", probe.tls_ok, f"SNI {sni}"),
        ("No DNSBL hits", not threat.blocklist_hits, ", ".join(threat.blocklist_hits) or "clean"),
        ("Route score ≥ 55 (measured)", probe.score >= 55, f"score {probe.score}"),
        ("Packet loss ≤ 10%", probe.packet_loss_pct <= 10, f"{probe.packet_loss_pct:.1f}%"),
        ("P95 latency ≤ 400 ms", (probe.p95_ms or 9999) <= 400, f"{probe.p95_ms or '-'} ms"),
        ("Not CDN-fronted origin", not intel.cdn_detected, intel.cdn_detected or "direct IP"),
    ]

    passed = sum(1 for _, ok, _ in checks if ok)
    verdict = "READY" if passed >= 6 and probe.tcp_ok and not threat.blocklist_hits else "NOT READY"

    lines = [
        "VPS Pre-Deploy Validator",
        "═" * 58,
        "",
        f"  Target       : {target}",
        f"  Resolved IP  : {ip}",
        f"  Verdict      : {verdict} ({passed}/{len(checks)} checks passed)",
        "",
        "── Live measurements (your network) ──",
        f"  TCP / TLS    : {'OK' if probe.tcp_ok else 'FAIL'} / {'OK' if probe.tls_ok else 'FAIL'}",
        f"  Latency      : min {probe.min_ms or '-'} | avg {probe.avg_ms or '-'} | p95 {probe.p95_ms or '-'} ms",
        f"  Packet loss  : {probe.packet_loss_pct:.1f}%",
        f"  Route score  : {probe.score}/100 (measured)",
        "",
        "── Network identity (lookup) ──",
        f"  Country      : {intel.country or probe.country or '-'} ({intel.country_code or probe.country_code or '?'})",
        f"  ISP          : {intel.isp or probe.isp or '-'}",
        f"  ASN          : {intel.asn or '-'}",
        f"  Datacenter   : {intel.is_datacenter or threat.is_datacenter}",
        f"  PTR          : {', '.join(ptr) or 'none'}",
        "",
        "── Provider registry match ──",
    ]
    if providers:
        for p in providers[:3]:
            lines.append(f"  • {p.name} ({p.category})")
    else:
        lines.append("  • No catalog match — ASN may be reseller/colocation")

    lines.extend(["", "── Checklist ──"])
    for name, ok, detail in checks:
        mark = "PASS" if ok else "FAIL"
        lines.append(f"  [{mark}] {name} — {detail}")

    lines.extend(["", "── Port scan excerpt ──"])
    for line in port_report.splitlines()[6:14]:
        lines.append(f"  {line.strip()}")

    lines.extend([
        "",
        "── Before go-live ──",
        "  • Restrict SSH (22) to your IP only",
        "  • Install Xray on 443 with REALITY or TLS",
        "  • Re-run after peak-hour filtering test",
        "",
    ])
    return "\n".join(lines)


def validate_vps_deploy_sync(**kwargs) -> str:
    return asyncio.run(validate_vps_deploy(**kwargs))
