"""Deep single-IP / host reputation and connectivity check."""



from __future__ import annotations



import asyncio

from typing import Callable, Optional



from backend.intelligence import analyze_threat_intel

from network.cdn_detector import lookup_ip_intelligence

from tools.output_labels import EDITORIAL, HEURISTIC, MEASURED, RULE_OF_THUMB
from tools.datacenter_registry import identify_provider

from tools.ip_probe import probe_host, probe_ip, resolve_host





async def check_ip_or_host(

    target: str,

    port: int = 443,

    sni: Optional[str] = None,

    samples: int = 6,

    progress: Optional[Callable[[str], None]] = None,

) -> str:

    if progress:

        progress(f"Resolving {target}...")

    ip = await resolve_host(target)

    if not ip:

        return f"Could not resolve: {target}"



    if progress:

        progress(f"Probing {ip}:{port}...")

    if target != ip:

        probe = await probe_host(target, port=port, samples=samples)

    else:

        probe = await probe_ip(ip, port=port, sni=sni or "www.cloudflare.com", samples=samples)



    if progress:

        progress("Loading geo / CDN / DC registry...")

    intel = await lookup_ip_intelligence(ip, {})

    threat = analyze_threat_intel(intel)

    identified = identify_provider(

        asn=intel.asn or "",

        isp=intel.isp or probe.isp or "",

        org=getattr(intel, "organization", "") or "",

    )



    lines = [

        "IP Reputation & Connectivity Report",

        "═" * 58,

        "",

        f"  Target       : {target}",

        f"  Resolved IP  : {ip}",

        f"  Port / SNI   : {port} / {sni or 'default'}",

        "",

        "── Connectivity ──",

        f"  TCP          : {'OK' if probe.tcp_ok else 'FAIL'}",

        f"  TLS+SNI      : {'OK' if probe.tls_ok else 'FAIL'}",

        f"  Min / Avg / P95 : {probe.min_ms or '-'} / {probe.avg_ms or '-'} / {probe.p95_ms or '-'} ms",

        f"  Packet loss  : {probe.packet_loss_pct}%",

        f"  Samples OK   : {probe.samples_ok}/{probe.samples_total}",

        f"  Route score  : {probe.score}/100 {MEASURED}",

        "",

        "── Geo & Network ──",

        f"  Country      : {intel.country or probe.country or '-'} ({intel.country_code or probe.country_code or '?'})",

        f"  ISP          : {intel.isp or probe.isp or '-'}",

        f"  ASN          : {intel.asn or '-'}",

        f"  Datacenter   : {intel.is_datacenter or threat.is_datacenter}",

        f"  CDN detected : {intel.cdn_detected or 'none'}",

        f"  Hosting      : {getattr(intel, 'is_hosting', '-')}",

        "",

        "── Provider registry match (ASN/name patterns) ──",

    ]

    if identified:

        for p in identified[:4]:

            roles = []

            if p.tunnel_origin:

                roles.append("tunnel origin")

            if p.cdn_front:

                roles.append("CDN front")

            lines.append(f"  • {p.name} ({p.category}) — {', '.join(roles) or p.notes}")

    else:

        lines.append("  • No known VPS/CDN registry match")



    lines.extend([

        "",

        "── Threat intel ──",

        f"  Reputation   : {threat.reputation_score}/100 {HEURISTIC}",
        f"  Blocklists   : {', '.join(threat.blocklist_hits) or 'none'} {MEASURED if threat.blocklist_hits else ''}".rstrip(),

    ])

    for note in (threat.notes + probe.notes)[:8]:

        lines.append(f"  • {note}")



    lines.extend(["", "── Tunnel suitability ──"])

    if threat.blocklist_hits:

        lines.append("  BLOCKLISTED — do not use as origin or CF A record.")

    elif probe.score >= 75 and probe.tls_ok:

        lines.append("  GOOD — suitable for REALITY/VLESS origin or CF DNS-only A record.")

    elif probe.score >= 55:

        lines.append("  FAIR — test from target Iranian ISP before selling.")

    else:

        lines.append("  POOR — high loss/latency or TLS failure from your network.")

    if intel.cdn_detected:

        lines.append(f"  CDN front ({intel.cdn_detected}) — origin may differ from edge IP.")

    if probe.p95_ms and probe.p95_ms > 350:

        lines.append(f"  High P95 ({probe.p95_ms} ms) — try another region or provider.")



    return "\n".join(lines)





def check_ip_or_host_sync(**kwargs) -> str:

    return asyncio.run(check_ip_or_host(**kwargs))


