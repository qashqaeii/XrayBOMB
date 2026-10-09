"""Rank pasted VPS IPs by live route quality from your network."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from tools.ip_list_parser import parse_ip_lines
from tools.ip_probe import probe_many


async def rank_vps_ips_async(
    ip_text: str,
    *,
    port: int = 443,
    sni: str = "www.cloudflare.com",
    samples: int = 6,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    ips, warnings = parse_ip_lines(ip_text, max_ips=64)
    if not ips:
        return "Paste at least one valid IPv4 address (one per line)."

    if progress:
        progress(f"Probing {len(ips)} VPS IP(s) on :{port}...")

    results = await probe_many(
        ips, port=port, sni=sni, samples=samples, concurrency=8, progress=progress,
    )

    lines = [
        "VPS IP Ranker",
        "═" * 58,
        "",
        f"  IPs tested   : {len(ips)}",
        f"  Port / SNI   : {port} / {sni}",
        f"  Samples      : {samples}",
        "  Scores       : live measurements only",
        "",
        "── Ranked ──",
        f"  {'IP':<18} {'Score':>5} {'Avg':>7} {'P95':>7} {'Loss%':>6} {'TLS':>4} {'Geo':>4} {'ISP':<18}",
        "  " + "─" * 72,
    ]

    for p in results:
        if not p.tcp_ok and p.score == 0:
            continue
        tls = "Y" if p.tls_ok else "N"
        isp = (p.isp or "")[:18]
        lines.append(
            f"  {p.ip:<18} {p.score:>5} {p.avg_ms or '-':>7} {p.p95_ms or '-':>7} "
            f"{p.packet_loss_pct:>5.1f}% {tls:>4} {p.country_code or '?':>4} {isp:<18}"
        )

    unreachable = [p.ip for p in results if not p.tcp_ok]
    if unreachable:
        lines.extend(["", "── Unreachable ──"])
        lines.append("  " + ", ".join(unreachable))

    if warnings:
        lines.extend(["", "── Input notes ──"])
        for w in warnings[:5]:
            lines.append(f"  • {w}")

    best = next((p for p in results if p.tcp_ok), None)
    lines.extend(["", "── Recommendation ──"])
    if best:
        lines.append(f"  Best measured IP: {best.ip} (score {best.score}, avg {best.avg_ms or '-'} ms)")
        if best.blocklist_hits:
            lines.append("  ⚠ Best IP has blocklist hits — do not use for production.")
    else:
        lines.append("  No reachable IPs — check firewall or wrong addresses.")

    lines.append("")
    return "\n".join(lines)


def rank_vps_ips_sync(**kwargs) -> str:
    return asyncio.run(rank_vps_ips_async(**kwargs))
