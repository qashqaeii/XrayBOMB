"""Multi-region ping matrix — measured latency from your network."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from tools.ip_probe import probe_host, resolve_host
from tools.output_labels import MEASURED, RULE_OF_THUMB

REGION_TARGETS: tuple[tuple[str, str, str], ...] = (
    ("Frankfurt", "DE", "speed.hetzner.de"),
    ("Amsterdam", "NL", "ams3.digitalocean.com"),
    ("Paris", "FR", "scaleway.com"),
    ("London", "GB", "lon1.digitalocean.com"),
    ("Istanbul", "TR", "www.turktelekom.com.tr"),
    ("Dubai", "AE", "ae.gcore.com"),
)


async def build_ping_matrix(
    samples: int = 5,
    port: int = 443,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    lines = [
        "Multi-Region Ping Matrix",
        "═" * 58,
        "",
        f"  Samples: {samples}  Port: {port}",
        "  All values measured live from YOUR network.",
        "",
        f"  {'Region':<14} {'Code':<5} {'Host':<28} {'Avg ms':<8} {'P95':<8} {'Loss':<6} {'Score'}",
        f"  {MEASURED}",
        "  " + "─" * 72,
    ]

    results: list[tuple[str, str, float, float, float, int]] = []

    for region, code, host in REGION_TARGETS:
        if progress:
            progress(f"Probing {region} ({host})...")
        ip = await resolve_host(host)
        if not ip:
            lines.append(f"  {region:<14} {code:<5} {host:<28} DNS FAIL")
            continue
        probe = await probe_host(host, port=port, samples=samples)
        avg = probe.avg_ms or 0
        p95 = probe.p95_ms or 0
        loss = probe.packet_loss_pct
        score = probe.score
        results.append((region, code, avg, p95, loss, score))
        lines.append(
            f"  {region:<14} {code:<5} {host:<28} "
            f"{f'{avg:.0f}' if avg else '—':<8} "
            f"{f'{p95:.0f}' if p95 else '—':<8} "
            f"{loss:.0f}%{'':<3} {score}"
        )

    if results:
        best = max(results, key=lambda r: r[5])
        lines.extend([
            "",
            "── Best route (by measured score) ──",
            f"  {best[0]} ({best[1]}) — avg {best[2]:.0f} ms, score {best[5]} {MEASURED}",
            "",
            f"── Latency thresholds {RULE_OF_THUMB} ──",
            "  EU <120ms excellent | 120–250 good | 250–350 fair | >350 poor",
            "  Compare with Datacenter Finder for provider-specific picks.",
        ])
    return "\n".join(lines)


def build_ping_matrix_sync(**kwargs) -> str:
    return asyncio.run(build_ping_matrix(**kwargs))
