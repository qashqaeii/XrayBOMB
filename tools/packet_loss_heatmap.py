"""Packet loss & jitter heatmap — live TCP probes."""

from __future__ import annotations

import asyncio
import statistics
from typing import Callable, Optional
from network.latency_benchmark import benchmark_tcp_latency
from tools.ip_probe import resolve_host
from tools.multi_region_ping import REGION_TARGETS
from tools.output_labels import MEASURED


async def _probe_series(host: str, port: int, samples: int) -> tuple[list[float], float]:
    latencies: list[float] = []
    fails = 0
    for _ in range(samples):
        r = await benchmark_tcp_latency(host, port, timeout=6.0)
        if r.success and r.latency_ms is not None:
            latencies.append(r.latency_ms)
        else:
            fails += 1
    loss = (fails / samples) * 100 if samples else 100.0
    return latencies, loss


def _jitter_ms(latencies: list[float]) -> Optional[float]:
    if len(latencies) < 2:
        return None
    deltas = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return statistics.mean(deltas)


def _cell(latencies: list[float], idx: int) -> str:
    if idx >= len(latencies):
        return " XX "
    ms = latencies[idx]
    if ms < 120:
        return f"{ms:4.0f}"
    if ms < 250:
        return f"{ms:4.0f}"
    return f"{ms:4.0f}"


async def build_packet_loss_heatmap(
    samples: int = 8,
    port: int = 443,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    samples = max(4, min(samples, 12))
    lines = [
        "Packet Loss & Jitter Heatmap",
        "═" * 72,
        "",
        f"  Samples per target: {samples}  Port: {port}  {MEASURED}",
        "  Cell values = TCP connect latency (ms). XX = failed sample.",
        "",
    ]

    header = "  Region         " + "".join(f" s{i+1:>2} " for i in range(min(samples, 8)))
    if samples > 8:
        header += " ..."
    header += "  Loss   Jitter"
    lines.append(header)
    lines.append("  " + "─" * (len(header) - 2))

    rows_data: list[tuple[str, float, Optional[float]]] = []

    for region, code, host in REGION_TARGETS:
        if progress:
            progress(f"Probing {region} ({host})...")
        ip = await resolve_host(host)
        if not ip:
            lines.append(f"  {region:<14} DNS FAIL")
            continue
        latencies, loss = await _probe_series(host, port, samples)
        jitter = _jitter_ms(latencies)
        rows_data.append((region, loss, jitter))

        cells = ""
        show = min(samples, 8)
        for i in range(show):
            if i < len(latencies):
                cells += f" {_cell(latencies, i)} "
            else:
                cells += "  XX "
        if samples > 8:
            cells += " ..."
        jit_s = f"{jitter:.1f}ms" if jitter is not None else "—"
        lines.append(f"  {region:<14}{cells}  {loss:4.0f}%  {jit_s}")

    if rows_data:
        worst = max(rows_data, key=lambda r: r[1])
        best = min(rows_data, key=lambda r: r[1])
        lines.extend([
            "",
            "── Summary ──",
            f"  Lowest loss  : {best[0]} ({best[1]:.0f}%)",
            f"  Highest loss : {worst[0]} ({worst[1]:.0f}%)",
            "  Use with Multi-Region Ping for ranked scores.",
        ])
    return "\n".join(lines)


def build_packet_loss_heatmap_sync(**kwargs) -> str:
    return asyncio.run(build_packet_loss_heatmap(**kwargs))
