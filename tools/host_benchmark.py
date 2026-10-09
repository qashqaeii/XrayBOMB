"""Benchmark latency to any host:port."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from tools.output_labels import MEASURED, RULE_OF_THUMB
from tools.ip_probe import probe_host, resolve_host


async def benchmark_host(
    host: str,
    port: int = 443,
    samples: int = 8,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host:
        return "Enter a hostname or IP."

    if progress:
        progress(f"Resolving {host}...")
    ip = await resolve_host(host)
    if not ip:
        return f"DNS failed for: {host}"

    if progress:
        progress(f"Benchmarking {ip}:{port} ({samples} samples)...")
    probe = await probe_host(host, port=port, samples=samples)

    lines = [
        "Host Latency Benchmark",
        "═" * 52,
        "",
        f"  Host       : {host}",
        f"  IP         : {ip}",
        f"  Port       : {port}",
        f"  Samples    : {samples}",
        "",
        f"  TCP OK     : {probe.tcp_ok}",
        f"  Min        : {probe.min_ms or '-'} ms",
        f"  Avg        : {probe.avg_ms or '-'} ms",
        f"  P95        : {probe.p95_ms or '-'} ms",
        f"  Packet loss: {probe.packet_loss_pct}%",
        f"  Score      : {probe.score}/100 {MEASURED}",
        f"  Geo        : {probe.country_code or '?'} — {probe.country or '-'}",
        "",
        "── Notes ──",
    ]
    for n in probe.notes:
        lines.append(f"  • {n}")
    if probe.blocklist_hits:
        lines.append(f"  ⚠ Blocklist: {', '.join(probe.blocklist_hits)}")

    lines.extend([
        "",
        "── Latency thresholds (rule-of-thumb for operators in Iran) ──",
        f"  <120ms p95 excellent | 120–250 good | 250–350 fair | >350 poor {RULE_OF_THUMB}",
    ])
    return "\n".join(lines)


def benchmark_host_sync(**kwargs) -> str:
    return asyncio.run(benchmark_host(**kwargs))
