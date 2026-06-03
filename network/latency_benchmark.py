"""Latency benchmark with min/avg/max/p95."""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import Optional

from backend.models import LatencyStats
from utils.settings import get_settings


async def benchmark_tcp_latency(host: str, port: int, samples: Optional[int] = None) -> LatencyStats:
    n = samples or get_settings().latency_samples
    latencies: list[float] = []

    for _ in range(n):
        start = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=8)
            latencies.append((time.perf_counter() - start) * 1000)
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(0.1)

    if not latencies:
        return LatencyStats(samples=0)

    latencies.sort()
    p95_idx = min(len(latencies) - 1, int(len(latencies) * 0.95))
    return LatencyStats(
        min_ms=round(min(latencies), 2),
        max_ms=round(max(latencies), 2),
        avg_ms=round(statistics.mean(latencies), 2),
        p95_ms=round(latencies[p95_idx], 2),
        samples=len(latencies),
    )
