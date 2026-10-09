"""Multi-country datacenter benchmark — parallel live comparison."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from tools.datacenter_finder import benchmark_datacenters
from tools.provider_catalog import TARGET_COUNTRIES


COMPARE_COUNTRIES: tuple[str, ...] = TARGET_COUNTRIES


async def compare_countries_async(
    countries: list[str],
    *,
    port: int = 443,
    samples: int = 5,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    if not countries:
        return "Select at least one country."

    if progress:
        progress(f"Benchmarking {len(countries)} countries in parallel...")

    async def one(country: str):
        if progress:
            progress(f"  → {country}...")
        try:
            return await benchmark_datacenters(country=country, port=port, samples=samples)
        except Exception as exc:
            return exc

    results = await asyncio.gather(*[one(c) for c in countries])

    lines = [
        "Multi-Country Datacenter Compare",
        "═" * 58,
        "",
        f"  Countries    : {', '.join(countries)}",
        f"  Port         : {port}",
        f"  Samples      : {samples} per provider",
        "  All scores   : measured live from your network",
        "",
        "── Winners by country ──",
        f"  {'Country':<18} {'Winner':<20} {'Score':>6} {'2nd place':<20} {'Score':>6}",
        "  " + "─" * 72,
    ]

    winners: list[tuple[str, str, int, float | None]] = []

    for country, res in zip(countries, results):
        if isinstance(res, Exception):
            lines.append(f"  {country:<18} ERROR: {res}")
            continue
        w = res.results[0] if res.results else None
        s = res.results[1] if len(res.results) > 1 else None
        w_name = w.provider if w else "—"
        w_score = w.score if w else 0
        s_name = s.provider if s else "—"
        s_score = s.score if s else 0
        lines.append(f"  {country:<18} {w_name:<20} {w_score:>6} {s_name:<20} {s_score:>6}")
        if w and w.score > 0:
            winners.append((country, w_name, w_score, w.avg_ms))

    if winners:
        winners.sort(key=lambda x: -x[2])
        lines.extend(["", "── Overall ranking (best country for your route) ──"])
        for i, (country, prov, score, avg) in enumerate(winners, 1):
            avg_s = f"{avg:.0f} ms" if avg else "—"
            lines.append(f"  {i}. {country} — {prov} — score {score} — avg {avg_s}")

    lines.extend(["", "── Per-country top 3 ──"])
    for country, res in zip(countries, results):
        if isinstance(res, Exception):
            continue
        lines.append(f"\n  {country} ({res.country_code}):")
        for p in res.results[:3]:
            lines.append(
                f"    {p.provider:<18} score {p.score:>3}  avg {p.avg_ms or '-':>6} ms  "
                f"loss {p.packet_loss_pct:.0f}%  {p.ip or '-'}"
            )

    lines.extend(["", ""])
    return "\n".join(lines)


def compare_countries_sync(**kwargs) -> str:
    return asyncio.run(compare_countries_async(**kwargs))
