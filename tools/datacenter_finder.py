"""Datacenter / VPS provider benchmark by target country."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.models import DatacenterFinderResult, ProviderBenchmarkResult
from tools.ip_probe import probe_host, resolve_host
from tools.provider_catalog import COUNTRY_CATALOG, TARGET_COUNTRIES, CountryCatalog, ProviderProbe


def _score_provider(
    base_score: int,
    loss_pct: float,
    avg_ms: Optional[float],
    p95_ms: Optional[float],
    country_match: bool,
    blocklist: list[str],
    weight: float,
) -> int:
    score = float(base_score)
    if blocklist:
        score -= 25
    if not country_match:
        score -= 12
    if loss_pct > 10:
        score -= 20
    elif loss_pct > 3:
        score -= 8
    score *= weight
    if avg_ms and avg_ms < 150:
        score += 5
    if p95_ms and p95_ms > 400:
        score -= 10
    return max(0, min(100, int(round(score))))


async def _benchmark_provider(
    provider: ProviderProbe,
    catalog: CountryCatalog,
    port: int,
    samples: int,
) -> ProviderBenchmarkResult:
    best_probe = None
    best_score = -1
    notes: list[str] = []

    for host in provider.hosts:
        resolved = await resolve_host(host)
        if not resolved:
            notes.append(f"{host}: DNS failed")
            continue
        probe = await probe_host(
            host, port=port, samples=samples, target_country_code=catalog.code,
        )
        country_match = probe.country_code == catalog.code
        score = _score_provider(
            probe.score, probe.packet_loss_pct, probe.avg_ms, probe.p95_ms,
            country_match, probe.blocklist_hits, provider.weight,
        )
        if score > best_score:
            best_score = score
            best_probe = probe
            best_probe.score = score

    if not best_probe:
        return ProviderBenchmarkResult(
            provider=provider.name,
            score=0,
            asn_hint=provider.asn_hint,
            iran_notes=provider.iran_notes,
            notes=notes or ["All probe hosts failed DNS resolve"],
        )

    return ProviderBenchmarkResult(
        provider=provider.name,
        score=best_score,
        host=best_probe.target,
        ip=best_probe.ip,
        avg_ms=best_probe.avg_ms,
        p95_ms=best_probe.p95_ms,
        min_ms=best_probe.min_ms,
        packet_loss_pct=best_probe.packet_loss_pct,
        country=best_probe.country,
        country_code=best_probe.country_code,
        asn_hint=provider.asn_hint,
        iran_notes=provider.iran_notes,
        blocklist_hits=best_probe.blocklist_hits,
        notes=best_probe.notes + notes,
    )


async def benchmark_datacenters(
    country: str = "Germany",
    port: int = 443,
    samples: int = 6,
    progress: Optional[Callable[[str], None]] = None,
) -> DatacenterFinderResult:
    catalog = COUNTRY_CATALOG.get(country)
    if not catalog:
        raise ValueError(f"Unknown country: {country}. Choose from {', '.join(TARGET_COUNTRIES)}")

    if progress:
        progress(f"Benchmarking {len(catalog.providers)} providers → {country} ({catalog.code})...")

    sem = asyncio.Semaphore(3)

    async def run_one(prov: ProviderProbe) -> ProviderBenchmarkResult:
        async with sem:
            if progress:
                progress(f"  Testing {prov.name}...")
            return await _benchmark_provider(prov, catalog, port, samples)

    results = list(await asyncio.gather(*[run_one(p) for p in catalog.providers]))
    results.sort(key=lambda r: r.score, reverse=True)
    winner = results[0] if results and results[0].score > 0 else None

    tips = [
        f"Target: {country} ({catalog.code}) — measured from your network (Iran-calibrated).",
        "Score combines latency, packet loss, geo match, and Iran-market provider weight.",
        "Re-test the same provider during peak filtering before buying VPS.",
        "Hetzner/OVH are common for REALITY+CDN; Contabo is cheaper but more variable.",
    ]

    return DatacenterFinderResult(
        tool="datacenter_finder",
        country=country,
        country_code=catalog.code,
        port=port,
        results=results,
        winner=winner.provider if winner else None,
        winner_score=winner.score if winner else None,
        tips=tips,
    )


def benchmark_datacenters_sync(**kwargs) -> DatacenterFinderResult:
    return asyncio.run(benchmark_datacenters(**kwargs))
