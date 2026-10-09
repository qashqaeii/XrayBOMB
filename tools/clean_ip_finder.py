"""Cloudflare clean IP finder — scan CF edges; user-defined ranges or IP lists."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.models import CleanIPFinderResult, CleanIPResult
from tools.cloudflare_ranges import REGION_OPTIONS, SCAN_SOURCE_MODES, resolve_scan_ips
from tools.ip_probe import probe_many


async def find_clean_cloudflare_ips(
    region: str = "Germany",
    sni: str = "www.cloudflare.com",
    port: int = 443,
    max_ips: int = 40,
    samples: int = 5,
    scan_mode: str = "Cloudflare live list",
    custom_input: str = "",
    progress: Optional[Callable[[str], None]] = None,
) -> CleanIPFinderResult:
    if progress:
        progress(f"Building scan list ({scan_mode})...")
    ips, source_label, warnings = await resolve_scan_ips(
        region, max_ips=max_ips, mode=scan_mode, custom_text=custom_input,
    )

    if progress:
        progress(f"Scanning {len(ips)} IPs on :{port} (SNI={sni})...")

    raw = await probe_many(
        ips,
        port=port,
        sni=sni,
        samples=samples,
        concurrency=14,
        progress=progress,
        target_country_code=None,
    )

    rows: list[CleanIPResult] = []
    for p in raw:
        if not p.tcp_ok:
            continue
        rows.append(CleanIPResult(
            ip=p.ip,
            score=p.score,
            avg_ms=p.avg_ms,
            p95_ms=p.p95_ms,
            min_ms=p.min_ms,
            packet_loss_pct=p.packet_loss_pct,
            tls_ok=p.tls_ok,
            blocklist_hits=p.blocklist_hits,
            country=p.country,
            country_code=p.country_code,
            isp=p.isp,
            notes=p.notes,
        ))

    rows.sort(key=lambda r: r.score, reverse=True)
    best = rows[0] if rows else None

    tips = [
        f"Scan source: {source_label}",
        "Scores are measured live from your network (latency, TLS, DNSBL).",
        "Cloudflare uses anycast — geo/ISP columns are lookup results, not guaranteed PoP.",
    ]
    tips.extend(warnings)

    return CleanIPFinderResult(
        tool="cloudflare_clean_ip",
        region=region,
        sni=sni,
        port=port,
        scanned=len(ips),
        reachable=len(rows),
        results=rows,
        best_ip=best.ip if best else None,
        best_score=best.score if best else None,
        tips=tips,
    )


def find_clean_cloudflare_ips_sync(**kwargs) -> CleanIPFinderResult:
    return asyncio.run(find_clean_cloudflare_ips(**kwargs))
