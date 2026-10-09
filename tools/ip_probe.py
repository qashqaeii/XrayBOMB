"""Shared IP probing — latency, packet loss, TLS, blocklist."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from backend.intelligence import _check_dnsbl
from network.latency_benchmark import benchmark_tcp_latency
from network.geo import lookup_geo_ip
from utils.logger import get_logger

logger = get_logger(__name__)

PROBE_PORT = 443
DEFAULT_SAMPLES = 6


@dataclass
class ProbeResult:
    target: str
    ip: str = ""
    port: int = PROBE_PORT
    tcp_ok: bool = False
    tls_ok: bool = False
    avg_ms: Optional[float] = None
    p95_ms: Optional[float] = None
    min_ms: Optional[float] = None
    packet_loss_pct: float = 100.0
    samples_ok: int = 0
    samples_total: int = 0
    blocklist_hits: list[str] = field(default_factory=list)
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    score: int = 0
    notes: list[str] = field(default_factory=list)


async def resolve_host(host: str) -> Optional[str]:
    if _is_ipv4(host):
        return host
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except Exception:
        pass
    return None


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


async def probe_tls(ip: str, port: int, sni: str, timeout: float = 6.0) -> bool:
    sni = sni or "www.cloudflare.com"
    try:
        loop = asyncio.get_event_loop()

        def _handshake() -> None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                    ss.do_handshake()

        await asyncio.wait_for(loop.run_in_executor(None, _handshake), timeout=timeout + 1)
        return True
    except Exception:
        return False


def score_latency_iran(avg_ms: Optional[float], p95_ms: Optional[float], loss_pct: float) -> tuple[int, list[str]]:
    """Score 0–100 tuned for client in Iran → target abroad."""
    notes: list[str] = []
    score = 100.0
    if avg_ms is None:
        return 0, ["Connection failed"]

    if loss_pct <= 0:
        score += 5
        notes.append("No packet loss")
    elif loss_pct <= 5:
        score -= loss_pct * 3
        notes.append(f"Packet loss {loss_pct:.0f}%")
    else:
        score -= 15 + loss_pct
        notes.append(f"High packet loss {loss_pct:.0f}%")

    p95 = p95_ms or avg_ms
    if p95 < 120:
        score += 10
        notes.append("Excellent ping from Iran")
    elif p95 < 200:
        notes.append("Good ping")
    elif p95 < 350:
        score -= 12
        notes.append("Fair ping")
    else:
        score -= 25
        notes.append("High ping")

    jitter = (p95 - avg_ms) if p95 and avg_ms else 0
    if jitter > 80:
        score -= 10
        notes.append("High latency jitter")

    return max(0, min(100, int(score))), notes


def score_clean_ip_cf(
    tcp_ok: bool,
    tls_ok: bool,
    avg_ms: Optional[float],
    p95_ms: Optional[float],
    loss_pct: float,
    blocklist: list[str],
    country_code: Optional[str],
    target_country: Optional[str],
) -> tuple[int, list[str]]:
    if not tcp_ok:
        return 0, ["TCP 443 failed"]
    score, notes = score_latency_iran(avg_ms, p95_ms, loss_pct)
    if tls_ok:
        score = min(100, score + 8)
        notes.append("TLS+SNI OK")
    else:
        score -= 15
        notes.append("TLS/SNI failed — may still work behind CDN")
    if blocklist:
        score -= 30
        notes.append(f"Blocklist: {', '.join(blocklist)}")
    else:
        score = min(100, score + 5)
        notes.append("No DNSBL hits")
    if target_country and country_code and target_country != country_code:
        score -= 8
        notes.append(f"Geo {country_code} != target {target_country}")
    elif country_code:
        notes.append(f"Geo: {country_code}")
    return max(0, min(100, score)), notes


async def probe_ip(
    ip: str,
    port: int = PROBE_PORT,
    sni: Optional[str] = None,
    samples: int = DEFAULT_SAMPLES,
    check_tls: bool = True,
    geo_lookup: bool = True,
    target_country_code: Optional[str] = None,
    score_fn: Optional[Callable[..., tuple[int, list[str]]]] = None,
) -> ProbeResult:
    result = ProbeResult(target=ip, ip=ip, port=port, samples_total=samples)
    stats = await benchmark_tcp_latency(ip, port, samples=samples)
    result.samples_ok = stats.samples
    result.samples_total = samples
    result.avg_ms = stats.avg_ms
    result.p95_ms = stats.p95_ms
    result.min_ms = stats.min_ms
    if stats.samples:
        result.tcp_ok = True
        result.packet_loss_pct = round((1 - stats.samples / samples) * 100, 1)
    else:
        result.packet_loss_pct = 100.0
        return result

    if check_tls and sni:
        result.tls_ok = await probe_tls(ip, port, sni)

    loop = asyncio.get_event_loop()
    result.blocklist_hits = await loop.run_in_executor(None, _check_dnsbl, ip)

    if geo_lookup:
        geo = await lookup_geo_ip(ip)
        result.country = geo.get("country")
        result.country_code = geo.get("country_code")
        result.isp = geo.get("isp")

    fn = score_fn or (
        lambda *a, **k: score_clean_ip_cf(
            result.tcp_ok, result.tls_ok, result.avg_ms, result.p95_ms,
            result.packet_loss_pct, result.blocklist_hits,
            result.country_code, target_country_code,
        )
    )
    result.score, result.notes = fn(
        result.tcp_ok, result.tls_ok, result.avg_ms, result.p95_ms,
        result.packet_loss_pct, result.blocklist_hits,
        result.country_code, target_country_code,
    )
    return result


async def probe_host(
    host: str,
    port: int = PROBE_PORT,
    samples: int = DEFAULT_SAMPLES,
    target_country_code: Optional[str] = None,
) -> ProbeResult:
    ip = await resolve_host(host)
    if not ip:
        return ProbeResult(target=host, notes=["DNS resolve failed"])
    result = await probe_ip(
        ip, port=port, sni=host if not _is_ipv4(host) else None,
        samples=samples, check_tls=False, geo_lookup=True,
        target_country_code=target_country_code,
        score_fn=lambda tcp_ok, tls_ok, avg, p95, loss, bl, cc, tc: score_latency_iran(avg, p95, loss),
    )
    result.target = host
    # Provider score: latency + geo match + blocklist
    score = result.score
    notes = list(result.notes)
    if result.blocklist_hits:
        score -= 25
        notes.append("Blocklist hit")
    if target_country_code and result.country_code == target_country_code:
        score = min(100, score + 10)
        notes.append("Target country geo confirmed")
    elif target_country_code and result.country_code:
        score -= 15
        notes.append(f"Geo {result.country_code} != {target_country_code}")
    result.score = max(0, min(100, score))
    result.notes = notes
    return result


async def probe_many(
    targets: list[str],
    *,
    port: int = PROBE_PORT,
    sni: Optional[str] = None,
    samples: int = DEFAULT_SAMPLES,
    concurrency: int = 12,
    progress: Optional[Callable[[str], None]] = None,
    target_country_code: Optional[str] = None,
    host_mode: bool = False,
) -> list[ProbeResult]:
    sem = asyncio.Semaphore(concurrency)
    results: list[ProbeResult] = []

    async def one(t: str) -> ProbeResult:
        async with sem:
            if progress:
                progress(f"Probing {t}...")
            if host_mode:
                return await probe_host(t, port=port, samples=samples, target_country_code=target_country_code)
            return await probe_ip(
                t, port=port, sni=sni, samples=samples,
                target_country_code=target_country_code,
            )

    out = await asyncio.gather(*[one(t) for t in targets], return_exceptions=True)
    for item in out:
        if isinstance(item, ProbeResult):
            results.append(item)
        elif isinstance(item, Exception):
            logger.debug("Probe error: %s", item)
    results.sort(key=lambda r: r.score, reverse=True)
    return results
