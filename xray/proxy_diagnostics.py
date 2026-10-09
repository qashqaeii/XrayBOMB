"""SOCKS tunnel diagnostics: site reachability, speed test, leak check."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Optional

import httpx

from backend.models import (
    LeakCheckResult,
    SiteReachabilityResult,
    SpeedTestResult,
    TestStatus,
)
from utils.direct_http import make_direct_async_client
from utils.logger import get_logger
from utils.socks_client import make_async_socks_client

logger = get_logger(__name__)

SITE_TESTS: list[tuple[str, str]] = [
    ("Basic", "http://www.gstatic.com/generate_204"),
    ("Google", "https://www.google.com/generate_204"),
    ("YouTube", "https://www.youtube.com/generate_204"),
    ("Instagram", "https://www.instagram.com/"),
    ("Telegram", "https://api.telegram.org"),
    ("Cloudflare Trace", "https://www.cloudflare.com/cdn-cgi/trace"),
]

_LENIENT_REACHABILITY_HOSTS = (
    "api.telegram.org",
    "youtube.com",
    "instagram.com",
)

SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"


def _valid_public_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
        return None
    return str(addr)


def _is_lenient_reachability(url: str, status_code: int) -> bool:
    if status_code >= 500:
        return False
    return any(host in url for host in _LENIENT_REACHABILITY_HOSTS)


def _parse_cf_trace(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.strip().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def _socks_client(
    port: int,
    *,
    socks_host: str,
    socks_user: Optional[str] = None,
    socks_pass: Optional[str] = None,
):
    return make_async_socks_client(
        port,
        host=socks_host,
        username=socks_user,
        password=socks_pass,
        timeout=25,
    )


async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[TestStatus, int, str, float]:
    start = time.perf_counter()
    try:
        resp = await client.get(url, follow_redirects=True)
        latency = round((time.perf_counter() - start) * 1000, 2)
        if resp.status_code < 400 or _is_lenient_reachability(url, resp.status_code):
            detail = "HTTP response received"
            if 400 <= resp.status_code < 500:
                detail = f"HTTP {resp.status_code} (reachable, not full site usability)"
            return TestStatus.VALID, resp.status_code, detail, latency
        return TestStatus.WARNING, resp.status_code, f"HTTP {resp.status_code}", latency
    except Exception as exc:
        return TestStatus.INVALID, 0, str(exc)[:120], round((time.perf_counter() - start) * 1000, 2)


async def run_site_reachability(
    port: int,
    *,
    socks_host: str = "127.0.0.1",
    socks_user: Optional[str] = None,
    socks_pass: Optional[str] = None,
) -> list[SiteReachabilityResult]:
    results: list[SiteReachabilityResult] = []
    async with _socks_client(port, socks_host=socks_host, socks_user=socks_user, socks_pass=socks_pass) as client:
        for name, url in SITE_TESTS:
            status, code, detail, latency = await _fetch(client, url)
            if name == "Cloudflare Trace" and status == TestStatus.VALID:
                try:
                    resp = await client.get(url)
                    trace = _parse_cf_trace(resp.text)
                    detail = (
                        f"ip={trace.get('ip', '?')} loc={trace.get('loc', '?')} "
                        f"colo={trace.get('colo', '?')}"
                    )
                except Exception:
                    pass
            results.append(SiteReachabilityResult(
                name=name, url=url, status=status,
                http_status=code if code else None,
                latency_ms=latency, details=detail,
            ))
    return results


async def run_speed_test(
    port: int,
    *,
    socks_host: str = "127.0.0.1",
    socks_user: Optional[str] = None,
    socks_pass: Optional[str] = None,
) -> SpeedTestResult:
    result = SpeedTestResult()
    try:
        start = time.perf_counter()
        async with _socks_client(
            port, socks_host=socks_host, socks_user=socks_user, socks_pass=socks_pass,
        ) as client:
            async with client.stream("GET", SPEED_TEST_URL) as resp:
                resp.raise_for_status()
                nbytes = 0
                async for chunk in resp.aiter_bytes():
                    nbytes += len(chunk)
        duration = time.perf_counter() - start
        result.bytes_downloaded = nbytes
        result.duration_sec = round(duration, 2)
        if duration > 0 and nbytes > 0:
            result.download_mbps = round((nbytes * 8) / duration / 1_000_000, 2)
        result.status = TestStatus.VALID if nbytes >= 100_000 else TestStatus.WARNING
    except Exception as exc:
        result.status = TestStatus.INVALID
        result.error = str(exc)[:200]
    return result


async def _resolve_hostname(hostname: str) -> list[str]:
    try:
        import dns.asyncresolver

        answers = await dns.asyncresolver.Resolver().resolve(hostname, "A")
        return [str(r) for r in answers]
    except Exception:
        return []


async def _collect_baseline_samples() -> tuple[list[dict], str, bool]:
    """Direct HTTP samples (trust_env=False) with source, time, status — same run only."""
    samples: list[dict] = []
    valid_ips: set[str] = []

    async with make_direct_async_client(timeout=10) as direct:
        for url, parser in (
            ("https://api.ipify.org?format=json", lambda r: r.json().get("ip")),
            ("https://ifconfig.me/ip", lambda r: r.text.strip()),
        ):
            ts = time.time()
            try:
                r = await direct.get(url)
                r.raise_for_status()
                raw_ip = parser(r)
                ip = _valid_public_ip(raw_ip)
                row = {"source": url, "at": ts, "status": "ok" if ip else "invalid_ip", "raw": raw_ip}
                if ip:
                    row["ip"] = ip
                    valid_ips.add(ip)
                samples.append(row)
            except Exception as exc:
                samples.append({"source": url, "at": ts, "status": "error", "error": str(exc)[:120]})

    if not valid_ips:
        return samples, "missing", True
    if len(valid_ips) > 1:
        return samples, "inconclusive", True
    return samples, "ok", False


async def run_leak_check(
    port: int,
    test_hostname: str,
    *,
    socks_host: str = "127.0.0.1",
    socks_user: Optional[str] = None,
    socks_pass: Optional[str] = None,
    run_id: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> LeakCheckResult:
    """Leak/baseline for this SOCKS run. Legacy client_ip is ignored (no stale geo baseline)."""
    del client_ip
    result = LeakCheckResult(test_hostname=test_hostname)
    result.dns_leak_status = TestStatus.NOT_TESTED
    result.dns_leak = None
    result.ip_leak = None

    if test_hostname and not test_hostname.replace(".", "").isdigit():
        result.server_dns_ips = await _resolve_hostname(test_hostname)

    samples, baseline_status, inconclusive = await _collect_baseline_samples()
    result.baseline_samples = samples
    result.baseline_status = baseline_status
    result.baseline_inconclusive = inconclusive
    result.notes.append("DNS leak: not tested (requires dedicated resolver test infrastructure).")

    valid_ips = sorted({s["ip"] for s in samples if s.get("ip")})
    if baseline_status == "missing":
        result.notes.append("Baseline IP unknown — no valid direct samples in this run.")
    elif inconclusive:
        result.notes.append(f"Baseline multi-egress observed in this run: {', '.join(valid_ips)}")
        result.notes.append(
            "Inconsistent baseline — not proof of leak or no-leak; VPN/TUN/Proxifier may affect routes."
        )
    elif valid_ips:
        result.client_ip = valid_ips[0]

    try:
        async with _socks_client(
            port, socks_host=socks_host, socks_user=socks_user, socks_pass=socks_pass,
        ) as proxied:
            tr = await proxied.get("https://www.cloudflare.com/cdn-cgi/trace")
            trace = _parse_cf_trace(tr.text)
            result.proxy_exit_ip = _valid_public_ip(trace.get("ip"))
            result.proxy_exit_country = trace.get("loc")
            result.proxy_exit_colo = trace.get("colo")
            try:
                r2 = await proxied.get("https://api.ipify.org?format=json")
                ip2 = _valid_public_ip(r2.json().get("ip"))
                if ip2 and result.proxy_exit_ip and ip2 != result.proxy_exit_ip:
                    result.notes.append(
                        f"Exit IP differs by service in this run: cf={result.proxy_exit_ip} ipify={ip2}"
                    )
                if not result.proxy_exit_ip:
                    result.proxy_exit_ip = ip2
            except Exception:
                pass
    except Exception as exc:
        result.notes.append(f"Proxy IP lookup failed: {exc}")

    if result.client_ip and result.proxy_exit_ip and baseline_status == "ok" and not inconclusive:
        result.exit_ip_same_observed = result.client_ip == result.proxy_exit_ip
        if result.exit_ip_same_observed:
            result.notes.append(
                "Baseline and exit IP match in this run — not proof of leak or absence of leak."
            )
        else:
            result.notes.append(
                f"Exit {result.proxy_exit_ip} differs from baseline {result.client_ip} in this run — "
                "does not prove all leak types absent."
            )
    else:
        result.exit_ip_same_observed = None
        result.notes.append("IP leak verdict: inconclusive (baseline or exit incomplete).")

    if result.server_dns_ips:
        result.notes.append(
            f"Resolver A for server hostname (not necessarily TCP peer): "
            f"{', '.join(result.server_dns_ips[:4])}"
        )
    if run_id:
        result.notes.append(f"run_id={run_id}")

    return result


async def run_all_proxy_diagnostics(
    port: int,
    test_hostname: str,
    *,
    socks_host: str = "127.0.0.1",
    socks_user: Optional[str] = None,
    socks_pass: Optional[str] = None,
    run_id: Optional[str] = None,
    client_ip: Optional[str] = None,
) -> tuple[list[SiteReachabilityResult], SpeedTestResult, LeakCheckResult]:
    sites, speed, leak = await asyncio.gather(
        run_site_reachability(port, socks_host=socks_host, socks_user=socks_user, socks_pass=socks_pass),
        run_speed_test(port, socks_host=socks_host, socks_user=socks_user, socks_pass=socks_pass),
        run_leak_check(
            port, test_hostname,
            socks_host=socks_host, socks_user=socks_user, socks_pass=socks_pass,
            run_id=run_id, client_ip=client_ip,
        ),
    )
    return sites, speed, leak
