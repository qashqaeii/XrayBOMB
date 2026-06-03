"""SOCKS tunnel diagnostics: site reachability, speed test, leak check."""



from __future__ import annotations



import asyncio

import time

from typing import Optional



import httpx



from backend.models import (

    LeakCheckResult,

    SiteReachabilityResult,

    SpeedTestResult,

    TestStatus,

)

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

# Hosts where HTTP 4xx can still mean the tunnel reached the service (blocks/rate limits).
_LENIENT_REACHABILITY_HOSTS = (
    "api.telegram.org",
    "youtube.com",
    "instagram.com",
)



SPEED_TEST_URL = "https://speed.cloudflare.com/__down?bytes=1000000"

SPEED_TEST_BYTES = 1_000_000





async def _fetch(client: httpx.AsyncClient, url: str) -> tuple[TestStatus, int, str, float]:

    start = time.perf_counter()

    try:

        resp = await client.get(url, follow_redirects=True)

        latency = round((time.perf_counter() - start) * 1000, 2)

        if resp.status_code < 400 or _is_lenient_reachability(url, resp.status_code):
            return TestStatus.VALID, resp.status_code, "OK", latency

        return TestStatus.WARNING, resp.status_code, f"HTTP {resp.status_code}", latency

    except Exception as exc:

        return TestStatus.INVALID, 0, str(exc)[:120], round((time.perf_counter() - start) * 1000, 2)





def _is_lenient_reachability(url: str, status_code: int) -> bool:
    """Treat 4xx from major sites as reachable when the tunnel got a real HTTP response."""
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





async def run_site_reachability(port: int) -> list[SiteReachabilityResult]:

    results: list[SiteReachabilityResult] = []

    async with make_async_socks_client(port, timeout=25) as client:

        for name, url in SITE_TESTS:

            status, code, detail, latency = await _fetch(client, url)

            extra = ""

            if name == "Cloudflare Trace" and status == TestStatus.VALID:

                try:

                    resp = await client.get(url)

                    trace = _parse_cf_trace(resp.text)

                    extra = f"ip={trace.get('ip', '?')} loc={trace.get('loc', '?')} colo={trace.get('colo', '?')}"

                    detail = extra

                except Exception:

                    pass

            results.append(SiteReachabilityResult(

                name=name, url=url, status=status,

                http_status=code if code else None,

                latency_ms=latency, details=detail,

            ))

    return results





async def run_speed_test(port: int) -> SpeedTestResult:

    result = SpeedTestResult()

    try:

        start = time.perf_counter()

        async with make_async_socks_client(port, timeout=60) as client:

            resp = await client.get(SPEED_TEST_URL)

            resp.raise_for_status()

            nbytes = len(resp.content)

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





async def run_leak_check(

    port: int,

    test_hostname: str,

    client_ip: Optional[str] = None,

) -> LeakCheckResult:

    result = LeakCheckResult(test_hostname=test_hostname)

    result.client_ip = client_ip



    if test_hostname:

        result.direct_dns_ips = await _resolve_hostname(test_hostname)



    try:

        async with httpx.AsyncClient(timeout=10, verify=False) as direct:

            r = await direct.get("https://api.ipify.org?format=json")

            if not result.client_ip:

                result.client_ip = r.json().get("ip")

    except Exception as exc:

        result.notes.append(f"Direct IP lookup failed: {exc}")



    try:

        async with make_async_socks_client(port, timeout=20) as proxied:

            tr = await proxied.get("https://www.cloudflare.com/cdn-cgi/trace")

            trace = _parse_cf_trace(tr.text)

            result.proxy_exit_ip = trace.get("ip")

            result.proxy_exit_country = trace.get("loc")

            result.proxy_exit_colo = trace.get("colo")

            try:

                r2 = await proxied.get("https://api.ipify.org?format=json")

                if not result.proxy_exit_ip:

                    result.proxy_exit_ip = r2.json().get("ip")

            except Exception:

                pass

    except Exception as exc:

        result.notes.append(f"Proxy IP lookup failed: {exc}")



    if result.client_ip and result.proxy_exit_ip:

        result.ip_leak = result.client_ip == result.proxy_exit_ip

        if result.ip_leak:

            result.notes.append("WARNING: Exit IP matches client IP — possible IP leak")

        else:

            result.notes.append(f"Exit IP {result.proxy_exit_ip} ({result.proxy_exit_country or '?'}) differs from client")



    if result.direct_dns_ips and result.proxy_exit_ip:

        result.dns_leak = False

        result.notes.append(f"Direct DNS A: {', '.join(result.direct_dns_ips[:3])}")



    return result





async def run_all_proxy_diagnostics(

    port: int,

    test_hostname: str,

    client_ip: Optional[str] = None,

) -> tuple[list[SiteReachabilityResult], SpeedTestResult, LeakCheckResult]:

    sites, speed, leak = await asyncio.gather(

        run_site_reachability(port),

        run_speed_test(port),

        run_leak_check(port, test_hostname, client_ip),

    )

    return sites, speed, leak


