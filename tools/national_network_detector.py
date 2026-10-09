"""National network detector — filtering, DNS hijack, connectivity hints."""

from __future__ import annotations

import asyncio
import socket
from typing import Callable, Optional

import httpx

from dns_analyzer.resolver import _doh_lookup
from network.geo import lookup_geo_ip
from utils.logger import get_logger

logger = get_logger(__name__)

_HTTP = {"timeout": 10.0, "trust_env": False, "follow_redirects": True}


def _section(name: str) -> str:
    return f"── {name} ──"

TEST_DOMAINS = ("google.com", "cloudflare.com", "github.com", "youtube.com")
FILTER_PROBE = "cloudflare-dns.com"


async def _tcp_connect(host: str, port: int, timeout: float = 6.0) -> tuple[bool, float]:
    start = asyncio.get_event_loop().time()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        ms = (asyncio.get_event_loop().time() - start) * 1000
        return True, round(ms, 1)
    except Exception:
        return False, 0.0


async def _https_head(url: str) -> tuple[bool, int, str]:
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.head(url)
            return True, r.status_code, ""
    except httpx.HTTPStatusError as exc:
        return True, exc.response.status_code, ""
    except Exception as exc:
        return False, 0, str(exc)[:80]


async def build_national_network_report(
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    lines = [
        "National Network Detector",
        "═" * 58,
        "",
        "  Live tests from YOUR network — no simulated scores.",
        "",
    ]

    if progress:
        progress("Geo lookup...")
    geo = await lookup_geo_ip()
    cc = (geo or {}).get("country_code", "?")
    isp = (geo or {}).get("isp", "—")
    lines.extend([
        _section("Client context"),
        f"  Country : {geo.get('country', '?')} ({cc})" if geo else "  Country : unknown",
        f"  ISP     : {isp}",
        "",
    ])

    if progress:
        progress("TCP connectivity tests...")
    lines.append(_section("TCP reachability"))
    tcp_targets = [
        ("8.8.8.8:443", "8.8.8.8", 443),
        ("1.1.1.1:443", "1.1.1.1", 443),
        ("9.9.9.9:443", "9.9.9.9", 443),
    ]
    tcp_ok = 0
    for label, host, port in tcp_targets:
        ok, ms = await _tcp_connect(host, port)
        if ok:
            tcp_ok += 1
        lines.append(f"  {label:<16} {'OK' if ok else 'FAIL':<6} {f'{ms} ms' if ok else ''}")

    if progress:
        progress("HTTPS tests...")
    lines.extend(["", _section("HTTPS (TLS) reachability")])
    https_ok = 0
    for domain in TEST_DOMAINS:
        ok, code, err = await _https_head(f"https://{domain}")
        if ok and code:
            https_ok += 1
        status = f"HTTP {code}" if ok else f"FAIL ({err})"
        lines.append(f"  {domain:<20} {status}")

    if progress:
        progress("DNS hijack check (local vs DoH)...")
    lines.extend(["", _section("DNS hijack probe")])
    local_ips: list[str] = []
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(FILTER_PROBE, None, family=socket.AF_INET)
        local_ips = sorted({i[4][0] for i in infos})
    except Exception as exc:
        lines.append(f"  Local DNS failed: {exc}")

    doh = await _doh_lookup(FILTER_PROBE)
    lines.append(f"  Probe domain : {FILTER_PROBE}")
    lines.append(f"  Local A      : {', '.join(local_ips) or 'none'}")
    dns_hijack = False
    for provider, ips in doh.items():
        lines.append(f"  DoH {provider:<12}: {', '.join(ips) or 'none'}")
        if local_ips and ips and set(local_ips) != set(ips):
            dns_hijack = True

    if progress:
        progress("Analyzing...")
    lines.extend(["", _section("Detection summary")])

    if cc == "IR":
        if https_ok >= 3 and tcp_ok >= 2:
            lines.append("  ✓ Global internet — HTTPS to major sites OK")
        elif https_ok >= 1:
            lines.append("  ⚠ Semi-connected — some international sites reachable")
        else:
            lines.append("  ✗ Limited international access from this network")

        if dns_hijack:
            lines.append("  ⚠ DNS hijack / ISP rewrite detected (local ≠ DoH)")
        else:
            lines.append("  ✓ No obvious DNS poisoning on probe domain")

        if https_ok < len(TEST_DOMAINS) and tcp_ok >= 2:
            lines.append("  ⚠ Possible DPI / SNI filtering (TCP OK but HTTPS fails)")
    else:
        lines.append(f"  Client not in Iran ({cc}) — use as baseline reference.")

    lines.extend([
        "",
        _section("Notes"),
        "  National Information Network cannot be confirmed remotely with certainty.",
        "  Use Remote Server Toolkit to test from an Iran VPS directly.",
        "  Pair with DNS Health on your front domain for poisoning checks.",
        "",
    ])
    return "\n".join(lines)


def build_national_network_report_sync(**kwargs) -> str:
    return asyncio.run(build_national_network_report(**kwargs))
