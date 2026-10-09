"""Iran filtering test suite — TLS, HTTP, DNS live probes."""

from __future__ import annotations

import asyncio
import socket
from typing import Callable, Optional

import httpx

from dns_analyzer.resolver import _doh_lookup

_HTTP = {"timeout": 12.0, "trust_env": False, "follow_redirects": True}


async def _test_https(domain: str) -> tuple[str, bool, str]:
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get(f"https://{domain}", headers={"User-Agent": "Mozilla/5.0"})
            return domain, True, f"HTTP {r.status_code}"
    except Exception as exc:
        return domain, False, str(exc)[:60]


async def _test_quic_hint(domain: str) -> tuple[str, bool, str]:
    """UDP/443 not fully tested — check HTTP/3 alt-svc header as hint."""
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.head(f"https://{domain}")
            alt = r.headers.get("alt-svc", "")
            if "h3" in alt.lower():
                return domain, True, f"HTTP/3 advertised ({alt[:40]})"
            return domain, False, "no h3 alt-svc (QUIC may still work)"
    except Exception as exc:
        return domain, False, str(exc)[:50]


async def run_iran_filtering_suite(
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    lines = [
        "Iran Filtering Test Suite",
        "═" * 58,
        "",
        "  Live probes from YOUR network — results vary by ISP and time.",
        "",
    ]

    https_targets = [
        "www.google.com",
        "www.youtube.com",
        "twitter.com",
        "www.instagram.com",
        "api.telegram.org",
        "github.com",
        "1.1.1.1",
    ]

    if progress:
        progress("HTTPS/TLS tests...")
    lines.append("── TLS / HTTPS ──")
    https_ok = 0
    for domain in https_targets:
        _, ok, status = await _test_https(domain)
        if ok:
            https_ok += 1
        mark = "✓" if ok else "✗"
        lines.append(f"  {mark} {domain:<28} {status}")

    if progress:
        progress("QUIC hints...")
    lines.extend(["", "── QUIC (HTTP/3 hint via alt-svc) ──"])
    for domain in ("cloudflare.com", "www.google.com"):
        _, ok, status = await _test_quic_hint(domain)
        lines.append(f"  {'✓' if ok else '·'} {domain:<28} {status}")

    if progress:
        progress("DNS tests...")
    lines.extend(["", "── DNS ──"])
    probe = "instagram.com"
    local_ips: list[str] = []
    try:
        loop = asyncio.get_event_loop()
        infos = await loop.getaddrinfo(probe, None, family=socket.AF_INET)
        local_ips = sorted({i[4][0] for i in infos})
    except Exception as exc:
        lines.append(f"  Local DNS {probe}: FAIL ({exc})")
    else:
        lines.append(f"  Local DNS {probe}: {', '.join(local_ips) or 'none'}")

    doh = await _doh_lookup(probe)
    for prov, ips in doh.items():
        lines.append(f"  DoH {prov} {probe}: {', '.join(ips) or 'none'}")

    dns_poison = bool(local_ips and doh and any(set(local_ips) != set(v) for v in doh.values()))

    lines.extend([
        "",
        "── Summary ──",
        f"  HTTPS reachable: {https_ok}/{len(https_targets)}",
        f"  DNS poisoning  : {'suspected' if dns_poison else 'not detected on probe'}",
        "",
        "  Re-run during peak hours (21:00–01:00 IR) for worst-case filtering.",
        "  Use National Network Detector for broader connectivity picture.",
    ])
    return "\n".join(lines)


def run_iran_filtering_suite_sync(**kwargs) -> str:
    return asyncio.run(run_iran_filtering_suite(**kwargs))
