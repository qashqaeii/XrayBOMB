"""Cloudflare colo / edge POP finder via cdn-cgi/trace."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

import httpx

from tools.cloudflare_ranges import _cidr_to_sample_ips, fetch_cloudflare_cidrs
from tools.ip_probe import probe_ip, resolve_host
from tools.output_labels import MEASURED
from utils.helpers import is_ip_address

_HTTP = {"timeout": 12.0, "trust_env": False, "follow_redirects": True}

# IATA → city label (public airport codes used by Cloudflare colo field)
COLO_LABELS: dict[str, str] = {
    "FRA": "Frankfurt",
    "AMS": "Amsterdam",
    "LHR": "London",
    "CDG": "Paris",
    "IST": "Istanbul",
    "DXB": "Dubai",
    "MRS": "Marseille",
    "WAW": "Warsaw",
    "HEL": "Helsinki",
    "VIE": "Vienna",
    "MXP": "Milan",
    "ARN": "Stockholm",
    "OTP": "Bucharest",
    "SOF": "Sofia",
    "BAH": "Bahrain",
}


async def _cf_trace(ip: Optional[str] = None) -> dict[str, str]:
    url = f"https://{ip}/cdn-cgi/trace" if ip else "https://1.1.1.1/cdn-cgi/trace"
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get(url)
            r.raise_for_status()
            out: dict[str, str] = {}
            for line in r.text.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
            return out
    except Exception:
        return {}


async def find_cloudflare_colo(
    target: str = "",
    scan_ips: bool = False,
    max_ips: int = 5,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    lines = [
        "Cloudflare Colo Finder",
        "═" * 58,
        "",
        f"  Source: Cloudflare /cdn-cgi/trace endpoint {MEASURED}",
        "",
    ]

    if target.strip():
        t = target.strip()
        ip = t if is_ip_address(t) else await resolve_host(t)
        if not ip:
            return f"Could not resolve: {t}"
        if progress:
            progress(f"Tracing via {ip}...")
        data = await _cf_trace(ip)
        lines.extend(_format_trace(data, ip))
    else:
        if progress:
            progress("Default trace via 1.1.1.1...")
        data = await _cf_trace(None)
        lines.extend(_format_trace(data, "1.1.1.1 (default)"))

    if scan_ips:
        lines.extend(["", "── Scan Cloudflare IPs (your route to edge) ──"])
        if progress:
            progress("Loading Cloudflare IP list...")
        cidrs = await fetch_cloudflare_cidrs()
        sample_ips: list[str] = []
        for cidr in cidrs[:5]:
            sample_ips.extend(_cidr_to_sample_ips(cidr, count=max_ips))
        sample_ips = sample_ips[:max_ips]
        seen_colos: set[str] = set()
        for ip in sample_ips:
            if progress:
                progress(f"Trace {ip}...")
            tr = await _cf_trace(ip)
            colo = tr.get("colo", "?")
            if colo in seen_colos:
                continue
            seen_colos.add(colo)
            probe = await probe_ip(ip, samples=3)
            city = COLO_LABELS.get(colo, colo)
            lines.append(
                f"  {ip:<16} colo={colo} ({city})  "
                f"avg {probe.avg_ms or '—'} ms  tls={'OK' if probe.tls_ok else 'FAIL'}"
            )

    lines.extend([
        "",
        "  colo = IATA airport code of Cloudflare edge serving your request.",
        "  Scan finds which POPs answer from your network (anycast).",
    ])
    return "\n".join(lines)


def _format_trace(data: dict[str, str], label: str) -> list[str]:
    if not data:
        return [f"  Trace failed for {label}"]
    colo = data.get("colo", "—")
    city = COLO_LABELS.get(colo, "—")
    rows = [
        f"  Via          : {label}",
        f"  colo (POP)   : {colo} — {city}",
        f"  ip           : {data.get('ip', '—')}",
        f"  loc          : {data.get('loc', '—')}",
        f"  tls          : {data.get('tls', '—')}",
        f"  http         : {data.get('http', '—')}",
        f"  warp         : {data.get('warp', '—')}",
        f"  visit_scheme : {data.get('visit_scheme', '—')}",
    ]
    fl = data.get("fl")
    if fl:
        rows.append(f"  flags (fl)   : {fl}")
    return rows


def find_cloudflare_colo_sync(**kwargs) -> str:
    return asyncio.run(find_cloudflare_colo(**kwargs))
