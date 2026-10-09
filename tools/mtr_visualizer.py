"""MTR / traceroute visualizer with hop ASN and country enrichment."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional
from network.geo import lookup_geo_ip
from network.traceroute import run_traceroute
from tools.ip_probe import resolve_host
from tools.output_labels import MEASURED
from utils.helpers import is_ip_address


async def _geo_for_ip(ip: str) -> tuple[str, str]:
    try:
        g = await lookup_geo_ip(ip)
        if g:
            cc = g.get("country_code") or "?"
            asn = (g.get("asn") or "—")
            if isinstance(g.get("connection"), dict):
                asn = g["connection"].get("asn") or asn
            return cc, str(asn)
    except Exception:
        pass
    return "?", "—"


def _bar(ms: Optional[float], width: int = 20) -> str:
    if ms is None:
        return "·" * width
    cap = 400.0
    n = min(width, max(1, int((ms / cap) * width)))
    return "█" * n + "·" * (width - n)


async def build_mtr_report(
    target: str,
    max_hops: int = 18,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    target = target.strip()
    if not target:
        return "Enter hostname or IP."

    host = target
    if not is_ip_address(target):
        if progress:
            progress(f"Resolving {target}...")
        ip = await resolve_host(target)
        if not ip:
            return f"DNS failed: {target}"
        host = ip

    if progress:
        progress(f"Traceroute to {host} (max {max_hops} hops)...")
    trace = await run_traceroute(host, max_hops=max_hops)

    lines = [
        "MTR / Traceroute Visualizer",
        "═" * 72,
        "",
        f"  Target   : {target}",
        f"  Resolved : {host}",
        f"  Hops     : {trace.hop_count or len(trace.hops)} {MEASURED}",
        "",
    ]

    if trace.errors:
        lines.extend(["── Errors ──"])
        for e in trace.errors:
            lines.append(f"  • {e}")
        lines.append("")

    if not trace.hops:
        lines.append("  No hop data — traceroute/tracert may be blocked or unavailable.")
        return "\n".join(lines)

    lines.extend([
        f"  {'Hop':>3}  {'IP':<16} {'ms':>7}  {'CC':<4} {'ASN':<14} Graph",
        "  " + "─" * 68,
    ])

    geo_cache: dict[str, tuple[str, str]] = {}
    prev_ms: Optional[float] = None

    for hop in trace.hops[:max_hops]:
        if hop.ip and hop.ip not in geo_cache:
            if progress:
                progress(f"Geo lookup hop {hop.hop} ({hop.ip})...")
            geo_cache[hop.ip] = await _geo_for_ip(hop.ip)

        cc, asn = geo_cache.get(hop.ip or "", ("?", "—"))
        ms = hop.latency_ms
        delta = ""
        if ms is not None and prev_ms is not None:
            d = ms - prev_ms
            delta = f" (+{d:.0f})" if d > 0 else ""
        if ms is not None:
            prev_ms = ms

        ip_s = hop.ip or "*"
        ms_s = f"{ms:.1f}" if ms is not None else "—"
        host_hint = f"  {hop.hostname}" if hop.hostname and hop.hostname != hop.ip else ""
        lines.append(
            f"  {hop.hop:>3}  {ip_s:<16} {ms_s:>7}{delta:<6}  {cc:<4} {asn:<14} {_bar(ms)}"
        )
        if host_hint:
            lines.append(f"       {host_hint.strip()}")

    lines.extend([
        "",
        "── Legend ──",
        "  Graph = relative latency per hop (not packet loss).",
        "  CC/ASN from ipwho.is per hop IP.",
        "  Many IR ISPs hide or rate-limit ICMP — * hops are normal.",
    ])
    return "\n".join(lines)


def build_mtr_report_sync(**kwargs) -> str:
    return asyncio.run(build_mtr_report(**kwargs))
