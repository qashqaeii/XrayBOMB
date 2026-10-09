"""Lightweight TCP port / service availability scanner."""

from __future__ import annotations

import asyncio
import socket
from typing import Callable, Optional

from tools.ip_probe import resolve_host

PRESETS: dict[str, tuple[int, ...]] = {
    "Tunnel / Xray (443,8443,2053,2083,2096,10443)": (443, 8443, 2053, 2083, 2096, 10443, 4433),
    "Cloudflare CDN ports": (443, 2053, 2083, 2096, 8443, 8880, 8080),
    "Web stack (80,443,8080,8443)": (80, 443, 8080, 8443),
    "Admin exposure (22,3389,5432,3306)": (22, 3389, 5432, 3306),
    "Full scan (18 ports)": (22, 80, 443, 465, 587, 993, 995, 2053, 2083, 2096, 8080, 8443, 8880, 10443, 4433, 3306, 5432, 3389),
}

SERVICE_HINTS: dict[int, str] = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS / REALITY",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    2053: "CF alt HTTPS",
    2083: "cPanel SSL",
    2096: "WHM SSL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP alt",
    8443: "HTTPS alt",
    8880: "CF HTTP",
    10443: "alt TLS",
    3306: "MySQL",
    4433: "alt TLS",
}


async def _tcp_open(host: str, port: int, timeout: float = 2.5) -> tuple[bool, Optional[float]]:
    t0 = asyncio.get_event_loop().time()
    try:
        conn = asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        reader, writer = await conn
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        ms = (asyncio.get_event_loop().time() - t0) * 1000
        return True, ms
    except Exception:
        return False, None


async def scan_ports_async(
    host: str,
    ports: tuple[int, ...],
    *,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host:
        return "Enter a hostname or IP."

    if progress:
        progress(f"Resolving {host}...")
    ip = await resolve_host(host)
    if not ip:
        return f"DNS resolution failed for {host}"

    if progress:
        progress(f"Scanning {len(ports)} TCP ports on {ip}...")

    sem = asyncio.Semaphore(12)

    async def check(port: int):
        async with sem:
            ok, ms = await _tcp_open(ip, port)
            return port, ok, ms

    results = await asyncio.gather(*[check(p) for p in ports])
    open_ports = [(p, ms) for p, ok, ms in results if ok]
    closed = [p for p, ok, _ in results if not ok]

    lines = [
        f"Port Scanner — {host} ({ip})",
        "═" * 52,
        "",
        f"  Ports tested : {len(ports)}",
        f"  Open         : {len(open_ports)}",
        f"  Closed/filtered : {len(closed)}",
        "",
        "── Open ports ──",
        f"  {'Port':<6} {'Service':<18} {'Connect ms':>10}",
        "  " + "─" * 38,
    ]
    for port, ms in sorted(open_ports, key=lambda x: x[0]):
        hint = SERVICE_HINTS.get(port, "unknown")
        ms_s = f"{ms:.0f}" if ms is not None else "—"
        lines.append(f"  {port:<6} {hint:<18} {ms_s:>10}")

    if not open_ports:
        lines.append("  (none — firewall, wrong IP, or ISP filtering)")

    lines.extend(["", "── Closed / filtered ──"])
    lines.append("  " + ", ".join(str(p) for p in sorted(closed)) or "—")

    lines.extend([
        "",
        "── Tunnel readiness ──",
        f"  443 REALITY-ready : {'yes' if any(p == 443 for p, _ in open_ports) else 'no'}",
        f"  CF alt ports open : {', '.join(str(p) for p, _ in open_ports if p in (2053,2083,2096,8443)) or 'none'}",
        f"  Admin exposed     : {', '.join(str(p) for p, _ in open_ports if p in (22,3389,3306,5432)) or 'none'}",
        "",
    ])
    return "\n".join(lines)


def scan_ports_sync(
    host: str,
    ports: tuple[int, ...],
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    return asyncio.run(scan_ports_async(host, ports, progress=progress))
