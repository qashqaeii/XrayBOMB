"""CDN route comparator — side-by-side live probes from your network."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from dns_analyzer.resolver import analyze_dns, reverse_dns
from network.cdn_detector import detect_cdn, lookup_ip_intelligence
from tools.ip_probe import probe_host, resolve_host
from tools.output_labels import HEURISTIC, MEASURED
from utils.helpers import is_ip_address


async def _analyze_side(label: str, target: str, port: int, samples: int) -> dict:
    target = target.strip().lower()
    out: dict = {"label": label, "target": target, "error": None}
    if not target:
        out["error"] = "empty"
        return out

    ip = target if is_ip_address(target) else await resolve_host(target)
    if not ip and not is_ip_address(target):
        dns = await analyze_dns(target)
        ips = dns.all_resolved_ips or dns.a_records or []
        ip = ips[0] if ips else None
    if not ip:
        out["error"] = "DNS failed"
        return out

    host = target if not is_ip_address(target) else ip
    probe = await probe_host(host if not is_ip_address(target) else ip, port=port, samples=samples)
    ptr = await reverse_dns(ip)
    intel = await lookup_ip_intelligence(ip, ptr)
    cdn, conf = detect_cdn(ip, intel.organization or intel.isp, ptr, intel.asn)

    out.update({
        "ip": ip,
        "probe": probe,
        "intel": intel,
        "cdn": cdn,
        "cdn_conf": conf,
        "ptr": ptr,
    })
    return out


async def compare_cdn_routes(
    target_a: str,
    target_b: str,
    port: int = 443,
    samples: int = 6,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    if progress:
        progress("Probing CDN A...")
    a = await _analyze_side("CDN A", target_a, port, samples)
    if progress:
        progress("Probing CDN B...")
    b = await _analyze_side("CDN B", target_b, port, samples)

    lines = [
        "CDN Route Comparator",
        "═" * 72,
        "",
        f"  All latency/loss values {MEASURED}",
        f"  CDN labels {HEURISTIC}",
        "",
        f"  {'Metric':<22} {'CDN A':<24} {'CDN B':<24}",
        "  " + "─" * 68,
    ]

    def _row(metric: str, va: str, vb: str) -> None:
        lines.append(f"  {metric:<22} {va:<24} {vb:<24}")

    def _fmt_side(s: dict) -> tuple[str, ...]:
        if s.get("error"):
            return (s["target"] or "—",) + ("ERR",) * 6
        p = s["probe"]
        return (
            s["target"],
            s["ip"],
            s.get("cdn") or "none",
            f"{p.avg_ms or '—'} ms",
            f"{p.p95_ms or '—'} ms",
            f"{p.packet_loss_pct:.0f}%",
            str(p.score),
        )

    fa = _fmt_side(a)
    fb = _fmt_side(b)
    _row("Target", fa[0], fb[0])
    _row("Resolved IP", fa[1], fb[1])
    _row("CDN detected", fa[2], fb[2])
    _row("Avg TCP", fa[3], fb[3])
    _row("P95 TCP", fa[4], fb[4])
    _row("Packet loss", fa[5], fb[5])
    _row("Route score", fa[6], fb[6])

    lines.extend(["", "── Verdict (from measured latency) ──"])
    if a.get("error") or b.get("error"):
        lines.append("  Incomplete — fix DNS/target errors and retry.")
    else:
        pa, pb = a["probe"], b["probe"]
        if pa.score > pb.score:
            lines.append(f"  → {target_a} wins on measured score ({pa.score} vs {pb.score})")
        elif pb.score > pa.score:
            lines.append(f"  → {target_b} wins on measured score ({pb.score} vs {pa.score})")
        else:
            lines.append(f"  → Tie on score ({pa.score}) — compare P95 and loss.")
        if pa.p95_ms and pb.p95_ms:
            diff = abs(pa.p95_ms - pb.p95_ms)
            lines.append(f"  P95 delta: {diff:.0f} ms")

    return "\n".join(lines)


def compare_cdn_routes_sync(**kwargs) -> str:
    return asyncio.run(compare_cdn_routes(**kwargs))
