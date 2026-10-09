"""Infrastructure similarity — computed match between configs."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.config_parser import parse_input
from network.cdn_detector import lookup_ip_intelligence
from tools.datacenter_registry import identify_provider
from tools.ip_probe import resolve_host
from tools.output_labels import HEURISTIC, MEASURED
from utils.helpers import is_ip_address


def _profile(config) -> dict:
    return {
        "protocol": (config.protocol.value if config.protocol else "").lower(),
        "transport": (config.transport_type.value if config.transport_type else "").lower(),
        "port": config.port or 443,
        "reality": bool(config.reality),
        "tls": bool(config.tls),
        "sni": (config.sni or config.host or "").lower(),
        "address": (config.address or "").lower(),
        "cdn": None,
        "dc": None,
        "country": None,
    }


async def _enrich_profile(prof: dict, progress: Optional[Callable[[str], None]] = None) -> None:
    addr = prof["address"]
    if not addr or prof.get("_enriched"):
        return
    ip = addr if is_ip_address(addr) else await resolve_host(addr)
    if not ip:
        return
    if progress:
        progress(f"IP lookup {ip}...")
    intel = await lookup_ip_intelligence(ip)
    prof["country"] = intel.country_code
    prof["cdn"] = intel.cdn_detected
    providers = identify_provider(asn=intel.asn or "", org=intel.organization or "", isp=intel.isp or "")
    for p in providers:
        if p.tunnel_origin or p.cdn_front:
            prof["dc"] = p.name
            break
    if not prof["dc"] and intel.is_datacenter:
        prof["dc"] = intel.organization
    prof["_enriched"] = True


def _similarity(a: dict, b: dict) -> tuple[int, list[str]]:
    """Weighted field match — computed from parsed config + IP lookup."""
    weights = [
        ("protocol", 15),
        ("transport", 15),
        ("port", 10),
        ("reality", 10),
        ("tls", 5),
        ("sni", 10),
        ("cdn", 15),
        ("dc", 10),
        ("country", 10),
    ]
    total = 0
    earned = 0
    details: list[str] = []
    for field, w in weights:
        total += w
        va, vb = a.get(field), b.get(field)
        if field in ("reality", "tls"):
            match = va == vb
        elif field == "sni":
            match = bool(va and vb and (va == vb or va in vb or vb in va))
        else:
            match = bool(va and vb and va == vb)
        if match:
            earned += w
            details.append(f"  ✓ {field}: {va}")
        else:
            details.append(f"  ✗ {field}: {va or '—'} vs {vb or '—'}")
    pct = int(round(100 * earned / total)) if total else 0
    return pct, details


async def compare_infrastructure(
    text_a: str,
    text_b: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    text_a, text_b = text_a.strip(), text_b.strip()
    if not text_a or not text_b:
        return "Paste two configs (share links or JSON) to compare."

    ca = parse_input(text_a)
    cb = parse_input(text_b)
    if not ca or not cb:
        return "Could not parse one or both configs."

    pa = _profile(ca[0])
    pb = _profile(cb[0])
    await _enrich_profile(pa, progress)
    await _enrich_profile(pb, progress)

    pct, details = _similarity(pa, pb)

    lines = [
        "Infrastructure Similarity Engine",
        "═" * 58,
        "",
        f"  Similarity: {pct}% (computed from parsed fields + IP lookup)",
        f"  Note: percentage is field-weight match {HEURISTIC} — not ML inference.",
        "",
        "── Config A ──",
        f"  {ca[0].address}:{ca[0].port}  {pa['protocol']}/{pa['transport']}",
        f"  CDN: {pa.get('cdn') or '—'}  DC: {pa.get('dc') or '—'}  CC: {pa.get('country') or '—'}",
        "",
        "── Config B ──",
        f"  {cb[0].address}:{cb[0].port}  {pb['protocol']}/{pb['transport']}",
        f"  CDN: {pb.get('cdn') or '—'}  DC: {pb.get('dc') or '—'}  CC: {pb.get('country') or '—'}",
        "",
        "── Field comparison ──",
    ]
    lines.extend(details)

    lines.extend(["", "── Interpretation ──"])
    if pct >= 85:
        lines.append("  Very similar stack — likely same architecture pattern.")
    elif pct >= 65:
        lines.append("  Moderately similar — shared CDN/DC or protocol choices.")
    elif pct >= 40:
        lines.append("  Partial overlap — different origin or transport.")
    else:
        lines.append("  Different infrastructure profiles.")

    return "\n".join(lines)


def compare_infrastructure_sync(**kwargs) -> str:
    return asyncio.run(compare_infrastructure(**kwargs))
