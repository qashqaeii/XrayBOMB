"""Infrastructure marketplace — catalog links + optional live TCP measurements only."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from tools.datacenter_registry import format_cdn_comparison_table
from tools.infrastructure_catalog import (
    CATEGORY_LABELS,
    DC_TYPE_LABELS,
    LISTINGS,
    ROLE_LABELS,
    TIER_LABELS,
    InfraListing,
)
from tools.ip_probe import probe_host, resolve_host


def _matches_country(item: InfraListing, country: str) -> bool:
    if country in ("Any region", "Any"):
        return True
    if country == "Global":
        return "Global" in item.countries
    if country == "Iran (local services)":
        return "Iran" in item.countries
    return country in item.countries or "Global" in item.countries


def _matches_category(item: InfraListing, category: str) -> bool:
    if category == "All categories":
        return True
    key = next((k for k, v in CATEGORY_LABELS.items() if v == category), None)
    return item.category == key if key else False


def _matches_role(item: InfraListing, role: str) -> bool:
    if role in ("All roles", "all"):
        return True
    key = next((k for k, v in ROLE_LABELS.items() if v == role), None)
    return (key in item.roles or "all" in item.roles) if key else False


def _matches_tier(item: InfraListing, tier: str) -> bool:
    if tier == "Any budget":
        return True
    key = next((k for k, v in TIER_LABELS.items() if v == tier), None)
    return item.tier == (key or tier)


def _matches_dc_type(item: InfraListing, dc_type: str) -> bool:
    if dc_type in ("All DC types", ""):
        return True
    key = next((k for k, v in DC_TYPE_LABELS.items() if v == dc_type), None)
    if not key:
        return True
    return item.dc_type == key


def filter_listings(
    *,
    country: str = "Any region",
    category: str = "All categories",
    role: str = "All roles",
    tier: str = "Any budget",
    dc_type: str = "All DC types",
) -> list[InfraListing]:
    out = [
        x for x in LISTINGS
        if _matches_country(x, country)
        and _matches_category(x, category)
        and _matches_role(x, role)
        and _matches_tier(x, tier)
        and _matches_dc_type(x, dc_type)
    ]
    out.sort(key=lambda x: x.name.lower())
    return out


async def _probe_listing(item: InfraListing, port: int) -> tuple[InfraListing, Optional[int], Optional[float], bool]:
    host = item.probe_host or item.website.replace("https://", "").replace("http://", "").split("/")[0]
    ip = await resolve_host(host)
    if not ip:
        return item, None, None, False
    pr = await probe_host(host, port=port, samples=4)
    return item, pr.score, pr.avg_ms, True


async def build_marketplace_report_async(
    *,
    country: str,
    category: str,
    role: str,
    tier: str,
    dc_type: str = "All DC types",
    live_probe: bool = False,
    probe_port: int = 443,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    items = filter_listings(
        country=country, category=category, role=role, tier=tier, dc_type=dc_type,
    )
    lines = [
        "Infrastructure Marketplace",
        "═" * 58,
        "",
        f"  Filters  : {country} | {category} | {role} | {tier} | {dc_type}",
        f"  Matches  : {len(items)} entries (public vendor links — not ranked without live probe)",
        f"  Catalog  : {len(LISTINGS)} total",
        "",
        "  Data policy: only live TCP probe scores are measured from your network.",
        "              Catalog fields (ASN, price hints) are reference — verify before purchase.",
        "",
    ]

    probe_map: dict[str, tuple[Optional[int], Optional[float]]] = {}
    if live_probe and items:
        if progress:
            progress("Live TCP probe (measured from your network)...")
        top = [x for x in items if x.probe_host][:15]
        if not top:
            top = items[:10]
        sem = asyncio.Semaphore(4)

        async def one(it: InfraListing):
            async with sem:
                return await _probe_listing(it, probe_port)

        results = await asyncio.gather(*[one(i) for i in top])
        measured = [(it, sc, avg) for it, sc, avg, ok in results if ok and sc is not None]
        measured.sort(key=lambda x: (-(x[1] or 0), x[0].name))
        for it, score, avg in measured:
            probe_map[it.name] = (score, avg)

    if probe_map:
        lines.append("── Measured from your network (live probe) ──")
        lines.append(f"  {'Name':<22} {'Score':>6} {'Avg ms':>8}  Website")
        lines.append("  " + "─" * 58)
        for name, (sc, avg) in sorted(probe_map.items(), key=lambda x: -(x[1][0] or 0)):
            it = next(i for i in items if i.name == name)
            lines.append(f"  {name:<22} {sc:>6} {avg or 0:>8.0f}  {it.website}")
        lines.append("")
    elif live_probe:
        lines.append("── Live probe ──")
        lines.append("  No successful measurements — check DNS/network.")
        lines.append("")

    lines.append("── Catalog (alphabetical — unmeasured) ──")
    lines.append(f"  {'Name':<22} {'Category':<16} {'ASN':<12} {'Website'}")
    lines.append("  " + "─" * 68)
    for it in items[:60]:
        cat = CATEGORY_LABELS.get(it.category, it.category)[:16]
        asn = (it.asn_hint or "—")[:12]
        lines.append(f"  {it.name:<22} {cat:<16} {asn:<12} {it.website}")

    lines.extend(["", "── Details (first 15) ──"])
    for it in items[:15]:
        lines.append("")
        lines.append(f"  ■ {it.name}")
        lines.append(f"      Website    : {it.website}")
        lines.append(f"      Category   : {CATEGORY_LABELS.get(it.category, it.category)}")
        if it.dc_type:
            lines.append(f"      DC type    : {DC_TYPE_LABELS.get(it.dc_type, it.dc_type)}")
        if it.asn_hint:
            lines.append(f"      ASN (ref)  : {it.asn_hint}")
        if it.regions:
            lines.append(f"      Regions    : {', '.join(it.regions)}")
        if it.price_from:
            lines.append(f"      Price ref  : {it.price_from}")
        lines.append(f"      Countries  : {', '.join(it.countries)}")
        lines.append(f"      Roles      : {', '.join(ROLE_LABELS.get(r, r) for r in it.roles)}")
        if it.tunnel_protocols:
            lines.append(f"      Protocols  : {', '.join(it.tunnel_protocols)}")
        if it.signup_hint:
            lines.append(f"      Buy        : {it.signup_hint}")
        if it.name in probe_map:
            sc, avg = probe_map[it.name]
            lines.append(f"      Measured   : score {sc}, avg {avg:.0f} ms (your network)")

    lines.append("")
    lines.extend(format_cdn_comparison_table())
    lines.extend([
        "",
        "── Verify before buying ──",
        "  • Datacenter Finder — live benchmark to your ISP",
        "  • IP Reputation — blocklist check on purchased IP",
        "",
    ])
    return "\n".join(lines)


def build_marketplace_report_sync(
    *,
    country: str = "Any region",
    category: str = "All categories",
    role: str = "All roles",
    tier: str = "Any budget",
    dc_type: str = "All DC types",
    live_probe: bool = False,
    probe_port: int = 443,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    return asyncio.run(
        build_marketplace_report_async(
            country=country, category=category, role=role, tier=tier, dc_type=dc_type,
            live_probe=live_probe, probe_port=probe_port, progress=progress,
        )
    )
