"""Tunnel route planner — architecture and provider mapping."""



from __future__ import annotations



from typing import Callable, Optional



from tools.infrastructure_catalog import LISTINGS

from tools.provider_catalog import COUNTRY_CATALOG





GOALS: tuple[str, ...] = (

    "Sell configs to Iran (REALITY / VLESS)",

    "Personal use (low detection)",

    "CDN-masked domain (Cloudflare front)",

    "Multi-hop relay (IR → EU)",

    "High traffic reseller (1000+ users)",

)



ORIGIN_COUNTRIES: tuple[str, ...] = tuple(COUNTRY_CATALOG.keys())





def _top_listings(country: str, limit: int = 5) -> list[str]:

    items = [

        x for x in LISTINGS

        if country in x.countries or "Global" in x.countries

        if x.category in ("vps", "bare_metal") and "tunnel_origin" in x.roles

    ]

    items.sort(key=lambda x: x.name.lower())
    return [f"{x.name} — {x.website}" for x in items[:limit]]





def build_tunnel_plan(

    goal: str,

    origin_country: str,

    use_cdn: bool = True,

    progress: Optional[Callable[[str], None]] = None,

) -> str:

    if progress:

        progress("Building architecture plan...")



    country = origin_country.split(" (")[0].strip() if " (" in origin_country else origin_country

    catalog = COUNTRY_CATALOG.get(country)

    dc_code = catalog.code if catalog else "?"



    lines = [

        "Tunnel Route Planner",

        "═" * 58,

        "",

        f"  Goal           : {goal}",

        f"  Origin country : {country} ({dc_code})",

        f"  CDN front      : {'Cloudflare (recommended)' if use_cdn else 'Direct IP (higher block risk)'}",

        f"  Benchmarkable  : {len(catalog.providers) if catalog else 0} providers in Datacenter Finder",

        "",

        "── Architecture ──",

    ]



    stacks = {

        "Sell": [

            "Iran client → REALITY or TLS+XHTTP → EU VPS origin",

            "Front domain → Cloudflare DNS (proxied or DNS-only per protocol)",

            "Panel → Xray-core, uTLS chrome, shortId rotation, 443/tcp",

        ],

        "Personal": [

            "Dedicated VPS (avoid shared promo IPs)",

            "REALITY + high-traffic SNI target",

            "Weekly Host Benchmark — routes shift seasonally",

        ],

        "CDN": [

            "Domain on Cloudflare → A record to clean IP",

            "DNS Health before launch — detect ISP poisoning",

            "REALITY: DNS-only; WS/gRPC: check CF orange-cloud limits",

        ],

        "Multi-hop": [

            f"IR relay (WireGuard internal) → EU exit ({country})",

            "EU hop runs REALITY; IR hop not advertised as public exit",

            "Use Infrastructure Marketplace for both hops",

        ],

        "reseller": [

            "Bare metal or Hetzner/OVH dedicated at scale",

            "Multiple EU regions for redundancy",

            "IP Reputation on every new origin IP",

        ],

    }



    if "Sell" in goal:

        key = "Sell"

    elif "Personal" in goal:

        key = "Personal"

    elif "CDN" in goal:

        key = "CDN"

    elif "Multi-hop" in goal:

        key = "Multi-hop"

    elif "reseller" in goal.lower():

        key = "reseller"

    else:

        key = "Sell"



    for s in stacks[key]:

        lines.append(f"  • {s}")



    if catalog:

        lines.extend(["", f"── Datacenter Finder targets ({country}) ──"])

        for p in catalog.providers:

            dtype = p.dc_type or "vps"

            lines.append(f"  • {p.name:<22} {p.asn_hint:<12} {dtype:<14} w={p.weight}")



    lines.extend(["", "── Marketplace picks (tunnel origin) ──"])

    for row in _top_listings(country):

        lines.append(f"  • {row}")



    if use_cdn:

        lines.extend([

            "",

            "── CDN stack ──",

            "  Primary  : Cloudflare (free) — Clean IP Finder for A record",

            "  Alt CDN  : Bunny.net, Gcore, QUIC.cloud (decoy/static)",

            "  Iran web : Arvan Cloud / Parspack (landing pages only)",

        ])



    lines.extend([

        "",

        "── Pre-launch checklist ──",

        "  □ Datacenter Finder winner purchased",

        "  □ Port Scanner: 443 open, SSH restricted",

        "  □ IP Reputation: no blocklist, score ≥70",

        "  □ DNS Health: no DoH mismatch on domain",

        "  □ Full Analyze: Iran score + Xray test pass",

        "",

    ])

    return "\n".join(lines)


