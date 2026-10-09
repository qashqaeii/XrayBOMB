"""Iranian ISP matrix — ASN data and EU region recommendations."""

from __future__ import annotations

from typing import Callable, Optional

from tools.output_labels import EDITORIAL


ISPS: tuple[str, ...] = (
    "All ISPs (overview)",
    "MCI (Hamrah-e Aval)",
    "Irancell",
    "Rightel",
    "Mokhaberat / ADSL",
    "Shatel",
    "Asiatech",
    "Pars Online",
    "HiWEB",
    "Other / WiFi ISP",
)

ISP_DATA: dict[str, dict] = {
    "MCI": {
        "asns": ("AS197207", "AS196874"),
        "prefixes": "Mobile core — see bgp.tools AS197207",
        "share": "~45% mobile",
        "best_regions": ("Germany", "Netherlands", "France"),
        "best_providers": ("Hetzner FSN", "OVH DE", "Netcup"),
        "cdn": "Cloudflare DE clean IP",
        "dns_risk": "Medium",
        "route_eu": "Measure with Multi-Region Ping",
        "route_tr": "Optional relay — validate first",
        "route_ae": "Higher latency — backup path",
        "notes": (
            "Stable EU paths; variable CF edge latency by time of day.",
            "REALITY + port 443 recommended over plain WS.",
            "Re-benchmark 21:00–01:00 IR peak filtering.",
        ),
    },
    "Irancell": {
        "asns": ("AS44244", "AS57218", "AS60330"),
        "prefixes": "MTN Irancell — bgp.tools AS44244",
        "share": "~45% mobile",
        "best_regions": ("Finland", "Germany", "Netherlands"),
        "best_providers": ("Hetzner HEL1", "UpCloud HEL", "Hetzner FSN"),
        "cdn": "Cloudflare + DNS Health check",
        "dns_risk": "Medium",
        "route_eu": "HEL1 often strong — live test required",
        "route_tr": "Variable",
        "route_ae": "Backup only",
        "notes": (
            "HEL1 Finland often strong; verify with Datacenter Finder.",
            "Packet loss >5% → switch DC before changing protocol.",
            "ASN must be AS44244 family when testing from Irancell data.",
        ),
    },
    "Rightel": {
        "asns": ("AS57235", "AS25184"),
        "prefixes": "Rightel — bgp.tools AS57235",
        "share": "~8% mobile",
        "best_regions": ("Germany", "Finland"),
        "best_providers": ("Hetzner", "OVH"),
        "cdn": "Cloudflare",
        "dns_risk": "Medium",
        "route_eu": "Benchmark empirically",
        "route_tr": "Optional",
        "route_ae": "Rare",
        "notes": (
            "Smaller base — benchmark empirically like Irancell.",
            "Same REALITY stack as MCI/Irancell.",
        ),
    },
    "Mokhaberat": {
        "asns": ("AS16322", "AS58224"),
        "prefixes": "TCI fixed — bgp.tools AS16322",
        "share": "Fixed ADSL/FTTH",
        "best_regions": ("Germany", "Turkey relay optional"),
        "best_providers": ("OVH", "Hetzner"),
        "cdn": "Cloudflare + mandatory DNS Health",
        "dns_risk": "High",
        "route_eu": "Good when DNS clean",
        "route_tr": "Relay option after EU validated",
        "route_ae": "Higher jitter",
        "notes": (
            "High DNS poisoning risk — always run DNS Health on front domain.",
            "DoH mismatch = fix DNS before launch.",
            "Turkey relay only after EU exit validated.",
        ),
    },
    "Shatel": {
        "asns": ("AS31549",),
        "prefixes": "Shatel — bgp.tools AS31549",
        "share": "Major fixed ISP",
        "best_regions": ("Germany", "Netherlands"),
        "best_providers": ("Hetzner", "OVH", "Leaseweb"),
        "cdn": "Cloudflare + DNS Health",
        "dns_risk": "Medium–High",
        "route_eu": "Measure live — often good off-peak",
        "route_tr": "Usable for relay",
        "route_ae": "Backup",
        "notes": (
            "Fixed line — DNS hijack common on filtered domains.",
            "Use Operator Comparison Lab on Shatel connection.",
        ),
    },
    "Asiatech": {
        "asns": ("AS25184", "AS16322"),
        "prefixes": "Asiatech — bgp.tools AS25184",
        "share": "Fixed / regional",
        "best_regions": ("Germany",),
        "best_providers": ("Hetzner", "Contabo"),
        "cdn": "Cloudflare",
        "dns_risk": "Medium",
        "route_eu": "Live test required",
        "route_tr": "Optional",
        "route_ae": "Rare",
        "notes": (
            "Verify ASN on Client Profile — may share upstream with TCI.",
        ),
    },
    "Pars Online": {
        "asns": ("AS16322", "AS57218"),
        "prefixes": "Pars Online — check live ASN",
        "share": "Fixed ISP",
        "best_regions": ("Germany",),
        "best_providers": ("OVH", "Hetzner"),
        "cdn": "Cloudflare",
        "dns_risk": "High",
        "route_eu": "Measure",
        "route_tr": "Optional relay",
        "route_ae": "Backup",
        "notes": (
            "DNS poisoning frequent — DNS Propagation + Health mandatory.",
        ),
    },
    "HiWEB": {
        "asns": ("AS56402",),
        "prefixes": "HiWEB — bgp.tools AS56402",
        "share": "Fixed ISP",
        "best_regions": ("Germany",),
        "best_providers": ("Hetzner", "OVH"),
        "cdn": "Cloudflare",
        "dns_risk": "Medium",
        "route_eu": "Live benchmark",
        "route_tr": "Optional",
        "route_ae": "Rare",
        "notes": (
            "Run Iran Filtering Test Suite during peak hours.",
        ),
    },
    "Other": {
        "asns": ("varies",),
        "prefixes": "Use Client Profile ASN",
        "share": "WiFi / regional ISPs",
        "best_regions": ("Germany",),
        "best_providers": ("Hetzner", "OVH"),
        "cdn": "Cloudflare",
        "dns_risk": "Variable",
        "route_eu": "Measure",
        "route_tr": "Optional",
        "route_ae": "Backup",
        "notes": (
            "Upstream ASN may differ from retail brand — use Client Profile ASN.",
            "Host Benchmark origin before go-live.",
        ),
    },
}


def build_isp_guide(isp: str, progress: Optional[Callable[[str], None]] = None) -> str:
    if progress:
        progress("Loading ISP matrix...")

    lines = [
        "Iran ISP Operator Matrix",
        "═" * 58,
        "",
        f"  Selected: {isp}",
        f"  Note: ASN values are public registry facts.",
        f"        Market share, DNS risk, routes, VPS picks = {EDITORIAL.strip('()')}.",
        "        Use Multi-Region Ping / Datacenter Finder for live data.",
        "",
    ]

    if isp.startswith("All"):
        lines.extend([
            "── ASN reference ──",
            f"  {'ISP':<14} {'Primary ASN':<22} {'DNS ref':<12} {'EU ref'}",
            "  " + "─" * 62,
        ])
        for name, data in ISP_DATA.items():
            lines.append(
                f"  {name:<14} {data['asns'][0]:<22} {data['dns_risk']:<12} {data['best_regions'][0]}"
            )
        lines.extend([
            "",
            "── Route notes (verify live — not simulated RTT) ──",
            f"  {'ISP':<14} {'EU':<22} {'Turkey':<14} {'UAE'}",
            "  " + "─" * 62,
        ])
        for name, data in ISP_DATA.items():
            lines.append(
                f"  {name:<14} {data['route_eu']:<22} {data['route_tr']:<14} {data['route_ae']}"
            )
        lines.extend([
            "",
            "── Recommended VPS/CDN (reference — verify with Datacenter Finder) ──",
        ])
        for name, data in ISP_DATA.items():
            lines.append(f"  {name:<14} → {', '.join(data['best_providers'][:3])} | CDN: {data['cdn']}")
        return "\n".join(lines)

    key = next((k for k in ISP_DATA if k in isp), "Other")
    data = ISP_DATA[key]

    lines.extend([
        "── Network identity ──",
        f"  ASNs         : {', '.join(data['asns'])}",
        f"  Prefixes     : {data['prefixes']}",
        f"  Market share : {data['share']}",
        f"  DNS risk     : {data['dns_risk']}",
        "",
        "── Route matrix (live verification required) ──",
        f"  Europe       : {data['route_eu']} {EDITORIAL}",
        f"  Turkey       : {data['route_tr']} {EDITORIAL}",
        f"  UAE          : {data['route_ae']} {EDITORIAL}",
        "",
        "── Best infrastructure (reference) ──",
        f"  EU regions   : {', '.join(data['best_regions'])} {EDITORIAL}",
        f"  VPS providers: {', '.join(data['best_providers'])} {EDITORIAL}",
        f"  CDN          : {data['cdn']} {EDITORIAL}",
        "",
        f"── {key} — operator notes ──",
    ])
    for note in data["notes"]:
        lines.append(f"  • {note}")

    lines.extend([
        "",
        "── Verification tools ──",
        "  Client Network Profile → confirm ASN matches target ISP",
        "  Multi-Region Ping      → measured EU/TR/AE latency",
        "  Operator Comparison Lab→ compare ISPs on different SIMs",
        "  Datacenter Finder      → live route to EU VPS",
        "  Clean IP Finder        → Cloudflare front tuning",
        "",
    ])
    return "\n".join(lines)
