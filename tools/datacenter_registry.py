"""Datacenter, CDN, and VPS provider registry — identification and tunnel metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderRegistryEntry:
    name: str
    category: str  # vps, cdn, dns, bare_metal, hyperscaler, ir_local
    asn_patterns: tuple[str, ...]
    name_patterns: tuple[str, ...]
    tunnel_origin: bool = False
    cdn_front: bool = False
    iran_score: int = 70
    notes: str = ""


REGISTRY: tuple[ProviderRegistryEntry, ...] = (
    # ── VPS / Cloud ──
    ProviderRegistryEntry("Hetzner", "vps", ("AS24940", "AS213230"), ("hetzner",), True, False, 92,
                          "Top REALITY/VLESS origin; FSN1/NBG1/HEL1"),
    ProviderRegistryEntry("OVH / OVHcloud", "vps", ("AS16276", "AS35540"), ("ovh", "ovhcloud"), True, False, 85,
                          "EU/US bare metal + VPS; variable IR routes"),
    ProviderRegistryEntry("Contabo", "vps", ("AS51167",), ("contabo",), True, False, 72,
                          "Budget; benchmark oversubscription"),
    ProviderRegistryEntry("DigitalOcean", "hyperscaler", ("AS14061",), ("digitalocean",), True, False, 80,
                          "FRA1/AMS3/NYC; API-friendly"),
    ProviderRegistryEntry("Vultr", "vps", ("AS20473",), ("vultr", "choopa"), True, False, 79, "Many POPs"),
    ProviderRegistryEntry("Linode / Akamai", "vps", ("AS63949",), ("linode", "akamai"), True, False, 77, ""),
    ProviderRegistryEntry("AWS", "hyperscaler", ("AS16509",), ("amazon", "aws"), True, False, 74, "Lightsail/EC2"),
    ProviderRegistryEntry("Google Cloud", "hyperscaler", ("AS15169",), ("google cloud", "googleusercontent"), True, False, 73, ""),
    ProviderRegistryEntry("Microsoft Azure", "hyperscaler", ("AS8075",), ("azure", "microsoft"), True, False, 70, ""),
    ProviderRegistryEntry("Scaleway", "vps", ("AS12876",), ("scaleway", "online.net"), True, False, 76, "FR/NL"),
    ProviderRegistryEntry("UpCloud", "vps", ("AS202053",), ("upcloud",), True, False, 84, "HEL1 strong for IR"),
    ProviderRegistryEntry("Netcup", "vps", ("AS197540",), ("netcup",), True, False, 78, "DE KVM"),
    ProviderRegistryEntry("Leaseweb", "bare_metal", ("AS60781",), ("leaseweb",), True, False, 82, "NL scale"),
    ProviderRegistryEntry("M247", "vps", ("AS9009",), ("m247",), True, False, 75, "EU colo network"),
    ProviderRegistryEntry("Ionos / 1&1", "vps", ("AS8560",), ("ionos", "1und1"), True, False, 74, "DE/FR/US"),
    ProviderRegistryEntry("HostEurope", "vps", ("AS34011",), ("hosteurope",), True, False, 71, ""),
    ProviderRegistryEntry("BuyVM", "vps", ("AS53667",), ("buyvm", "frantech"), True, False, 71, "Budget US/EU"),
    ProviderRegistryEntry("RackNerd", "vps", ("AS36352",), ("racknerd",), True, False, 62, "Promo US VPS"),
    ProviderRegistryEntry("Cherry Servers", "vps", ("AS59642",), ("cherry",), True, False, 76, "Baltics/EU"),
    ProviderRegistryEntry("Time4VPS", "vps", ("AS16125",), ("time4vps",), True, False, 70, "LT budget"),
    # ── CDN ──
    ProviderRegistryEntry("Cloudflare", "cdn", ("AS13335",), ("cloudflare",), False, True, 95,
                          "Primary tunnel front; clean IP workflow"),
    ProviderRegistryEntry("Akamai", "cdn", ("AS20940",), ("akamai",), False, True, 65, "Enterprise"),
    ProviderRegistryEntry("Fastly", "cdn", ("AS54113",), ("fastly",), False, True, 60, ""),
    ProviderRegistryEntry("Bunny CDN", "cdn", ("AS200325",), ("bunny",), False, True, 75, "Budget pull CDN"),
    ProviderRegistryEntry("Gcore", "cdn", ("AS199524",), ("gcore",), False, True, 72, "EU/TR POPs"),
    ProviderRegistryEntry("KeyCDN", "cdn", ("AS394536",), ("keycdn",), False, True, 68, ""),
    ProviderRegistryEntry("StackPath", "cdn", ("AS33438",), ("stackpath",), False, True, 66, ""),
    ProviderRegistryEntry("Arvan Cloud", "ir_local", ("AS202468",), ("arvan",), False, True, 88, "Iran CDN/DNS"),
    ProviderRegistryEntry("Parspack", "ir_local", ("AS202468",), ("parspack",), False, True, 82, "Iran hosting"),
    ProviderRegistryEntry("CDN77", "cdn", ("AS60068",), ("cdn77",), False, True, 70, ""),
    ProviderRegistryEntry("QUIC.cloud", "cdn", ("AS13335",), ("quic.cloud",), False, True, 78, "LiteSpeed CDN"),
    # ── Iran mobile / ISP (client-side identification) ──
    ProviderRegistryEntry("MCI", "ir_isp", ("AS197207",), ("mci", "hamrah", "mobile communication company"), False, False, 0, ""),
    ProviderRegistryEntry("Irancell", "ir_isp", ("AS44244", "AS57218"), ("irancell", "mtn", "iran cell"), False, False, 0, ""),
    ProviderRegistryEntry("Rightel", "ir_isp", ("AS57235", "AS25184"), ("rightel",), False, False, 0, ""),
)


CDN_COMPARISON: tuple[dict[str, str], ...] = (
    {"name": "Cloudflare", "free_tier": "Yes", "ws_grpc": "Limited", "reality_dns": "DNS-only A", "iran_use": "Primary"},
    {"name": "Bunny CDN", "free_tier": "Trial", "ws_grpc": "No", "reality_dns": "Pull origin", "iran_use": "Decoy static"},
    {"name": "Gcore", "free_tier": "Trial", "ws_grpc": "Partial", "reality_dns": "CNAME", "iran_use": "Alt CDN"},
    {"name": "Arvan Cloud", "free_tier": "Yes (IR)", "ws_grpc": "Yes", "reality_dns": "Local DNS", "iran_use": "IR landing only"},
    {"name": "Fastly", "free_tier": "No", "ws_grpc": "Yes", "reality_dns": "Enterprise", "iran_use": "Rare"},
    {"name": "Akamai", "free_tier": "No", "ws_grpc": "Yes", "reality_dns": "Enterprise", "iran_use": "Rare"},
)


def identify_provider(*, asn: str = "", isp: str = "", org: str = "") -> list[ProviderRegistryEntry]:
    blob = f"{asn} {isp} {org}".lower()
    hits: list[ProviderRegistryEntry] = []
    for entry in REGISTRY:
        if any(p.lower() in blob for p in entry.asn_patterns):
            hits.append(entry)
            continue
        if any(p in blob for p in entry.name_patterns):
            hits.append(entry)
    return hits


def format_cdn_comparison_table() -> list[str]:
    lines = [
        "── CDN comparison (editorial reference — not measured) ──",
        f"  {'CDN':<14} {'Free':<6} {'WS/gRPC':<10} {'REALITY':<14} {'Iran role':<12}",
        "  " + "─" * 58,
    ]
    for row in CDN_COMPARISON:
        lines.append(
            f"  {row['name']:<14} {row['free_tier']:<6} {row['ws_grpc']:<10} "
            f"{row['reality_dns']:<14} {row['iran_use']:<12}"
        )
    return lines
