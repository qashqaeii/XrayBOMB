"""Curated infrastructure marketplace — VPS, CDN, DNS, domains (Iran tunnel context)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Category = Literal["vps", "cdn", "dns", "domain", "bare_metal", "iran_cdn", "marketplace"]
Role = Literal["tunnel_origin", "cdn_front", "relay", "domain_ssl", "all"]
Tier = Literal["budget", "mid", "premium"]


@dataclass(frozen=True)
class InfraListing:
    name: str
    website: str
    category: Category
    countries: tuple[str, ...]
    roles: tuple[Role, ...]
    tier: Tier
    payment: tuple[str, ...]
    tunnel_notes: str
    features: tuple[str, ...]
    probe_host: str = ""
    iran_editorial_score: int = 70
    signup_hint: str = ""
    asn_hint: str = ""
    dc_type: str = ""
    tunnel_protocols: tuple[str, ...] = ()
    price_from: str = ""
    regions: tuple[str, ...] = ()


# Editorial scores: suitability for operators building tunnels to Iran (not live ping).
LISTINGS: tuple[InfraListing, ...] = (
    # ── VPS / Cloud — Germany ──
    InfraListing(
        "Hetzner", "https://www.hetzner.com", "vps",
        ("Germany", "Finland", "Netherlands"), ("tunnel_origin", "relay", "all"),
        "budget", ("card", "paypal", "sepa"),
        "Top pick for REALITY/VLESS; FSN/HEL often stable from IR. Avoid overselling peak hours.",
        ("NVMe", "IPv6", "hourly billing", "ARM cheap"),
        "hetzner.com", 92, "Cloud → Create server → location FSN or HEL",
        "AS24940", "budget_vps", ("REALITY", "VLESS", "XHTTP"), "from €4/mo", ("FSN1", "NBG1", "HEL1"),
    ),
    InfraListing(
        "OVH / OVHcloud", "https://www.ovhcloud.com", "vps",
        ("Germany", "France", "Netherlands", "United States"), ("tunnel_origin", "relay", "all"),
        "mid", ("card", "paypal"),
        "Good price/performance; variable routes to Iran. Use EU West for selling configs.",
        ("DDoS basic", "many regions", "bare metal option"),
        "ovh.com", 85, "VPS or Dedicated → EU datacenter",
    ),
    InfraListing(
        "Contabo", "https://contabo.com", "vps",
        ("Germany", "Netherlands", "United States"), ("tunnel_origin", "all"),
        "budget", ("card", "paypal"),
        "Very cheap; can be oversubscribed — benchmark before bulk selling.",
        ("large disks", "unlimited traffic marketing"),
        "contabo.com", 72, "VPS → EU (DE/NL)",
    ),
    InfraListing(
        "Netcup", "https://www.netcup.eu", "vps",
        ("Germany",), ("tunnel_origin", "relay"),
        "budget", ("card", "paypal", "sepa"),
        "German DC; decent for mid-tier subs to Iran.",
        ("KVM", "snapshots"),
        "netcup.eu", 78, "Root Server / VPS → DE",
    ),
    InfraListing(
        "DigitalOcean", "https://www.digitalocean.com", "vps",
        ("Germany", "Netherlands", "United States", "Turkey"), ("tunnel_origin", "relay"),
        "mid", ("card", "paypal"),
        "FRA1/AMS3; easy API. Ping varies by Iranian ISP.",
        ("1-click apps", "firewalls", "floating IP"),
        "fra1.digitalocean.com", 80, "Create Droplet → Frankfurt or Amsterdam",
    ),
    InfraListing(
        "Vultr", "https://www.vultr.com", "vps",
        ("Germany", "Netherlands", "United States", "Turkey"), ("tunnel_origin", "relay"),
        "mid", ("card", "paypal", "crypto"),
        "Many locations; use benchmark tool before choosing region.",
        ("hourly", "block storage"),
        "fra-ping.vultr.com", 79, "Deploy → Frankfurt / Istanbul",
    ),
    InfraListing(
        "Linode / Akamai", "https://www.linode.com", "vps",
        ("Germany", "Netherlands", "United States"), ("tunnel_origin", "relay"),
        "mid", ("card", "paypal"),
        "Frankfurt/Newark; reliable API for automation.",
        ("managed K8s", "object storage"),
        "speedtest.frankfurt.linode.com", 77, "Create Linode → EU",
    ),
    InfraListing(
        "Scaleway", "https://www.scaleway.com", "vps",
        ("France", "Netherlands"), ("tunnel_origin", "relay"),
        "mid", ("card"),
        "French DC; good when OVH path is congested.",
        ("ARM instances", "K8s"),
        "scaleway.com", 76, "Instances → PAR or AMS",
    ),
    InfraListing(
        "UpCloud", "https://upcloud.com", "vps",
        ("Finland", "Germany", "Netherlands"), ("tunnel_origin", "relay"),
        "premium", ("card"),
        "HEL1 popular for Iran paths; higher price, often stable.",
        ("max IOPS", "private networks"),
        "upcloud.com", 84, "Deploy → Helsinki or Frankfurt",
    ),
    # ── Finland / Turkey / France ──
    InfraListing(
        "Creanova (FI hosting)", "https://www.creanova.org", "vps",
        ("Finland",), ("tunnel_origin",),
        "mid", ("card", "invoice"),
        "Nordic routes sometimes excellent from Irancell/MCI.",
        ("FI local support",),
        "creanova.org", 70, "Check VPS in Finland",
    ),
    InfraListing(
        "Turhost / Turkiye providers", "https://www.turhost.com", "vps",
        ("Turkey",), ("tunnel_origin", "relay"),
        "mid", ("card", "local TR"),
        "Geographic proximity; test DPI — not always best for REALITY.",
        ("local support", "TR payment"),
        "turhost.com", 74, "VPS → Istanbul",
    ),
    InfraListing(
        "Guzel Hosting TR", "https://www.guzel.net.tr", "vps",
        ("Turkey",), ("tunnel_origin",),
        "budget", ("local TR",),
        "Budget TR VPS; verify latency with Host Benchmark tool.",
        ("cPanel option",),
        "guzel.net.tr", 68, "Sanal sunucu",
    ),
    # ── CDN & DNS (global) ──
    InfraListing(
        "Cloudflare", "https://www.cloudflare.com", "cdn",
        ("Global",), ("cdn_front", "dns", "all"),
        "budget", ("card",),
        "Free CDN/DNS; use Clean IP Finder + DNS-only A for REALITY fronts.",
        ("Workers", "WAF", "Spectrum"),
        "www.cloudflare.com", 95, "Add site → DNS → use clean IP in A record",
        "AS13335", "cdn_edge", ("REALITY", "WS", "gRPC"), "free tier", ("Global PoP",),
    ),
    InfraListing(
        "Bunny CDN", "https://bunny.net", "cdn",
        ("Global",), ("cdn_front",),
        "budget", ("card", "paypal"),
        "Cheap CDN if not on Cloudflare; good for static decoy sites.",
        ("pull zones", "storage"),
        "bunny.net", 75, "Create Pull Zone",
    ),
    InfraListing(
        "Fastly", "https://www.fastly.com", "cdn",
        ("Global",), ("cdn_front",),
        "premium", ("card", "enterprise"),
        "Enterprise CDN; rarely needed for typical IR tunnel sellers.",
        ("edge compute",),
        "fastly.com", 60, "Sales-led signup",
    ),
    InfraListing(
        "Gcore CDN", "https://gcore.com", "cdn",
        ("Global", "Germany", "Turkey"), ("cdn_front", "relay"),
        "mid", ("card",),
        "Alternative CDN with EU/TR POPs.",
        ("DDoS", "streaming"),
        "gcore.com", 72, "CDN → create resource",
    ),
    # ── Iran / regional CDN ──
    InfraListing(
        "Arvan Cloud", "https://www.arvancloud.ir", "iran_cdn",
        ("Iran", "Global"), ("cdn_front", "dns"),
        "mid", ("rial", "card IR"),
        "Iranian CDN/DNS; for domestic landing pages, not origin for blocked tunnels.",
        ("Iran PoP", "video", "DNS"),
        "www.arvancloud.ir", 88, "پنل → CDN / DNS",
    ),
    InfraListing(
        "Parspack", "https://parspack.com", "iran_cdn",
        ("Iran",), ("cdn_front", "domain_ssl"),
        "mid", ("rial",),
        "Iran hosting/CDN; compliance/local billing.",
        ("Iran support",),
        "parspack.com", 82, "هاست / CDN",
    ),
    InfraListing(
        "Asiatech / IranServer", "https://www.iranserver.com", "vps",
        ("Iran",), ("relay", "domain_ssl"),
        "mid", ("rial",),
        "Inside-IR server — bridge/relay only, not public tunnel exit for filtered protocols.",
        ("local DC",),
        "iranserver.com", 65, "سرور مجازی ایران",
    ),
    # ── Domains ──
    InfraListing(
        "Cloudflare Registrar", "https://www.cloudflare.com/products/registrar/", "domain",
        ("Global",), ("domain_ssl", "cdn_front"),
        "budget", ("card",),
        "At-cost domains + same-panel DNS for tunnel fronts.",
        ("WHOIS privacy", "integrated DNS"),
        "cloudflare.com", 90, "Register domain → DNS in CF",
    ),
    InfraListing(
        "Namecheap", "https://www.namecheap.com", "domain",
        ("Global",), ("domain_ssl",),
        "budget", ("card", "paypal", "crypto"),
        "Cheap domains; point NS to Cloudflare after purchase.",
        ("easy DNS",),
        "namecheap.com", 85, "Domain → set NS to CF",
    ),
    InfraListing(
        "Porkbun", "https://porkbun.com", "domain",
        ("Global",), ("domain_ssl",),
        "budget", ("card", "crypto"),
        "Low-cost TLDs; good for disposable front domains.",
        ("WHOIS privacy",),
        "porkbun.com", 83, "Buy domain → change NS",
    ),
    InfraListing(
        "Njalla", "https://njal.la", "domain",
        ("Global",), ("domain_ssl",),
        "premium", ("crypto",),
        "Privacy-focused; higher trust for sensitive fronts.",
        ("anonymized WHOIS",),
        "njal.la", 78, "Register → DNS to CF",
    ),
    # ── Marketplaces / compare ──
    InfraListing(
        "LowEndBox", "https://lowendbox.com", "marketplace",
        ("Global",), ("all",),
        "budget", ("varies",),
        "Deals blog — verify provider reputation before Iran bulk sales.",
        ("community deals",),
        "lowendbox.com", 55, "Browse deals → verify with DC Finder",
    ),
    InfraListing(
        "VPSBenchmarks", "https://www.vpsbenchmarks.com", "marketplace",
        ("Global",), ("all",),
        "mid", ("n/a",),
        "Compare CPU/disk scores — complement with in-app Datacenter Finder.",
        ("Screener", "trials"),
        "vpsbenchmarks.com", 70, "Screener → region filter",
    ),
    InfraListing(
        "HostingBench", "https://www.hostingbench.com", "marketplace",
        ("Global",), ("all",),
        "mid", ("n/a",),
        "Provider comparisons; cross-check latency from your ISP.",
        ("reviews",),
        "hostingbench.com", 65, "Compare VPS providers",
    ),
    # ── Bare metal / premium exit ──
    InfraListing(
        "Hetzner Dedicated", "https://www.hetzner.com/dedicated-rootserver", "bare_metal",
        ("Germany", "Finland"), ("tunnel_origin",),
        "premium", ("card", "sepa"),
        "High-traffic sellers; consistent performance for thousands of users.",
        ("1 Gbit+", "ECC RAM"),
        "hetzner.com", 91, "Server Auction / EX line",
    ),
    InfraListing(
        "OVH Dedicated", "https://www.ovhcloud.com/bare-metal", "bare_metal",
        ("France", "Germany"), ("tunnel_origin",),
        "premium", ("card",),
        "Scale-up path from OVH VPS; watch IR routing during peak.",
        ("anti-DDoS",),
        "ovh.com", 86, "Bare Metal → EU",
    ),
    InfraListing(
        "AWS Lightsail", "https://aws.amazon.com/lightsail/", "vps",
        ("Germany", "United States"), ("tunnel_origin", "relay"),
        "mid", ("card",),
        "Simple AWS VMs; higher cost, stable network.",
        ("snapshots", "static IP"),
        "aws.amazon.com", 74, "Lightsail → EU region",
    ),
    InfraListing(
        "Google Cloud CE", "https://cloud.google.com/compute", "vps",
        ("Germany", "Netherlands", "Finland"), ("tunnel_origin",),
        "premium", ("card",),
        "e2-micro free tier limited; good for testing, costly at scale.",
        ("global network",),
        "cloud.google.com", 73, "Compute Engine → europe-west",
    ),
    InfraListing(
        "Azure VM", "https://azure.microsoft.com", "vps",
        ("Germany", "Netherlands", "United States"), ("tunnel_origin", "relay"),
        "premium", ("card",),
        "Enterprise; use if clients require compliance branding.",
        ("SLA", "express route"),
        "azure.microsoft.com", 70, "Create VM → West Europe",
    ),
    InfraListing(
        "BuyVM", "https://buyvm.net", "vps",
        ("United States", "Netherlands"), ("tunnel_origin",),
        "budget", ("card", "crypto", "paypal"),
        "Budget US/EU; check blocklists with IP Reputation Scanner.",
        ("DDoS filter option", "storage slabs"),
        "buyvm.net", 71, "Stock check → order KVM",
    ),
    InfraListing(
        "RackNerd", "https://www.racknerd.com", "vps",
        ("United States",), ("tunnel_origin",),
        "budget", ("card", "paypal"),
        "Low-cost US; often higher latency to Iran — rank with benchmarks.",
        ("promo cycles",),
        "racknerd.com", 62, "Promo VPS pages",
    ),
)

from tools.infrastructure_listings_extra import EXTRA_LISTINGS  # noqa: E402

LISTINGS = LISTINGS + EXTRA_LISTINGS

DC_TYPE_LABELS: dict[str, str] = {
    "budget_vps": "Budget VPS",
    "premium_vps": "Premium VPS",
    "hyperscaler": "Hyperscaler Cloud",
    "bare_metal": "Dedicated / Bare Metal",
    "colo_vps": "Colocation / Carrier VPS",
    "cdn_edge": "CDN Edge",
    "budget_cdn": "Budget CDN",
    "enterprise_cdn": "Enterprise CDN",
    "dns_host": "DNS Hosting",
    "registrar": "Domain Registrar",
    "ir_local": "Iran Local Host",
    "marketplace": "Marketplace / Compare",
}

CATEGORY_LABELS: dict[Category, str] = {
    "vps": "VPS / Cloud Servers",
    "cdn": "CDN (Global)",
    "dns": "DNS Providers",
    "domain": "Domain Registrars",
    "bare_metal": "Dedicated / Bare Metal",
    "iran_cdn": "Iran CDN / Local Host",
    "marketplace": "Marketplaces & Comparisons",
}

ROLE_LABELS: dict[Role, str] = {
    "tunnel_origin": "Tunnel exit (REALITY / VLESS origin)",
    "cdn_front": "CDN / front domain masking",
    "relay": "Relay / bridge hop",
    "domain_ssl": "Domain & SSL front",
    "all": "All roles",
}

TIER_LABELS: dict[Tier, str] = {
    "budget": "Budget",
    "mid": "Mid-range",
    "premium": "Premium",
}

MARKETPLACE_COUNTRIES: tuple[str, ...] = (
    "Any region",
    "Germany",
    "Netherlands",
    "Finland",
    "France",
    "Turkey",
    "United Kingdom",
    "United States",
    "United Arab Emirates",
    "Iran (local services)",
    "Global",
)

DC_TYPES: tuple[str, ...] = ("All DC types",) + tuple(DC_TYPE_LABELS.values())
