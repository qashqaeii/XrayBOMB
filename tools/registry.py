"""Tool registry — categories and metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    tool_id: str
    category: str
    icon: str
    title: str
    subtitle: str
    description: str
    tags: tuple[str, ...] = ()


TOOL_SPECS: tuple[ToolSpec, ...] = (
    # ── Network Context ──
    ToolSpec(
        "client_profile", "Network Context", "📍",
        "Client Network Profile",
        "IPv4/IPv6, ISP, ASN, rDNS, connection type",
        "Full network identity via ipwho.is — geo, timezone, reverse DNS, mobile/FTTH hint.",
        ("geo", "isp", "asn", "ipv6"),
    ),
    ToolSpec(
        "isp_guide", "Network Context", "📡",
        "Iran ISP Operator Matrix",
        "MCI, Irancell, Shatel, Asiatech, HiWEB…",
        "ASN reference, route notes (EU/TR/AE), DNS risk, VPS/CDN picks per operator.",
        ("mci", "irancell", "shatel", "asn"),
    ),
    ToolSpec(
        "national_network", "Network Context", "🇮🇷",
        "National Network Detector",
        "Global internet vs filtering hints",
        "Live TCP/HTTPS tests, DNS hijack probe, DPI hints — from your network.",
        ("filtering", "dns", "dpi"),
    ),
    ToolSpec(
        "operator_comparison", "Network Context", "📊",
        "Operator Comparison Lab",
        "Compare ISPs — live EU matrix",
        "ASN reference + live Multi-Region Ping from your current operator.",
        ("mci", "irancell", "rtt"),
    ),
    # ── Cloudflare & CDN ──
    ToolSpec(
        "clean_ip", "Cloudflare & CDN", "☁",
        "Cloudflare Clean IP Finder",
        "CF edge scan from your network",
        "Latency, TLS, SNI, DNSBL — ranked clean IPs for DNS A records.",
        ("cloudflare", "clean-ip", "cdn"),
    ),
    ToolSpec(
        "cdn_detector", "Cloudflare & CDN", "🌐",
        "CDN Detector",
        "Cloudflare, Arvan, Akamai, Fastly…",
        "Identify CDN from domain/IP — ASN, rDNS, CNAME heuristics.",
        ("cdn", "cloudflare", "arvan"),
    ),
    ToolSpec(
        "fake_cdn", "Cloudflare & CDN", "🎭",
        "Fake CDN Detector",
        "Real CDN vs direct VPS origin",
        "Compare claimed CDN with actual IP classification — reverse proxy hints.",
        ("cdn", "fronting", "reality"),
    ),
    ToolSpec(
        "cf_colo_finder", "Cloudflare & CDN", "✈",
        "Cloudflare Colo Finder",
        "POP / edge IATA codes (FRA, AMS…)",
        "Live /cdn-cgi/trace — colo, TLS, optional CF IP scan from your route.",
        ("cloudflare", "pop", "colo"),
    ),
    ToolSpec(
        "cdn_route_compare", "Cloudflare & CDN", "⚖",
        "CDN Route Comparator",
        "Compare CDN A vs CDN B live",
        "Side-by-side latency, loss, CDN detection from your network.",
        ("cdn", "compare", "latency"),
    ),
    ToolSpec(
        "ip_checker", "Cloudflare & CDN", "🛡",
        "IP Reputation Scanner",
        "DC/CDN registry + threat intel",
        "Connectivity, TLS, ASN, CDN/DC identification, blocklist, tunnel suitability.",
        ("blocklist", "reputation", "cdn"),
    ),
    ToolSpec(
        "host_benchmark", "Cloudflare & CDN", "📶",
        "Host Latency Benchmark",
        "TCP min/avg/p95 to any host:port",
        "Compare nodes and provider endpoints before publishing configs.",
        ("ping", "latency", "tcp"),
    ),
    ToolSpec(
        "port_scanner", "Cloudflare & CDN", "🔌",
        "Port & Service Scanner",
        "Xray + Cloudflare port presets",
        "443, 8443, 2053, CF CDN ports — tunnel readiness summary.",
        ("ports", "firewall", "xray"),
    ),
    # ── VPS & Datacenter ──
    ToolSpec(
        "remote_server", "VPS & Remote Server", "🖥",
        "Remote Server Manager",
        "Encrypted vault + live SSH console",
        "Save servers locally (Fernet), quick IR↔World tests, interactive terminal.",
        ("ssh", "vps", "deploy"),
    ),
    ToolSpec(
        "datacenter", "VPS & Datacenter", "🏢",
        "Datacenter Finder",
        "10+ providers per country, parallel test",
        "Hetzner, OVH, Contabo, DO, Leaseweb — live benchmark ranked by your route.",
        ("vps", "hetzner", "benchmark"),
    ),
    ToolSpec(
        "multi_dc_compare", "VPS & Datacenter", "⚖",
        "Multi-Country DC Compare",
        "Compare 2–3 countries side-by-side",
        "Parallel benchmark Germany vs Finland vs NL — pick best origin for your ISP.",
        ("compare", "country", "benchmark"),
    ),
    ToolSpec(
        "vps_deploy_check", "VPS & Datacenter", "✅",
        "VPS Pre-Deploy Validator",
        "Go/no-go before installing Xray",
        "Live TCP/TLS, blocklist, ports, PTR, checklist — after you buy a VPS.",
        ("deploy", "checklist", "xray"),
    ),
    ToolSpec(
        "vps_ip_ranker", "VPS & Datacenter", "📊",
        "VPS IP Ranker",
        "Rank your server IPs by route quality",
        "Paste multiple VPS IPs — measured latency, TLS, blocklist from your network.",
        ("rank", "vps", "compare"),
    ),
    ToolSpec(
        "asn_dc_lookup", "VPS & Datacenter", "🔍",
        "ASN & Datacenter Identifier",
        "Who owns this IP?",
        "ipwho.is + geo + DC/CDN classification + provider catalog match.",
        ("asn", "datacenter", "lookup"),
    ),
    ToolSpec(
        "dc_fingerprint", "VPS & Datacenter", "🔬",
        "Datacenter Fingerprint",
        "OVH, Hetzner, DO, AWS, Azure…",
        "Identify hosting provider from IP — ASN registry match.",
        ("ovh", "hetzner", "aws"),
    ),
    # ── DNS Intelligence ──
    ToolSpec(
        "dns_health", "DNS Intelligence", "🌐",
        "DNS Health Analyzer",
        "Records, DoH, CDN NS detection",
        "A/AAAA/CNAME/TXT, local vs DoH mismatch, filtering detection.",
        ("dns", "doh", "cdn"),
    ),
    ToolSpec(
        "dns_propagation", "DNS Intelligence", "📡",
        "DNS Propagation Monitor",
        "Cloudflare, Google, Quad9, OpenDNS",
        "Compare A records across resolvers — propagation or ISP rewrite.",
        ("dns", "propagation", "doh"),
    ),
    ToolSpec(
        "dnssec_validator", "DNS Intelligence", "🔒",
        "DNSSEC Validator",
        "DS, DNSKEY, chain validation",
        "Check DNSSEC signing data and resolver validation status.",
        ("dnssec", "dns", "security"),
    ),
    ToolSpec(
        "geodns_analyzer", "DNS Intelligence", "🌏",
        "GeoDNS Analyzer",
        "Regional DNS routing",
        "Compare A records across resolvers — GeoDNS or ISP rewrite hints.",
        ("geodns", "dns", "routing"),
    ),
    # ── Latency & Routing ──
    ToolSpec(
        "multi_region_ping", "Latency & Routing", "🌍",
        "Multi-Region Ping Matrix",
        "Frankfurt, Amsterdam, Istanbul, Dubai…",
        "Live TCP latency matrix from your network to EU/TR/AE endpoints.",
        ("ping", "eu", "routing"),
    ),
    ToolSpec(
        "mtr_visualizer", "Latency & Routing", "🛤",
        "MTR / Traceroute Visualizer",
        "Hops, ASN, country, latency graph",
        "Live tracert/traceroute with per-hop geo enrichment and ASCII graph.",
        ("mtr", "traceroute", "hops"),
    ),
    ToolSpec(
        "packet_loss_heatmap", "Latency & Routing", "🔥",
        "Packet Loss Heatmap",
        "Loss & jitter across regions",
        "ASCII heatmap of TCP sample success/fail per EU/TR/AE target.",
        ("loss", "jitter", "heatmap"),
    ),
    ToolSpec(
        "anycast_detector", "Latency & Routing", "📡",
        "Anycast Detector",
        "Anycast vs unicast DNS",
        "Repeated DNS resolution — unique IP count and DoH comparison.",
        ("anycast", "dns", "cdn"),
    ),
    # ── TLS Intelligence ──
    ToolSpec(
        "tls_scanner", "TLS Intelligence", "🔐",
        "TLS & Certificate Scanner",
        "Version, cipher, ALPN, CA, expiry",
        "Live TLS handshake analysis and certificate intelligence.",
        ("tls", "cert", "cipher"),
    ),
    # ── Xray / Sing-box ──
    ToolSpec(
        "config_topology", "Xray / Sing-box", "🗺",
        "Infrastructure Mapper",
        "Topology + reproduction from config",
        "Parse link → CDN/origin/DC layers, ASCII topology, reproduction checklist.",
        ("topology", "xray", "mapper"),
    ),
    ToolSpec(
        "infra_similarity", "Xray / Sing-box", "🧬",
        "Infrastructure Similarity Engine",
        "Compare two configs — computed match %",
        "Weighted field match from parsed config + live IP lookup — no fake ML score.",
        ("similarity", "compare", "topology"),
    ),
    ToolSpec(
        "reality_analyzer", "Xray / Sing-box", "🛡",
        "REALITY Analyzer",
        "SNI, pbk, shortId, fingerprint",
        "Parse VLESS REALITY fields and server-side checklist.",
        ("reality", "vless", "sni"),
    ),
    ToolSpec(
        "subscription_analyzer", "Xray / Sing-box", "📋",
        "Subscription Analyzer",
        "Nodes, countries, DCs, CDNs",
        "Fetch sub URL — protocol stats, geo, datacenter and CDN classification.",
        ("sub", "panel", "vless"),
    ),
    ToolSpec(
        "subscription_health", "Xray / Sing-box", "✓",
        "Subscription Link Checker",
        "Protocol, transport, port stats",
        "Quick health check — REALITY ratio, host diversity, port distribution.",
        ("sub", "health", "stats"),
    ),
    # ── Iran-specific ──
    ToolSpec(
        "iran_filtering", "Iran Tools", "🚧",
        "Iran Filtering Test Suite",
        "TLS, HTTP, DNS live probes",
        "Test reachability of filtered sites from your ISP — no fake scores.",
        ("filtering", "dpi", "dns"),
    ),
    ToolSpec(
        "arvan_inspector", "Iran Tools", "☁",
        "ArvanCloud Inspector",
        "POP, route, ASN, cache headers",
        "Arvan CDN/DNS analysis — live HTTP headers and route from your network.",
        ("arvan", "cdn", "iran"),
    ),
    ToolSpec(
        "national_cdn", "Iran Tools", "🇮🇷",
        "National CDN Analyzer",
        "Arvan, Afranet, Asiatech, Pars Online",
        "Detect Iran national CDN/hosting patterns via DNS and ASN heuristics.",
        ("iran", "cdn", "arvan"),
    ),
    # ── Infrastructure & Buying ──
    ToolSpec(
        "infrastructure_market", "Infrastructure & Buying", "🛒",
        "Infrastructure Marketplace",
        "60+ VPS, CDN, DNS, domain vendors",
        "Filter by country, DC type, role, budget — buy links, ASN, protocols, live probe.",
        ("vps", "cdn", "datacenter", "buy"),
    ),
    ToolSpec(
        "tunnel_planner", "Infrastructure & Buying", "🗺",
        "Tunnel Route Planner",
        "Architecture + provider mapping",
        "Stack design, Datacenter Finder targets, marketplace picks, CDN checklist.",
        ("architecture", "reality", "tunnel"),
    ),
)

CATEGORIES: tuple[str, ...] = tuple(dict.fromkeys(t.category for t in TOOL_SPECS))
