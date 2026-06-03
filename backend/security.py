"""Security analysis and deployment detection."""

from __future__ import annotations

from typing import Optional

from backend.models import (
    DeploymentAnalysis,
    DeploymentGuess,
    DNSAnalysis,
    ParsedConfig,
    ReproductionGuide,
    ReproductionItem,
    SecurityFinding,
    SecurityRecommendation,
    SecurityReport,
    TLSAnalysis,
    ConnectivityResult,
    IPIntelligence,
)
from utils.helpers import is_ip_address


def analyze_security(
    config: ParsedConfig,
    tls: TLSAnalysis,
    connectivity: ConnectivityResult,
    network: list[IPIntelligence],
) -> SecurityReport:
    """Generate security report with score."""
    findings: list[SecurityFinding] = []
    score = 100

    # TLS check
    if config.tls or config.reality:
        if tls.enabled and not tls.certificate_expired:
            findings.append(SecurityFinding(
                category="TLS", severity="info", title="TLS Enabled",
                description="Transport layer security is active.", passed=True,
            ))
        elif tls.certificate_expired:
            findings.append(SecurityFinding(
                category="TLS", severity="high", title="Expired Certificate",
                description="TLS certificate has expired.", passed=False,
            ))
            score -= 25
        elif connectivity.tls_handshake.value == "Invalid":
            findings.append(SecurityFinding(
                category="TLS", severity="high", title="TLS Handshake Failed",
                description="Could not complete TLS handshake.", passed=False,
            ))
            score -= 20
    else:
        findings.append(SecurityFinding(
            category="TLS", severity="high", title="No TLS",
            description="Connection is not encrypted with TLS.", passed=False,
        ))
        score -= 30

    # Reality
    if config.reality:
        findings.append(SecurityFinding(
            category="Reality", severity="info", title="Reality Protocol Active",
            description="REALITY obfuscation is enabled — strong anti-detection.", passed=True,
        ))
        score = min(100, score + 5)
    else:
        findings.append(SecurityFinding(
            category="Reality", severity="low", title="Reality Not Used",
            description="REALITY protocol is not enabled.", passed=True,
        ))

    # Weak cipher
    if tls.weak_cipher:
        findings.append(SecurityFinding(
            category="Cipher", severity="high", title="Weak Cipher Detected",
            description=f"Weak cipher suite: {tls.cipher_suite}", passed=False,
        ))
        score -= 20

    # Allow insecure
    if config.allow_insecure:
        findings.append(SecurityFinding(
            category="TLS", severity="medium", title="Certificate Verification Disabled",
            description="allowInsecure is enabled — MITM risk.", passed=False,
        ))
        score -= 15

    # Fingerprint
    if config.fingerprint:
        findings.append(SecurityFinding(
            category="Fingerprint", severity="info", title="TLS Fingerprint Set",
            description=f"Browser fingerprint: {config.fingerprint}", passed=True,
        ))
    else:
        if config.tls and not config.reality:
            findings.append(SecurityFinding(
                category="Fingerprint", severity="medium", title="No TLS Fingerprint",
                description="Default TLS fingerprint may be detectable.", passed=False,
            ))
            score -= 5

    # CDN exposure
    cdn_detected = any(ip.cdn_detected for ip in network)
    if cdn_detected:
        findings.append(SecurityFinding(
            category="CDN", severity="info", title="CDN Fronting Detected",
            description="Traffic appears routed through a CDN.", passed=True,
        ))
    elif not is_ip_address(config.address):
        findings.append(SecurityFinding(
            category="Exposure", severity="medium", title="Direct Domain Exposure",
            description="Domain resolves directly without CDN fronting.", passed=False,
        ))
        score -= 5

    # Metadata leak
    if config.remark and len(config.remark) > 50:
        findings.append(SecurityFinding(
            category="Metadata", severity="low", title="Long Remark Field",
            description="Remark contains extensive metadata.", passed=False,
        ))
        score -= 2

    # Origin exposure via IP
    if is_ip_address(config.address):
        findings.append(SecurityFinding(
            category="Exposure", severity="medium", title="Direct IP Connection",
            description="Config connects directly to IP — origin may be exposed.", passed=False,
        ))
        score -= 10

    score = max(0, min(100, score))

    recommendations: list[SecurityRecommendation] = []
    potential = score

    if not config.tls and not config.reality:
        recommendations.append(SecurityRecommendation(
            title="Enable TLS or REALITY",
            description="Encrypt transport to protect traffic from inspection.",
            score_impact=30,
        ))
        potential = min(100, potential + 30)

    if config.tls and not config.reality and not config.fingerprint:
        recommendations.append(SecurityRecommendation(
            title="Set TLS Fingerprint",
            description="Use uTLS fingerprint (e.g. chrome) to reduce detectability.",
            score_impact=5,
        ))
        potential = min(100, potential + 5)

    if config.allow_insecure:
        recommendations.append(SecurityRecommendation(
            title="Disable allowInsecure",
            description="Enable proper certificate verification.",
            score_impact=15,
        ))
        potential = min(100, potential + 15)

    if not cdn_detected and not is_ip_address(config.address):
        recommendations.append(SecurityRecommendation(
            title="Use CDN Fronting",
            description="Route through Cloudflare/Arvan to hide origin IP.",
            score_impact=5,
        ))

    if config.transport_type.value == "WebSocket":
        recommendations.append(SecurityRecommendation(
            title="Migrate to XHTTP",
            description="WebSocket is deprecated in Xray 26+. Use XHTTP H2/H3.",
            score_impact=0,
        ))

    return SecurityReport(
        findings=findings,
        score=score,
        potential_score=potential,
        tls_enabled=config.tls,
        reality_enabled=config.reality,
        recommendations=recommendations,
    )


def analyze_deployment(
    config: ParsedConfig,
    dns: DNSAnalysis,
    network: list[IPIntelligence],
    connectivity: ConnectivityResult,
) -> DeploymentAnalysis:
    """Heuristic deployment type detection."""
    guesses: list[DeploymentGuess] = []
    uncertain: list[str] = []

    cdn_ips = [ip for ip in network if ip.cdn_detected]
    has_cname = bool(dns.cname_records)
    is_direct_ip = is_ip_address(config.address)

    # Direct VPS
    vps_conf = 0.25
    if is_direct_ip and not cdn_ips:
        vps_conf = 0.70
    elif not cdn_ips and not has_cname:
        vps_conf = 0.45
    guesses.append(DeploymentGuess(
        name="Direct VPS", confidence=vps_conf,
        description="Server appears to be a direct VPS/hosting node.",
    ))

    # CDN Fronted
    cdn_conf = 0.10
    cdn_type = None
    if cdn_ips:
        best = max(cdn_ips, key=lambda x: x.cdn_confidence)
        cdn_conf = min(0.95, best.cdn_confidence + 0.1)
        cdn_type = best.cdn_detected
    elif has_cname:
        cdn_conf = 0.55
    if config.sni and config.sni != config.address:
        cdn_conf = min(0.95, cdn_conf + 0.15)
    guesses.append(DeploymentGuess(
        name="CDN Fronted", confidence=cdn_conf,
        description="Traffic may be fronted through a CDN.",
    ))

    # Cloudflare specific
    cf_conf = 0.10
    if any(ip.cdn_detected == "Cloudflare" for ip in network):
        cf_conf = 0.90
    elif any("cloudflare" in r.lower() for r in dns.cname_records + dns.reverse_dns):
        cf_conf = 0.80
    guesses.append(DeploymentGuess(
        name="Cloudflare CDN", confidence=cf_conf,
        description="Cloudflare CDN fronting detected or suspected.",
    ))

    # Arvan CDN
    arvan_conf = 0.10
    if any(ip.cdn_detected == "ArvanCloud" for ip in network):
        arvan_conf = 0.90
    elif any("arvan" in r.lower() for r in dns.cname_records + dns.reverse_dns):
        arvan_conf = 0.75
    guesses.append(DeploymentGuess(
        name="Arvan CDN", confidence=arvan_conf,
        description="ArvanCloud CDN fronting detected or suspected.",
    ))

    # Other CDNs from network intelligence
    for cdn_label, guess_name in (
        ("Akamai", "Akamai CDN"),
        ("Fastly", "Fastly CDN"),
        ("CloudFront", "AWS CloudFront"),
        ("Bunny", "BunnyCDN"),
        ("Gcore", "Gcore CDN"),
    ):
        conf = 0.10
        if any(ip.cdn_detected == cdn_label for ip in network):
            conf = max(ip.cdn_confidence for ip in network if ip.cdn_detected == cdn_label)
        guesses.append(DeploymentGuess(
            name=guess_name, confidence=min(0.95, conf),
            description=f"{cdn_label} CDN fronting detected from IP/ASN.",
        ))

    # Reverse Proxy
    rp_conf = 0.30
    transport = config.transport_type.value
    if config.extra.get("type") == "xhttp":
        transport = "XHTTP"
    if transport in ("WebSocket", "gRPC", "HTTPUpgrade", "XHTTP"):
        rp_conf = 0.55
    if connectivity.http_response.value == "Valid":
        rp_conf = min(0.85, rp_conf + 0.20)
    guesses.append(DeploymentGuess(
        name="Reverse Proxy", confidence=rp_conf,
        description="Nginx/Caddy/HAProxy reverse proxy likely in use.",
    ))

    # Cloudflare Tunnel
    tunnel_conf = 0.15
    if any("cfargotunnel.com" in r.lower() for r in dns.cname_records):
        tunnel_conf = 0.85
    guesses.append(DeploymentGuess(
        name="Cloudflare Tunnel", confidence=tunnel_conf,
        description="Cloudflare Argo/Tunnel (cloudflared) deployment possible.",
    ))

    # SNI / IP fronting
    sni_front_conf = 0.10
    if is_ip_address(config.address) and config.sni and config.sni != config.address:
        sni_front_conf = 0.82
    guesses.append(DeploymentGuess(
        name="SNI Fronting", confidence=sni_front_conf,
        description="Client connects to IP but uses domain SNI (CDN/IP fronting).",
    ))

    # Reverse Tunnel
    rev_conf = 0.25
    remark = (config.remark or "").lower()
    if any(w in remark for w in ("frp", "nps", "ngrok", "bore", "rathole")):
        rev_conf = 0.65
    guesses.append(DeploymentGuess(
        name="Reverse Tunnel", confidence=rev_conf,
        description="Reverse tunnel (frp/nps/ngrok) — confirmed only via remark or server-side info.",
    ))

    # Multi Hop
    guesses.append(DeploymentGuess(
        name="Multi Hop", confidence=0.20,
        description="Multi-hop chain not visible in single-node config.",
    ))

    guesses.sort(key=lambda g: g.confidence, reverse=True)

    result = DeploymentAnalysis(guesses=guesses, cdn_type=cdn_type)

    if cdn_ips:
        result.cdn_backend_ips = [ip.ip for ip in cdn_ips]
    else:
        uncertain.append("IP Origin behind CDN")
        uncertain.append("CDN backend IPs")

    if is_direct_ip:
        result.real_server_ip = config.address
    else:
        uncertain.append("Real server IP")

    uncertain.extend([
        "Internal tunnel structure",
        "Routing rules",
        "Server-side scripts",
        "Load balancer type",
    ])

    if not any(g.confidence > 0.6 for g in guesses if "Reverse Proxy" in g.name):
        uncertain.append("Reverse proxy type")

    result.uncertain_fields = uncertain
    result.reverse_proxy_type = "Unknown (heuristic)" if rp_conf > 0.5 else None
    result.load_balancer_type = None

    return result


def apply_traceroute_to_deployment(deployment: DeploymentAnalysis, hop_count: Optional[int]) -> DeploymentAnalysis:
    if hop_count is not None:
        deployment.hop_count = hop_count
    return deployment


def build_reproduction_guide(config: ParsedConfig) -> ReproductionGuide:
    """Build reproduction guide showing what can/cannot be reconstructed."""
    reproducible: list[ReproductionItem] = []
    not_reproducible: list[ReproductionItem] = []

    fields = [
        ("Protocol", config.protocol.value, bool(config.protocol.value != "Unknown")),
        ("Address", config.address, bool(config.address)),
        ("Port", str(config.port), bool(config.port)),
        ("UUID", config.uuid, bool(config.uuid)),
        ("Password", "***" if config.password else None, bool(config.password)),
        ("Encryption", config.encryption, bool(config.encryption)),
        ("Flow", config.flow, bool(config.flow)),
        ("Security", config.security, bool(config.security)),
        ("TLS", str(config.tls), True),
        ("Reality", str(config.reality), True),
        ("Public Key", config.public_key, bool(config.public_key)),
        ("Short ID", config.short_id, bool(config.short_id)),
        ("SNI", config.sni, bool(config.sni)),
        ("Host", config.host, bool(config.host)),
        ("ALPN", config.alpn, bool(config.alpn)),
        ("WS Path", config.path, bool(config.path)),
        ("Service Name", config.service_name, bool(config.service_name)),
        ("Transport", config.transport_type.value, config.transport_type.value != "Unknown"),
    ]

    for name, value, can in fields:
        item = ReproductionItem(field=name, reproducible=can, value=value if can else None)
        if can:
            reproducible.append(item)
        else:
            item.reason = "Not present in config"
            not_reproducible.append(item)

    static_not_repro = [
        ("Internal Tunnel Structure", "Cannot infer tunnel topology from client config"),
        ("Origin IP behind CDN", "CDN masks real server IP"),
        ("Routing Rules", "Server-side routing not in share link"),
        ("Server Side Scripts", "Backend automation not exposed"),
        ("Firewall Rules", "Server firewall config not available"),
        ("Rate Limiting", "Server-side limits not visible"),
    ]
    for field, reason in static_not_repro:
        not_reproducible.append(ReproductionItem(field=field, reproducible=False, reason=reason))

    return ReproductionGuide(reproducible=reproducible, not_reproducible=not_reproducible)
