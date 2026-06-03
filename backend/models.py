"""Pydantic data models for config analysis."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ProtocolType(str, Enum):
    VLESS = "VLESS"
    VMESS = "VMESS"
    TROJAN = "Trojan"
    SHADOWSOCKS = "Shadowsocks"
    HYSTERIA2 = "Hysteria2"
    TUIC = "TUIC"
    WIREGUARD = "WireGuard"
    OPENVPN = "OpenVPN"
    UNKNOWN = "Unknown"


class TransportType(str, Enum):
    TCP = "TCP"
    WS = "WebSocket"
    GRPC = "gRPC"
    HTTPUPGRADE = "HTTPUpgrade"
    XHTTP = "XHTTP"
    QUIC = "QUIC"
    HYSTERIA2 = "Hysteria2"
    TUIC = "TUIC"
    UNKNOWN = "Unknown"


class TestStatus(str, Enum):
    VALID = "Valid"
    INVALID = "Invalid"
    WARNING = "Warning"
    PENDING = "Pending"
    SKIPPED = "Skipped"


class ParsedConfig(BaseModel):
    """Extracted configuration fields."""

    protocol: ProtocolType = ProtocolType.UNKNOWN
    address: str = ""
    port: int = 0
    uuid: Optional[str] = None
    password: Optional[str] = None
    encryption: Optional[str] = None
    flow: Optional[str] = None
    security: Optional[str] = None
    tls: bool = False
    reality: bool = False
    public_key: Optional[str] = None
    short_id: Optional[str] = None
    sni: Optional[str] = None
    host: Optional[str] = None
    alpn: Optional[str] = None
    path: Optional[str] = None
    service_name: Optional[str] = None
    transport_type: TransportType = TransportType.UNKNOWN
    fingerprint: Optional[str] = None
    allow_insecure: bool = False
    remark: Optional[str] = None
    raw_url: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


class DNSRecord(BaseModel):
    record_type: str
    value: str
    ttl: Optional[int] = None


class DNSAnalysis(BaseModel):
    hostname: str = ""
    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    cname_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    ttl: Optional[int] = None
    reverse_dns: list[str] = Field(default_factory=list)
    all_resolved_ips: list[str] = Field(default_factory=list)
    dnssec: Optional[bool] = None
    doh_results: dict[str, list[str]] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)


class IPIntelligence(BaseModel):
    ip: str
    asn: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    datacenter: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    country_flag: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    cdn_detected: Optional[str] = None
    cdn_confidence: float = 0.0
    is_datacenter: bool = False
    is_residential: bool = False
    reputation_score: int = 50


class LatencyStats(BaseModel):
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    avg_ms: Optional[float] = None
    p95_ms: Optional[float] = None
    samples: int = 0


class TracerouteHop(BaseModel):
    hop: int
    ip: Optional[str] = None
    hostname: Optional[str] = None
    latency_ms: Optional[float] = None


class TracerouteResult(BaseModel):
    hops: list[TracerouteHop] = Field(default_factory=list)
    hop_count: Optional[int] = None
    errors: list[str] = Field(default_factory=list)


class ThreatIntel(BaseModel):
    ip: str
    is_datacenter: bool = False
    is_residential: bool = False
    reputation_score: int = 50
    blocklist_hits: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class CertTransparencyEntry(BaseModel):
    subdomain: str
    issuer: Optional[str] = None


class CertTransparencyResult(BaseModel):
    domain: str = ""
    entries: list[CertTransparencyEntry] = Field(default_factory=list)
    total_count: int = 0
    errors: list[str] = Field(default_factory=list)


class ValidationIssue(BaseModel):
    severity: str  # error, warning, info
    code: str
    message: str


class ConfigValidation(BaseModel):
    valid: bool = True
    issues: list[ValidationIssue] = Field(default_factory=list)


class TransportTestResult(BaseModel):
    transport: str
    status: TestStatus = TestStatus.PENDING
    latency_ms: Optional[float] = None
    details: str = ""


class TunnelRoute(BaseModel):
    """Client → Server tunnel geography."""

    client_ip: Optional[str] = None
    client_country: Optional[str] = None
    client_country_code: Optional[str] = None
    client_country_flag: Optional[str] = None
    client_city: Optional[str] = None
    server_ip: Optional[str] = None
    server_country: Optional[str] = None
    server_country_code: Optional[str] = None
    server_country_flag: Optional[str] = None
    server_city: Optional[str] = None
    route_display: str = ""


class ConnectivityResult(BaseModel):
    dns_resolve: TestStatus = TestStatus.PENDING
    dns_latency_ms: Optional[float] = None
    tcp_connect: TestStatus = TestStatus.PENDING
    tcp_latency_ms: Optional[float] = None
    tls_handshake: TestStatus = TestStatus.PENDING
    tls_latency_ms: Optional[float] = None
    websocket_upgrade: TestStatus = TestStatus.PENDING
    grpc_test: TestStatus = TestStatus.PENDING
    quic_test: TestStatus = TestStatus.PENDING
    reality_test: TestStatus = TestStatus.PENDING
    http_response: TestStatus = TestStatus.PENDING
    http_status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    packet_loss_percent: Optional[float] = None
    latency_benchmark: LatencyStats = Field(default_factory=LatencyStats)
    transport_tests: list[TransportTestResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class TLSAnalysis(BaseModel):
    enabled: bool = False
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[datetime] = None
    certificate_expired: bool = False
    days_until_expiry: Optional[int] = None
    fingerprint_sha256: Optional[str] = None
    sni_used: Optional[str] = None
    alpn_protocols: list[str] = Field(default_factory=list)
    weak_cipher: bool = False
    errors: list[str] = Field(default_factory=list)


class DeploymentGuess(BaseModel):
    name: str
    confidence: float
    description: str = ""


class DeploymentAnalysis(BaseModel):
    guesses: list[DeploymentGuess] = Field(default_factory=list)
    real_server_ip: Optional[str] = None
    cdn_backend_ips: list[str] = Field(default_factory=list)
    hop_count: Optional[int] = None
    cdn_type: Optional[str] = None
    reverse_proxy_type: Optional[str] = None
    load_balancer_type: Optional[str] = None
    uncertain_fields: list[str] = Field(default_factory=list)


class TunnelTypeMatch(BaseModel):
    """One detected tunnel topology with evidence."""

    tunnel_id: str
    name: str
    category: str = ""
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    traffic_flow: str = ""
    description: str = ""
    setup_steps: list[str] = Field(default_factory=list)


class TunnelAnalysis(BaseModel):
    """Aggregated tunnel type detection."""

    primary_type: str = ""
    primary_tunnel_id: str = ""
    primary_confidence: float = 0.0
    traffic_flow: str = ""
    detected_types: list[TunnelTypeMatch] = Field(default_factory=list)


class SecurityFinding(BaseModel):
    category: str
    severity: str  # low, medium, high, critical
    title: str
    description: str
    passed: bool = True


class SecurityRecommendation(BaseModel):
    title: str
    description: str
    score_impact: int = 0


class SecurityReport(BaseModel):
    findings: list[SecurityFinding] = Field(default_factory=list)
    score: int = 0
    potential_score: int = 0
    tls_enabled: bool = False
    reality_enabled: bool = False
    recommendations: list[SecurityRecommendation] = Field(default_factory=list)


class ReproductionItem(BaseModel):
    field: str
    reproducible: bool
    value: Optional[str] = None
    reason: Optional[str] = None


class ReproductionGuide(BaseModel):
    reproducible: list[ReproductionItem] = Field(default_factory=list)
    not_reproducible: list[ReproductionItem] = Field(default_factory=list)


class SetupGuideSection(BaseModel):
    title: str
    steps: list[str] = Field(default_factory=list)


class DeploymentSetupGuide(BaseModel):
    """Plain-language server implementation guide — fully derived from analysis data."""

    summary: str = ""
    detected_scenario: str = ""
    scenario_confidence: float = 0.0
    infrastructure_facts: list[str] = Field(default_factory=list)
    recommended_panels: list[str] = Field(default_factory=list)
    sections: list[SetupGuideSection] = Field(default_factory=list)
    checklist: list[str] = Field(default_factory=list)
    tips: list[str] = Field(default_factory=list)


class SiteReachabilityResult(BaseModel):
    name: str = ""
    url: str = ""
    status: TestStatus = TestStatus.PENDING
    http_status: Optional[int] = None
    latency_ms: Optional[float] = None
    details: str = ""


class SpeedTestResult(BaseModel):
    status: TestStatus = TestStatus.PENDING
    download_mbps: Optional[float] = None
    duration_sec: Optional[float] = None
    bytes_downloaded: int = 0
    error: Optional[str] = None


class LeakCheckResult(BaseModel):
    client_ip: Optional[str] = None
    proxy_exit_ip: Optional[str] = None
    proxy_exit_country: Optional[str] = None
    proxy_exit_colo: Optional[str] = None
    test_hostname: str = ""
    direct_dns_ips: list[str] = Field(default_factory=list)
    ip_leak: bool = False
    dns_leak: Optional[bool] = None
    notes: list[str] = Field(default_factory=list)


class XrayTestResult(BaseModel):
    status: TestStatus = TestStatus.PENDING
    xray_version: Optional[str] = None
    log_output: str = ""
    summary: str = ""
    errors: list[str] = Field(default_factory=list)
    proxy_test: TestStatus = TestStatus.PENDING
    proxy_latency_ms: Optional[float] = None
    socks_port: int = 10808
    site_reachability: list[SiteReachabilityResult] = Field(default_factory=list)
    speed_test: SpeedTestResult = Field(default_factory=SpeedTestResult)
    leak_check: LeakCheckResult = Field(default_factory=LeakCheckResult)
    exit_ip: Optional[str] = None
    exit_country: Optional[str] = None


class AnalysisResult(BaseModel):
    """Complete analysis result."""

    config: ParsedConfig
    validation: ConfigValidation = Field(default_factory=ConfigValidation)
    dns: DNSAnalysis = Field(default_factory=DNSAnalysis)
    network: list[IPIntelligence] = Field(default_factory=list)
    connectivity: ConnectivityResult = Field(default_factory=ConnectivityResult)
    tls: TLSAnalysis = Field(default_factory=TLSAnalysis)
    deployment: DeploymentAnalysis = Field(default_factory=DeploymentAnalysis)
    security: SecurityReport = Field(default_factory=SecurityReport)
    reproduction: ReproductionGuide = Field(default_factory=ReproductionGuide)
    setup_guide: DeploymentSetupGuide = Field(default_factory=DeploymentSetupGuide)
    xray_test: XrayTestResult = Field(default_factory=XrayTestResult)
    tunnel: TunnelRoute = Field(default_factory=TunnelRoute)
    tunnel_analysis: TunnelAnalysis = Field(default_factory=TunnelAnalysis)
    traceroute: TracerouteResult = Field(default_factory=TracerouteResult)
    threat_intel: list[ThreatIntel] = Field(default_factory=list)
    cert_transparency: CertTransparencyResult = Field(default_factory=CertTransparencyResult)
    xray_installed: bool = False
    analyzed_at: datetime = Field(default_factory=datetime.now)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class BatchAnalysisResult(BaseModel):
    """Multiple config analysis summary."""

    total: int = 0
    results: list[AnalysisResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
