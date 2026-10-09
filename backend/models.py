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
    FAILED = "Failed"
    WARNING = "Warning"
    PENDING = "Pending"
    SKIPPED = "Skipped"
    NOT_TESTED = "Not tested"
    NOT_APPLICABLE = "Not applicable"
    UNSUPPORTED = "Unsupported"
    INCONCLUSIVE = "Inconclusive"


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
    local_resolver_ips: list[str] = Field(default_factory=list)
    dns_split_detected: bool = False
    dns_split_note: str = ""
    ns_records: list[str] = Field(default_factory=list)
    dns_provider: Optional[str] = None
    dns_provider_confidence: float = 0.0
    dns_provider_evidence: list[str] = Field(default_factory=list)
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
    packet_loss_percent: Optional[float] = None  # legacy alias
    tcp_connection_failure_rate: Optional[float] = None
    http_response_note: str = ""
    latency_benchmark: LatencyStats = Field(default_factory=LatencyStats)
    transport_tests: list[TransportTestResult] = Field(default_factory=list)
    http_server_header: Optional[str] = None
    http_cdn_detected: Optional[str] = None
    http_panel_detected: Optional[str] = None
    http_reverse_proxy: Optional[str] = None
    http_probe_url: Optional[str] = None
    http_probe_headers: dict[str, str] = Field(default_factory=dict)
    http_baseline_status: TestStatus = TestStatus.NOT_TESTED
    http_baseline_status_code: Optional[int] = None
    http_baseline_latency_ms: Optional[float] = None
    http_baseline_headers: dict[str, str] = Field(default_factory=dict)
    http_baseline_note: str = ""
    websocket_handshake_status_code: Optional[int] = None
    websocket_handshake_checks: list[str] = Field(default_factory=list)
    websocket_handshake_validated: bool = False
    websocket_upgrade_note: str = ""
    errors: list[str] = Field(default_factory=list)


class TLSAnalysis(BaseModel):
    enabled: bool = False
    tls_configured: bool = False
    handshake_observed: bool = False
    chain_trusted: Optional[bool] = None
    hostname_matched: Optional[bool] = None
    collection_mode: str = "unverified_probe"
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


class ConfidenceLevel(str, Enum):
    """Evidence strength for a conclusion (ordered strongest → weakest)."""

    PROVEN = "Proven"
    STRONG = "Strong Evidence"
    WEAK = "Weak Evidence"
    SPECULATIVE = "Speculative"

    # Legacy aliases — kept for deserialized snapshots / external tools
    CONFIRMED = "Proven"
    LIKELY = "Strong Evidence"


class RiskFactor(BaseModel):
    """Scored factor with evidence and calibrated confidence."""

    title: str
    description: str
    impact: int = 0
    confidence: ConfidenceLevel = ConfidenceLevel.WEAK
    evidence: list[str] = Field(default_factory=list)


class DPIDetectabilityReport(BaseModel):
    """Resistance to DPI fingerprinting (higher = stealthier, harder to block)."""

    score: Optional[int] = None
    grade: str = "—"
    detection_risk: str = "unknown"
    summary: str = ""
    factors: list[RiskFactor] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class TrafficCamouflageReport(BaseModel):
    """How closely traffic mimics legitimate HTTPS (higher = more natural)."""

    score: Optional[int] = None
    grade: str = "—"
    naturalness: str = "unknown"
    summary: str = ""
    layers: list[RiskFactor] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class OriginExposureReport(BaseModel):
    """Likelihood the real origin IP is discoverable (higher = more exposed)."""

    risk_score: Optional[int] = None
    exposure_level: str = "unknown"
    grade: str = "—"
    summary: str = ""
    inferred_origin_ip: Optional[str] = None
    factors: list[RiskFactor] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class CalibratedInsight(BaseModel):
    """A conclusion with explicit evidence tier."""

    category: str
    title: str
    description: str
    confidence: ConfidenceLevel = ConfidenceLevel.WEAK
    evidence: list[str] = Field(default_factory=list)
    raw_confidence: float = 0.0
    calibrated_confidence: float = 0.0


class ConfidenceCalibrationReport(BaseModel):
    """Central registry of evidence-calibrated conclusions."""

    summary: str = ""
    insights: list[CalibratedInsight] = Field(default_factory=list)


class DeploymentGuess(BaseModel):
    name: str
    confidence: float
    description: str = ""
    confidence_level: ConfidenceLevel = ConfidenceLevel.WEAK
    calibrated_confidence: float = 0.0


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
    confidence_level: ConfidenceLevel = ConfidenceLevel.WEAK
    calibrated_confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)
    traffic_flow: str = ""
    description: str = ""
    setup_steps: list[str] = Field(default_factory=list)


class TunnelAnalysis(BaseModel):
    """Aggregated tunnel type detection."""

    primary_type: str = ""
    primary_tunnel_id: str = ""
    primary_confidence: float = 0.0
    primary_confidence_level: ConfidenceLevel = ConfidenceLevel.WEAK
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
    how_to_run_sections: list[SetupGuideSection] = Field(default_factory=list)
    how_to_run_text: str = ""


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
    server_dns_ips: list[str] = Field(default_factory=list)
    direct_dns_ips: list[str] = Field(default_factory=list)
    baseline_samples: list[dict[str, Any]] = Field(default_factory=list)
    baseline_status: str = "unknown"
    exit_ip_same_observed: Optional[bool] = None
    ip_leak: Optional[bool] = None
    dns_leak: Optional[bool] = None
    dns_leak_status: TestStatus = TestStatus.NOT_TESTED
    baseline_inconclusive: bool = False
    notes: list[str] = Field(default_factory=list)


class XrayTestResult(BaseModel):
    status: TestStatus = TestStatus.PENDING
    run_id: Optional[str] = None
    xray_version: Optional[str] = None
    process_pid: Optional[int] = None
    config_fingerprint: Optional[str] = None
    started_at: Optional[datetime] = None
    exit_code: Optional[int] = None
    log_output: str = ""
    summary: str = ""
    errors: list[str] = Field(default_factory=list)
    config_validation: TestStatus = TestStatus.PENDING
    config_validation_detail: str = ""
    proxy_test: TestStatus = TestStatus.PENDING
    proxy_latency_ms: Optional[float] = None
    internet_e2e_verified: bool = False
    e2e_contract_ok: bool = False
    e2e_contract_detail: str = ""
    socks_handshake_verified: bool = False
    process_alive_after_e2e: bool = False
    socks_port: int = 10808
    socks_host: str = "127.0.0.1"
    socks_auth_user: Optional[str] = None
    site_reachability: list[SiteReachabilityResult] = Field(default_factory=list)
    speed_test: SpeedTestResult = Field(default_factory=SpeedTestResult)
    leak_check: LeakCheckResult = Field(default_factory=LeakCheckResult)
    exit_ip: Optional[str] = None
    exit_country: Optional[str] = None


class OptimizationPriority(str, Enum):
    CRITICAL = "critical"  # P1 — must fix before selling
    HIGH = "high"          # P2 — strong impact on Iran filtering
    MEDIUM = "medium"      # P3 — quality / stability
    LOW = "low"            # P4 — polish
    INFO = "info"          # P5 — optional


class IPNodeScore(BaseModel):
    """Ranked IP behind DNS for seller comparison."""

    ip: str
    score: int = 0
    reputation: int = 50
    tcp_ok: bool = False
    tcp_latency_ms: Optional[float] = None
    is_datacenter: bool = False
    cdn: Optional[str] = None
    country: Optional[str] = None
    blocklist_hits: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class OptimizationAction(BaseModel):
    priority: OptimizationPriority = OptimizationPriority.MEDIUM
    priority_rank: int = 3
    title: str
    description: str
    field: Optional[str] = None
    current_value: Optional[str] = None
    suggested_value: Optional[str] = None
    score_gain: int = 0


class OptimizedBlueprint(BaseModel):
    """Suggested client/server fields derived from analysis — not a live server."""

    protocol: str = ""
    address: str = ""
    port: int = 443
    transport: str = ""
    security: str = ""
    flow: Optional[str] = None
    sni: Optional[str] = None
    host: Optional[str] = None
    path: Optional[str] = None
    fingerprint: Optional[str] = None
    alpn: Optional[str] = None
    service_name: Optional[str] = None
    allow_insecure: bool = False
    notes: list[str] = Field(default_factory=list)


class ConfigOptimizationReport(BaseModel):
    """Iran-focused optimization and seller readiness — priority-ordered."""

    iran_score: int = 0
    sell_readiness: int = 0
    grade: str = "—"
    verdict: str = ""
    ip_rankings: list[IPNodeScore] = Field(default_factory=list)
    best_ip: Optional[str] = None
    actions: list[OptimizationAction] = Field(default_factory=list)
    blueprint: OptimizedBlueprint = Field(default_factory=OptimizedBlueprint)
    suggested_share_link: Optional[str] = None
    server_recipe: list[str] = Field(default_factory=list)
    delivery_checklist: list[str] = Field(default_factory=list)
    support_message: str = ""
    ideal_stack_summary: str = ""


class ArchitectureEvidenceLine(BaseModel):
    """One line in Architecture Diagnostics (confirmed / probable / unknown)."""

    label: str
    status: str = "unknown"
    detail: str = ""


class ArchitectureDiagnosticsReport(BaseModel):
    """Evidence-based architecture summary for GUI and exports."""

    title: str = "Architecture Diagnostics"
    endpoint: str = ""
    connection_evidence: list[ArchitectureEvidenceLine] = Field(default_factory=list)
    infrastructure: list[ArchitectureEvidenceLine] = Field(default_factory=list)
    assessment_title: str = ""
    assessment_summary: str = ""
    positive_evidence: list[str] = Field(default_factory=list)
    negative_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    reproduction_client: list[str] = Field(default_factory=list)
    reproduction_server_hints: list[str] = Field(default_factory=list)


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
    optimization: ConfigOptimizationReport = Field(default_factory=ConfigOptimizationReport)
    dpi: DPIDetectabilityReport = Field(default_factory=DPIDetectabilityReport)
    camouflage: TrafficCamouflageReport = Field(default_factory=TrafficCamouflageReport)
    origin_exposure: OriginExposureReport = Field(default_factory=OriginExposureReport)
    confidence_calibration: ConfidenceCalibrationReport = Field(default_factory=ConfidenceCalibrationReport)
    test_environment: dict[str, Any] = Field(default_factory=dict)
    endpoint_targets: dict[str, Any] = Field(default_factory=dict)
    implementation_analysis: dict[str, Any] = Field(default_factory=dict)
    architecture_diagnostics: ArchitectureDiagnosticsReport = Field(
        default_factory=ArchitectureDiagnosticsReport,
    )
    analyzed_at: datetime = Field(default_factory=datetime.now)
    raw_data: dict[str, Any] = Field(default_factory=dict)


class CleanIPResult(BaseModel):
    ip: str
    score: int = 0
    avg_ms: Optional[float] = None
    p95_ms: Optional[float] = None
    min_ms: Optional[float] = None
    packet_loss_pct: float = 0.0
    tls_ok: bool = False
    blocklist_hits: list[str] = Field(default_factory=list)
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    notes: list[str] = Field(default_factory=list)


class CleanIPFinderResult(BaseModel):
    tool: str = "cloudflare_clean_ip"
    region: str = ""
    sni: str = ""
    port: int = 443
    scanned: int = 0
    reachable: int = 0
    results: list[CleanIPResult] = Field(default_factory=list)
    best_ip: Optional[str] = None
    best_score: Optional[int] = None
    tips: list[str] = Field(default_factory=list)


class ProviderBenchmarkResult(BaseModel):
    provider: str
    score: int = 0
    host: Optional[str] = None
    ip: Optional[str] = None
    avg_ms: Optional[float] = None
    p95_ms: Optional[float] = None
    min_ms: Optional[float] = None
    packet_loss_pct: float = 0.0
    country: Optional[str] = None
    country_code: Optional[str] = None
    asn_hint: str = ""
    iran_notes: str = ""
    blocklist_hits: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class DatacenterFinderResult(BaseModel):
    tool: str = "datacenter_finder"
    country: str = ""
    country_code: str = ""
    port: int = 443
    results: list[ProviderBenchmarkResult] = Field(default_factory=list)
    winner: Optional[str] = None
    winner_score: Optional[int] = None
    tips: list[str] = Field(default_factory=list)


class BatchAnalysisResult(BaseModel):
    """Multiple config analysis summary."""

    total: int = 0
    results: list[AnalysisResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
