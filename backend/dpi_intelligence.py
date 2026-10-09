"""DPI detectability intelligence — pattern DB, dynamic weighting, multi-factor fusion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from backend.models import (
    AnalysisResult,
    ConfidenceLevel,
    DPIDetectabilityReport,
    ProtocolType,
    RiskFactor,
    TestStatus,
    TransportType,
)
from backend.stealth_common import (
    _ALT_TLS_PORTS,
    _BROWSER_FPS,
    _INSUFFICIENT,
    effective_transport,
    factor,
    grade,
    has_analyzable_config,
    live_proxy_ok,
    weighted_composite,
)


@dataclass(frozen=True)
class _BlockingPattern:
    """Known DPI / filtering signature cluster."""

    name: str
    required: frozenset[str]
    optional: frozenset[str]
    base_penalty: int
    regions: frozenset[str]
    note: str


def _signal_map(r: AnalysisResult) -> set[str]:
    c = r.config
    conn = r.connectivity
    transport = effective_transport(c)
    signals: set[str] = set()

    if c.protocol != ProtocolType.UNKNOWN:
        signals.add(f"proto:{c.protocol.value.lower()}")
    if c.reality:
        signals.add("reality")
    elif c.tls:
        signals.add("tls")
    else:
        signals.add("no_tls")

    if transport != TransportType.UNKNOWN:
        signals.add(f"transport:{transport.value.lower().replace(' ', '')}")
    if c.port == 443:
        signals.add("port:443")
    elif c.port == 80:
        signals.add("port:80")
    elif c.port:
        signals.add("port:nonstandard")

    if c.fingerprint and c.fingerprint.lower() in _BROWSER_FPS:
        signals.add("browser_fp")
    elif c.tls and not c.reality:
        signals.add("no_browser_fp")

    if r.deployment.cdn_type or conn.http_cdn_detected:
        signals.add("cdn_front")

    if c.flow and "vision" in c.flow.lower():
        signals.add("xtls_vision")

    if conn.reality_test == TestStatus.VALID:
        signals.add("reality_probe_ok")
    if live_proxy_ok(r):
        signals.add("live_ok")

    return signals


_BLOCKING_PATTERNS: list[_BlockingPattern] = [
    _BlockingPattern(
        "Plaintext proxy on filtered port",
        frozenset({"no_tls", "transport:websocket"}),
        frozenset({"port:80", "proto:vmess"}),
        -22,
        frozenset({"iran", "cn", "ru"}),
        "WS without TLS on port 80 is a classic DPI target.",
    ),
    _BlockingPattern(
        "VMess cleartext signature",
        frozenset({"no_tls", "proto:vmess"}),
        frozenset(),
        -26,
        frozenset({"iran", "cn"}),
        "VMess without TLS matches well-known blocking rulesets.",
    ),
    _BlockingPattern(
        "Non-standard port direct exposure",
        frozenset({"port:nonstandard", "no_tls"}),
        frozenset({"proto:vmess", "proto:shadowsocks"}),
        -18,
        frozenset({"iran", "global"}),
        "Uncommon ports with weak obfuscation are port-scanned aggressively.",
    ),
    _BlockingPattern(
        "TLS without browser mimicry",
        frozenset({"tls", "no_browser_fp"}),
        frozenset({"transport:websocket", "proto:vmess"}),
        -14,
        frozenset({"iran", "global"}),
        "Default Go/OpenSSL client fingerprints are classifiable.",
    ),
    _BlockingPattern(
        "WireGuard UDP signature",
        frozenset({"proto:wireguard"}),
        frozenset({"port:nonstandard"}),
        -16,
        frozenset({"iran", "cn"}),
        "WireGuard UDP flows have distinct DPI signatures.",
    ),
    _BlockingPattern(
        "REALITY + Vision stack (resistant)",
        frozenset({"reality", "xtls_vision", "browser_fp"}),
        frozenset({"port:443", "reality_probe_ok"}),
        18,
        frozenset({"iran", "global"}),
        "REALITY with browser uTLS and Vision is among the strongest stacks.",
    ),
    _BlockingPattern(
        "CDN-shielded TLS edge",
        frozenset({"cdn_front", "tls"}),
        frozenset({"port:443", "browser_fp"}),
        10,
        frozenset({"iran", "global"}),
        "CDN front absorbs origin fingerprinting; edge looks like CDN HTTPS.",
    ),
]


def _match_patterns(signals: set[str]) -> list[tuple[_BlockingPattern, float]]:
    hits: list[tuple[_BlockingPattern, float]] = []
    for pat in _BLOCKING_PATTERNS:
        if not pat.required <= signals:
            continue
        optional_hits = len(pat.optional & signals)
        optional_total = len(pat.optional) or 1
        strength = 0.65 + 0.35 * (optional_hits / optional_total)
        hits.append((pat, strength))
    return hits


def _protocol_factor(r: AnalysisResult) -> Optional[RiskFactor]:
    c = r.config
    if c.protocol == ProtocolType.UNKNOWN:
        return None
    weights = {
        ProtocolType.VLESS: 14,
        ProtocolType.TROJAN: 11,
        ProtocolType.VMESS: -4,
        ProtocolType.SHADOWSOCKS: 2,
        ProtocolType.HYSTERIA2: 5,
        ProtocolType.TUIC: 5,
        ProtocolType.WIREGUARD: -8,
        ProtocolType.OPENVPN: -12,
    }
    impact = weights.get(c.protocol, -6)
    return factor(
        f"Protocol: {c.protocol.value}",
        "Protocol class weighted against known filtering signature databases.",
        impact,
        confidence=ConfidenceLevel.SPECULATIVE,
        evidence=[f"protocol={c.protocol.value}"],
    )


def _encryption_stack(r: AnalysisResult) -> list[RiskFactor]:
    c = r.config
    conn = r.connectivity
    out: list[RiskFactor] = []

    if c.reality:
        out.append(factor(
            "REALITY enabled",
            "REALITY masks handshake as a visit to the destination site.",
            22,
            confidence=ConfidenceLevel.PROVEN,
            evidence=["config.reality=true", f"sni={c.sni or 'unset'}"],
        ))
    elif c.tls:
        conf = (
            ConfidenceLevel.PROVEN
            if conn.tls_handshake == TestStatus.VALID
            else ConfidenceLevel.STRONG
        )
        out.append(factor(
            "TLS enabled",
            "TLS encrypts payload; fingerprint may still be classified.",
            10 if conn.tls_handshake != TestStatus.INVALID else 4,
            confidence=conf,
            evidence=[f"config.tls=true", f"tls_handshake={conn.tls_handshake.value}"],
        ))
    else:
        out.append(factor(
            "No TLS / REALITY",
            "No TLS or REALITY — plaintext or weak obfuscation.",
            -28,
            confidence=ConfidenceLevel.PROVEN,
            evidence=["config.tls=false", "config.reality=false"],
        ))
    return out


def build_dpi_report(r: AnalysisResult) -> DPIDetectabilityReport:
    """Higher score = more resistant to DPI."""
    c = r.config
    if not has_analyzable_config(c):
        return DPIDetectabilityReport(summary=_INSUFFICIENT)

    conn = r.connectivity
    transport = effective_transport(c)
    factors: list[RiskFactor] = []
    recs: list[str] = []
    signals = _signal_map(r)

    proto = _protocol_factor(r)
    if proto:
        factors.append(proto)

    factors.extend(_encryption_stack(r))

    if transport != TransportType.UNKNOWN:
        transport_impact = {
            TransportType.TCP: 12,
            TransportType.GRPC: 8,
            TransportType.HTTPUPGRADE: 9,
            TransportType.XHTTP: 10,
            TransportType.WS: -6,
            TransportType.QUIC: 4,
            TransportType.HYSTERIA2: 3,
            TransportType.TUIC: 3,
        }.get(transport, 0)
        if transport_impact:
            factors.append(factor(
                f"Transport: {transport.value}",
                "Transport affects observable DPI fingerprint surface.",
                transport_impact,
                confidence=ConfidenceLevel.SPECULATIVE,
                evidence=[f"transport={transport.value}"],
            ))

    if c.fingerprint and c.fingerprint.lower() in _BROWSER_FPS:
        factors.append(factor(
            f"uTLS fingerprint: {c.fingerprint}",
            "Browser fingerprint configured — reduces TLS client classification.",
            12,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"fingerprint={c.fingerprint}"],
        ))
    elif c.tls and not c.reality:
        factors.append(factor(
            "No TLS fingerprint in config",
            "Missing fp= — default TLS client may be classifiable.",
            -10,
            confidence=ConfidenceLevel.STRONG,
            evidence=["fingerprint=unset", f"tls={c.tls}"],
        ))
        recs.append("Set fp=chrome or fp=firefox on TLS configs.")

    if c.port:
        if c.port == 443:
            factors.append(factor(
                "Port 443",
                "Standard HTTPS port.",
                14,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"port={c.port}"],
            ))
        elif c.port in _ALT_TLS_PORTS:
            factors.append(factor(
                f"Port {c.port}",
                "Alternate TLS-related port.",
                6,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"port={c.port}"],
            ))
        elif c.port == 80:
            factors.append(factor(
                "Port 80",
                "HTTP port — heavily inspected on filtered networks.",
                -8,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"port={c.port}"],
            ))
        else:
            factors.append(factor(
                f"Non-standard port {c.port}",
                "Uncommon port increases port-scan exposure.",
                -8,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"port={c.port}"],
            ))
            recs.append("Move listener to 443 behind CDN or REALITY.")

    if c.flow and "vision" in c.flow.lower():
        factors.append(factor(
            f"Flow: {c.flow}",
            "XTLS Vision flow observed.",
            6,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"flow={c.flow}"],
        ))

    if conn.reality_test == TestStatus.VALID:
        factors.append(factor(
            "REALITY probe passed",
            "Connectivity probe confirmed REALITY handshake.",
            5,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"reality_test={conn.reality_test.value}"],
        ))
    elif conn.reality_test == TestStatus.INVALID and c.reality:
        factors.append(factor(
            "REALITY probe failed",
            "REALITY in config but probe did not succeed.",
            -8,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"reality_test={conn.reality_test.value}"],
        ))

    if live_proxy_ok(r):
        factors.append(factor(
            "Live proxy validated",
            "Xray live test reported working proxy.",
            4,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"proxy_test={r.xray_test.proxy_test.value}"],
        ))

    if r.deployment.cdn_type:
        factors.append(factor(
            f"CDN edge: {r.deployment.cdn_type}",
            "CDN type detected — edge traffic resembles CDN HTTPS.",
            5,
            confidence=ConfidenceLevel.PROVEN if conn.http_cdn_detected else ConfidenceLevel.STRONG,
            evidence=[
                f"deployment.cdn_type={r.deployment.cdn_type}",
                f"http_cdn={conn.http_cdn_detected or 'not detected'}",
            ],
        ))

    # Pattern DB fusion
    pattern_hits = _match_patterns(signals)
    synergy = 0
    for pat, strength in pattern_hits:
        impact = int(pat.base_penalty * strength)
        if impact == 0:
            continue
        factors.append(factor(
            f"Pattern: {pat.name}",
            pat.note,
            impact,
            confidence=ConfidenceLevel.STRONG if strength >= 0.85 else ConfidenceLevel.WEAK,
            evidence=[
                f"matched={','.join(sorted(pat.required & signals))}",
                f"regions={','.join(sorted(pat.regions))}",
            ],
        ))
        if impact > 0 and len(pat.required & signals) >= 2:
            synergy += min(6, impact // 3)

    score = weighted_composite(factors, synergy_bonus=synergy)
    if score is None:
        return DPIDetectabilityReport(summary=_INSUFFICIENT, factors=factors)

    risk = "Low" if score >= 75 else "Medium" if score >= 50 else "High"
    pat_note = f", {len(pattern_hits)} blocking-pattern match(es)" if pattern_hits else ""
    summary = (
        f"DPI resistance {score}/100 from {len(factors)} signals "
        f"({risk.lower()} detection risk{pat_note})."
    )
    return DPIDetectabilityReport(
        score=score,
        grade=grade(score),
        detection_risk=risk,
        summary=summary,
        factors=factors,
        recommendations=recs,
    )
