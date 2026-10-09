"""Traffic camouflage intelligence — TLS mimicry, ALPN, HTTP/2, REALITY fingerprint."""

from __future__ import annotations

from typing import Optional

from backend.models import (
    AnalysisResult,
    ConfidenceLevel,
    RiskFactor,
    TestStatus,
    TrafficCamouflageReport,
    TransportType,
)
from backend.stealth_common import (
    _BROWSER_FPS,
    _INSUFFICIENT,
    effective_transport,
    exit_ip,
    factor,
    grade,
    has_analyzable_config,
    live_proxy_ok,
    weighted_composite,
)

_MODERN_CIPHERS = frozenset({
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
})


def _reality_fingerprint_score(c) -> tuple[int, list[str], ConfidenceLevel]:
    """Score REALITY field completeness (proxy for fingerprint quality)."""
    score = 0
    evidence: list[str] = ["config.reality=true"]
    if c.sni:
        score += 8
        evidence.append(f"sni={c.sni}")
    if c.public_key:
        score += 6
        evidence.append("public_key=set")
    if c.short_id:
        score += 4
        evidence.append("short_id=set")
    if c.fingerprint and c.fingerprint.lower() in _BROWSER_FPS:
        score += 6
        evidence.append(f"fingerprint={c.fingerprint}")
    level = (
        ConfidenceLevel.PROVEN if score >= 18
        else ConfidenceLevel.STRONG if score >= 10
        else ConfidenceLevel.WEAK
    )
    return score, evidence, level


def _alpn_mimicry(c, tls) -> Optional[RiskFactor]:
    config_alpn = (c.alpn or "").lower()
    probe_alpn = [p.lower() for p in tls.alpn_protocols]
    if not config_alpn and not probe_alpn:
        return None

    browser_like = "h2" in config_alpn or "http/1.1" in config_alpn
    probe_h2 = any("h2" in p or p == "h2" for p in probe_alpn)

    if browser_like and probe_h2:
        return factor(
            "ALPN + HTTP/2 browser stack",
            "Config ALPN and probe both indicate browser-like HTTP/2 negotiation.",
            10,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"config_alpn={c.alpn}", f"probe_alpn={','.join(probe_alpn)}"],
        )
    if browser_like:
        return factor(
            f"ALPN: {c.alpn}",
            "Browser-typical ALPN in config (h2 + http/1.1).",
            6,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"alpn={c.alpn}"],
        )
    if probe_alpn:
        return factor(
            f"Probe ALPN: {', '.join(probe_alpn)}",
            "ALPN from live TLS probe.",
            4 if probe_h2 else 2,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"probe_alpn={','.join(probe_alpn)}"],
        )
    return None


def _tls_fingerprint_layer(r: AnalysisResult) -> list[RiskFactor]:
    tls = r.tls
    layers: list[RiskFactor] = []

    if tls.fingerprint_sha256:
        layers.append(factor(
            "Certificate SHA256 observed",
            "TLS probe captured cert fingerprint for correlation.",
            3,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"cert_sha256={tls.fingerprint_sha256[:24]}…"],
        ))

    if tls.cipher_suite:
        modern = tls.cipher_suite in _MODERN_CIPHERS or "TLS_AES" in (tls.cipher_suite or "")
        layers.append(factor(
            f"Cipher: {tls.cipher_suite}",
            "Cipher suite from TLS probe — modern ciphers mimic browsers.",
            -10 if tls.weak_cipher else (6 if modern else 3),
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"cipher={tls.cipher_suite}", f"weak={tls.weak_cipher}"],
        ))

    if tls.version:
        layers.append(factor(
            f"TLS version: {tls.version}",
            "TLS version from certificate probe.",
            8 if "1.3" in tls.version else 3,
            confidence=ConfidenceLevel.PROVEN if tls.enabled else ConfidenceLevel.STRONG,
            evidence=[f"tls.version={tls.version}"],
        ))

    if tls.certificate_issuer and not r.config.reality:
        issuer = tls.certificate_issuer.lower()
        cdn_ca = any(x in issuer for x in ("cloudflare", "let's encrypt", "google trust", "digicert"))
        layers.append(factor(
            f"Cert issuer: {tls.certificate_issuer[:60]}",
            "Public CA issuer — typical for CDN-terminated HTTPS.",
            4 if cdn_ca else 0,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"issuer={tls.certificate_issuer[:80]}"],
        ))

    return layers


def build_camouflage_report(r: AnalysisResult) -> TrafficCamouflageReport:
    """Higher score = traffic looks more like real HTTPS."""
    c = r.config
    if not has_analyzable_config(c):
        return TrafficCamouflageReport(summary=_INSUFFICIENT)

    tls = r.tls
    conn = r.connectivity
    layers: list[RiskFactor] = []
    recs: list[str] = []
    synergy = 0

    if c.reality:
        r_score, r_ev, r_lvl = _reality_fingerprint_score(c)
        layers.append(factor(
            "REALITY camouflage stack",
            "REALITY field completeness — proxy for handshake mimicry quality.",
            min(24, r_score),
            confidence=r_lvl,
            evidence=r_ev,
        ))
        if r_score >= 18:
            synergy += 4
    elif c.tls and conn.tls_handshake == TestStatus.VALID:
        layers.append(factor(
            "Valid TLS handshake",
            "TLS probe completed successfully.",
            14,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"tls_handshake={conn.tls_handshake.value}"],
        ))
    elif c.tls:
        layers.append(factor(
            "TLS configured, handshake unverified",
            "TLS in config but handshake not confirmed.",
            6,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"tls_handshake={conn.tls_handshake.value}"],
        ))
    else:
        layers.append(factor(
            "No TLS mimicry",
            "No TLS/REALITY in config.",
            -30,
            confidence=ConfidenceLevel.PROVEN,
            evidence=["config.tls=false", "config.reality=false"],
        ))
        recs.append("Use REALITY or valid TLS with realistic SNI.")

    if c.fingerprint and c.fingerprint.lower() in _BROWSER_FPS:
        layers.append(factor(
            f"Browser uTLS ({c.fingerprint})",
            "Browser fingerprint in config — JA3-class mimicry intent.",
            14,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"fingerprint={c.fingerprint}"],
        ))
        synergy += 3
    elif c.tls and not c.reality:
        layers.append(factor(
            "No browser fingerprint",
            "TLS without fp= — non-browser TLS client fingerprint likely.",
            -8,
            confidence=ConfidenceLevel.STRONG,
            evidence=["fingerprint=unset"],
        ))
        recs.append("Set fingerprint=chrome for TLS configs.")

    layers.extend(_tls_fingerprint_layer(r))

    alpn_f = _alpn_mimicry(c, tls)
    if alpn_f:
        layers.append(alpn_f)
        if "HTTP/2" in alpn_f.title:
            synergy += 3

    sni = c.sni or ""
    host = c.host or ""
    if sni and host:
        aligned = host == sni or sni in host
        layers.append(factor(
            "SNI/Host alignment" if aligned else "SNI/Host mismatch",
            "SNI and Host from config compared.",
            8 if aligned else -6,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"sni={sni}", f"host={host}"],
        ))
    elif sni:
        layers.append(factor(
            "SNI set",
            "SNI present in config.",
            4,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"sni={sni}"],
        ))

    if r.deployment.cdn_type:
        layers.append(factor(
            f"CDN front ({r.deployment.cdn_type})",
            "CDN detected — client sees CDN edge HTTPS.",
            10,
            confidence=ConfidenceLevel.PROVEN if conn.http_cdn_detected else ConfidenceLevel.STRONG,
            evidence=[f"cdn_type={r.deployment.cdn_type}"],
        ))

    if conn.http_cdn_detected:
        layers.append(factor(
            f"HTTP CDN header ({conn.http_cdn_detected})",
            "CDN header from HTTP probe.",
            5,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"http_cdn_detected={conn.http_cdn_detected}"],
        ))

    if conn.http_panel_detected:
        layers.append(factor(
            f"Panel fingerprint ({conn.http_panel_detected})",
            "Panel signature from HTTP probe — not browser traffic.",
            -18,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"http_panel_detected={conn.http_panel_detected}"],
        ))
        recs.append("Hide panel behind CDN; disable default panel paths on origin.")

    if c.allow_insecure:
        layers.append(factor(
            "allowInsecure enabled",
            "allowInsecure=true — may skip cert validation checks.",
            -12,
            confidence=ConfidenceLevel.PROVEN,
            evidence=["allow_insecure=true"],
        ))
        recs.append("Disable allowInsecure for production configs.")

    if effective_transport(c) == TransportType.WS:
        path = c.path or "/"
        if path in ("/", ""):
            layers.append(factor(
                "Generic WebSocket path",
                "WS transport with root path — atypical for CDN sites.",
                -5,
                confidence=ConfidenceLevel.STRONG,
                evidence=[f"path={path}", "transport=ws"],
            ))
        elif len(path) > 12 and "/" in path[1:]:
            layers.append(factor(
                f"Realistic WS path ({path})",
                "Non-root WebSocket path mimics CDN/app routing.",
                4,
                confidence=ConfidenceLevel.STRONG,
                evidence=[f"path={path}"],
            ))

    if conn.websocket_upgrade == TestStatus.VALID:
        layers.append(factor(
            "WebSocket upgrade verified",
            "WS upgrade probe succeeded — HTTP camouflage layer active.",
            5,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"websocket_upgrade={conn.websocket_upgrade.value}"],
        ))

    if live_proxy_ok(r) and exit_ip(r):
        layers.append(factor(
            "Live egress verified",
            "Exit IP observed from Xray live test.",
            4,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"exit_ip={exit_ip(r)}"],
        ))

    score = weighted_composite(layers, synergy_bonus=synergy)
    if score is None:
        return TrafficCamouflageReport(summary=_INSUFFICIENT, layers=layers)

    naturalness = (
        "Highly natural" if score >= 85 else
        "Natural" if score >= 70 else
        "Moderate" if score >= 50 else
        "Easily identifiable"
    )
    summary = (
        f"Traffic camouflage {score}/100 from {len(layers)} signals "
        f"({naturalness.lower()} HTTPS mimicry)."
    )
    return TrafficCamouflageReport(
        score=score,
        grade=grade(score),
        naturalness=naturalness,
        summary=summary,
        layers=layers,
        recommendations=recs,
    )
