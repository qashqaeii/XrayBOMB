"""Origin exposure intelligence — CT, ASN, certificate & header correlation."""

from __future__ import annotations

from collections import Counter
from typing import Optional

from backend.models import (
    AnalysisResult,
    ConfidenceLevel,
    OriginExposureReport,
    RiskFactor,
)
from backend.stealth_common import (
    _INSUFFICIENT,
    exit_ip,
    factor,
    grade,
    has_analyzable_config,
    live_proxy_ok,
)
from utils.helpers import is_ip_address

_ORIGIN_LEAK_HEADERS = (
    "x-forwarded-for",
    "x-real-ip",
    "x-origin",
    "x-backend",
    "x-upstream",
    "x-served-by",
    "via",
)


def _ct_exposure(r: AnalysisResult) -> list[RiskFactor]:
    ct = r.cert_transparency
    if ct.total_count <= 0:
        return []

    factors: list[RiskFactor] = []
    factors.append(factor(
        f"CT log entries ({ct.total_count})",
        "Certificate transparency history — subdomains may reveal origin patterns.",
        8 if ct.total_count > 15 else 4,
        confidence=ConfidenceLevel.PROVEN,
        evidence=[f"ct_total={ct.total_count}", f"domain={ct.domain}"],
    ))

    issuers = [e.issuer for e in ct.entries if e.issuer]
    if issuers:
        top_issuer, count = Counter(issuers).most_common(1)[0]
        if count >= 3:
            factors.append(factor(
                f"Reused cert issuer ({top_issuer[:50]})",
                "Same CA issuer across multiple CT entries — certificate correlation vector.",
                6,
                confidence=ConfidenceLevel.STRONG,
                evidence=[f"issuer={top_issuer[:80]}", f"ct_entries_with_issuer={count}"],
            ))

    unique_subs = {e.subdomain for e in ct.entries}
    if len(unique_subs) >= 8:
        factors.append(factor(
            f"CT subdomain surface ({len(unique_subs)} names)",
            "Large CT subdomain set increases origin discovery attack surface.",
            7,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"unique_subdomains={len(unique_subs)}"],
        ))

    return factors


def _asn_correlation(r: AnalysisResult) -> list[RiskFactor]:
    d = r.deployment
    factors: list[RiskFactor] = []
    if not r.network:
        return factors

    cdn_asns: set[str] = set()
    dc_asns: set[str] = set()
    for ip in r.network:
        if not ip.asn:
            continue
        if ip.cdn_detected or d.cdn_type:
            cdn_asns.add(ip.asn)
        if ip.is_datacenter and not ip.cdn_detected:
            dc_asns.add(ip.asn)

    if d.cdn_type and dc_asns and not cdn_asns:
        factors.append(factor(
            "DNS resolves to datacenter ASN (no CDN ASN)",
            "A records point to hosting ASN without CDN edge ASN — grey-cloud risk.",
            16,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"cdn_type={d.cdn_type}", f"dc_asn={next(iter(dc_asns))}"],
        ))
    elif d.cdn_type and cdn_asns and dc_asns and cdn_asns.isdisjoint(dc_asns):
        factors.append(factor(
            "CDN ASN ≠ datacenter ASN",
            "DNS uses CDN edge ASN; live egress may reveal separate origin ASN.",
            10,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"cdn_asn={','.join(sorted(cdn_asns)[:2])}", f"dc_asn={','.join(sorted(dc_asns)[:2])}"],
        ))

    exit = exit_ip(r)
    if exit and live_proxy_ok(r):
        exit_intel = next((ip for ip in r.network if ip.ip == exit), None)
        dns_ips = r.dns.all_resolved_ips or r.dns.a_records
        if exit_intel and exit_intel.is_datacenter and d.cdn_type:
            if exit not in dns_ips:
                factors.append(factor(
                    f"Exit datacenter ASN ({exit_intel.asn or 'unknown'})",
                    "Live egress is datacenter IP not in public DNS — origin may be hidden but ASN-correlatable.",
                    12,
                    confidence=ConfidenceLevel.PROVEN,
                    evidence=[f"exit_ip={exit}", f"asn={exit_intel.asn}", f"org={exit_intel.organization or '—'}"],
                ))

    return factors


def _header_leakage(r: AnalysisResult) -> list[RiskFactor]:
    conn = r.connectivity
    hdrs = conn.http_probe_headers or {}
    factors: list[RiskFactor] = []

    for key in _ORIGIN_LEAK_HEADERS:
        val = hdrs.get(key) or hdrs.get(key.replace("-", "_"))
        if not val:
            continue
        impact = 10 if key in ("x-real-ip", "x-forwarded-for", "x-origin") else 6
        factors.append(factor(
            f"Header leak: {key}",
            f"HTTP probe exposed {key} — may reveal origin routing.",
            impact,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"{key}={val[:80]}"],
        ))

    server = hdrs.get("server") or conn.http_server_header
    if server and not r.deployment.cdn_type:
        if any(x in server.lower() for x in ("nginx/", "apache/", "openresty", "caddy")):
            factors.append(factor(
                f"Origin server header ({server})",
                "Bare web server banner from HTTP probe.",
                8,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"server={server}"],
            ))

    if conn.http_reverse_proxy and not r.deployment.cdn_type:
        factors.append(factor(
            f"Reverse proxy header ({conn.http_reverse_proxy})",
            "Reverse proxy detected — origin stack partially visible.",
            5,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"reverse_proxy={conn.http_reverse_proxy}"],
        ))

    return factors


def _cert_correlation(r: AnalysisResult) -> list[RiskFactor]:
    tls = r.tls
    factors: list[RiskFactor] = []
    if not tls.fingerprint_sha256:
        return factors

    ct = r.cert_transparency
    if ct.entries and tls.certificate_subject:
        factors.append(factor(
            "Certificate fingerprint captured",
            "TLS cert SHA256 available for cross-domain / historical correlation.",
            5,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[
                f"cert_sha256={tls.fingerprint_sha256[:32]}…",
                f"subject={tls.certificate_subject[:60]}",
            ],
        ))

    if tls.certificate_subject and r.config.sni:
        subj = tls.certificate_subject.lower()
        sni = r.config.sni.lower()
        if sni not in subj and "cloudflare" not in subj:
            factors.append(factor(
                "SNI ≠ certificate subject",
                "TLS cert subject does not match config SNI — possible fronting or misconfig.",
                6,
                confidence=ConfidenceLevel.STRONG,
                evidence=[f"sni={r.config.sni}", f"cert_subject={tls.certificate_subject[:60]}"],
            ))

    return factors


def build_origin_exposure_report(r: AnalysisResult) -> OriginExposureReport:
    """Higher risk_score = origin more likely exposed."""
    c = r.config
    if not has_analyzable_config(c):
        return OriginExposureReport(summary=_INSUFFICIENT)

    d = r.deployment
    dns = r.dns
    conn = r.connectivity
    factors: list[RiskFactor] = []
    recs: list[str] = []
    inferred: Optional[str] = d.real_server_ip
    live = live_proxy_ok(r)
    exit = exit_ip(r)
    resolved = dns.all_resolved_ips or dns.a_records

    if is_ip_address(c.address):
        inferred = c.address
        factors.append(factor(
            "Direct IP in config",
            "Link address is a literal IP — immediate origin exposure.",
            38,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"address={c.address}"],
        ))
        recs.append("Put domain behind Cloudflare/Arvan proxied mode; avoid sharing raw VPS IP.")

    if not d.cdn_type and not is_ip_address(c.address):
        factors.append(factor(
            "No CDN detected",
            "Deployment analysis found no CDN front.",
            18,
            confidence=ConfidenceLevel.STRONG,
            evidence=[f"a_records={', '.join(resolved[:3]) or 'none'}"],
        ))
        recs.append("Enable CDN proxy (orange cloud) to hide origin.")

    if d.cdn_type and live and exit and resolved:
        if exit in resolved:
            factors.append(factor(
                "Exit IP matches DNS A record",
                "Live egress IP equals resolved DNS — grey-cloud CDN or direct origin.",
                22,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"exit_ip={exit}", f"dns_a={', '.join(resolved[:3])}"],
            ))
            recs.append("Switch CDN to proxied mode; origin IP must not appear in public DNS.")
        else:
            factors.append(factor(
                "Exit IP differs from DNS A",
                "Live egress uses different IP than DNS A — CDN proxy likely active.",
                -12,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"exit_ip={exit}", f"dns_a={', '.join(resolved[:3])}"],
            ))

    if dns.dns_split_detected:
        factors.append(factor(
            "DNS split detected",
            "Resolver divergence — may indicate split-horizon or poisoned DNS.",
            8,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[dns.dns_split_note or "dns_split_detected=true"],
        ))

    if conn.http_panel_detected:
        factors.append(factor(
            f"Panel exposed ({conn.http_panel_detected})",
            "Panel fingerprint from HTTP probe.",
            14,
            confidence=ConfidenceLevel.PROVEN,
            evidence=[f"http_panel_detected={conn.http_panel_detected}"],
        ))

    factors.extend(_ct_exposure(r))
    factors.extend(_asn_correlation(r))
    factors.extend(_header_leakage(r))
    factors.extend(_cert_correlation(r))

    for ip_intel in r.network:
        if ip_intel.is_datacenter and not d.cdn_type:
            factors.append(factor(
                f"Datacenter IP ({ip_intel.ip})",
                "Resolved IP classified as datacenter without CDN.",
                5,
                confidence=ConfidenceLevel.PROVEN,
                evidence=[f"ip={ip_intel.ip}", f"asn={ip_intel.asn or 'unknown'}"],
            ))
            if not inferred:
                inferred = ip_intel.ip
            break

    if r.threat_intel:
        for ti in r.threat_intel:
            if ti.blocklist_hits:
                factors.append(factor(
                    f"Blocklist hits on {ti.ip}",
                    "IP appears on DNSBL — historical abuse / exposure signal.",
                    8,
                    confidence=ConfidenceLevel.STRONG,
                    evidence=[f"blocklists={','.join(ti.blocklist_hits[:3])}"],
                ))
                break

    if not factors:
        return OriginExposureReport(
            summary="No origin-exposure signals observed yet.",
            inferred_origin_ip=inferred,
        )

    risk = max(0, min(100, sum(f.impact for f in factors)))
    if risk < 25:
        level = "hidden"
    elif risk < 55:
        level = "partial"
    else:
        level = "exposed"

    summary = (
        f"Origin exposure {risk}/100 from {len(factors)} signals "
        f"(level: {level})."
    )
    return OriginExposureReport(
        risk_score=risk,
        exposure_level=level,
        grade=grade(risk, higher_is_better=False),
        summary=summary,
        inferred_origin_ip=inferred,
        factors=factors,
        recommendations=recs,
    )
