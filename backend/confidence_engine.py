"""Evidence calibration with 4-tier confidence and mutual-exclusivity resolution."""

from __future__ import annotations

from backend.models import (
    AnalysisResult,
    CalibratedInsight,
    ConfidenceCalibrationReport,
    ConfidenceLevel,
    DeploymentAnalysis,
    DeploymentGuess,
    DPIDetectabilityReport,
    OriginExposureReport,
    TestStatus,
    TrafficCamouflageReport,
    TunnelAnalysis,
    TunnelTypeMatch,
)

CONFIDENCE_CAP = 0.92
_LIVE_TEST_CONFIRM_BOOST = 0.10
_NO_LIVE_CAP = 0.72

_LEVEL_ORDER = (
    ConfidenceLevel.PROVEN,
    ConfidenceLevel.STRONG,
    ConfidenceLevel.WEAK,
    ConfidenceLevel.SPECULATIVE,
)

_CDN_TUNNEL_IDS = frozenset({
    "cdn_fronting",
    "cloudflare_cdn",
    "arvan_cdn",
    "akamai_cdn",
    "fastly_cdn",
    "cloudfront_cdn",
    "bunny_cdn",
    "gcore_cdn",
})

_DIRECT_TOPOLOGY_IDS = frozenset({
    "direct_xray_inbound",
    "direct_vps",
})

_CDN_DEPLOYMENT_NAMES = frozenset({
    "CDN Fronted",
    "Cloudflare CDN",
    "Arvan CDN",
    "Akamai CDN",
    "Fastly CDN",
    "AWS CloudFront",
    "BunnyCDN",
    "Gcore CDN",
})

_DIRECT_DEPLOYMENT_NAMES = frozenset({
    "Direct VPS",
    "Reverse Proxy",
})


def _demote(level: ConfidenceLevel, steps: int = 1) -> ConfidenceLevel:
    idx = _LEVEL_ORDER.index(level)
    return _LEVEL_ORDER[min(len(_LEVEL_ORDER) - 1, idx + steps)]


def _level_rank(level: ConfidenceLevel) -> int:
    return _LEVEL_ORDER.index(level)


def _live_proxy_ok(r: AnalysisResult) -> bool:
    from backend.e2e_validity import evaluate_xray_test_result

    return evaluate_xray_test_result(r.xray_test).internet_verified


def _cdn_detected(r: AnalysisResult) -> bool:
    from backend.architecture_consistency import cdn_edge_proven

    if cdn_edge_proven(r):
        return True
    return bool(r.connectivity.http_cdn_detected and r.connectivity.http_probe_headers.get("cf-ray"))


def calibrate_evidence(
    raw: float,
    *,
    live: bool,
    evidence_count: int,
    direct_observation: bool = False,
    heuristic_only: bool = False,
) -> tuple[float, ConfidenceLevel]:
    """Map raw confidence + evidence to a 4-tier calibrated result."""
    raw = max(0.0, min(1.0, raw))

    if heuristic_only:
        cal = min(_NO_LIVE_CAP * 0.75, raw * 0.85)
        return cal, ConfidenceLevel.SPECULATIVE

    if live and direct_observation and evidence_count >= 2 and raw >= 0.68:
        cal = min(CONFIDENCE_CAP, raw + _LIVE_TEST_CONFIRM_BOOST)
        return cal, ConfidenceLevel.PROVEN

    if live and evidence_count >= 2 and raw >= 0.58:
        cal = min(CONFIDENCE_CAP, raw + 0.06)
        return cal, ConfidenceLevel.STRONG

    if direct_observation and raw >= 0.78:
        cal = min(_NO_LIVE_CAP if not live else CONFIDENCE_CAP, raw)
        return cal, ConfidenceLevel.STRONG

    if raw >= 0.72 and evidence_count >= 1:
        cal = min(_NO_LIVE_CAP if not live else CONFIDENCE_CAP - 0.05, raw)
        return cal, ConfidenceLevel.STRONG

    if raw >= 0.45 and evidence_count >= 1:
        cal = min(_NO_LIVE_CAP * 0.9 if not live else _NO_LIVE_CAP, raw)
        return cal, ConfidenceLevel.WEAK

    cal = min(_NO_LIVE_CAP * 0.8, raw * 0.88)
    return cal, ConfidenceLevel.SPECULATIVE


def _apply_tunnel_conflict_rules(
    matches: list[TunnelTypeMatch],
    r: AnalysisResult,
) -> list[TunnelTypeMatch]:
    if not matches:
        return matches

    cdn_matches = [m for m in matches if m.tunnel_id in _CDN_TUNNEL_IDS]
    direct_matches = [m for m in matches if m.tunnel_id in _DIRECT_TOPOLOGY_IDS]
    has_cdn = _cdn_detected(r)

    best_cdn = max(cdn_matches, key=lambda m: m.confidence, default=None)
    cdn_strong = best_cdn and best_cdn.confidence >= 0.65 and has_cdn

    updated: list[TunnelTypeMatch] = []
    for m in matches:
        cal = m.calibrated_confidence
        level = m.confidence_level

        if cdn_strong and m.tunnel_id in _DIRECT_TOPOLOGY_IDS:
            # CDN fronting contradicts "direct public inbound" — proxy live ≠ direct exposure
            cal = min(cal, 0.55)
            level = _demote(level, 2)
            if _level_rank(level) < _level_rank(ConfidenceLevel.WEAK):
                level = ConfidenceLevel.WEAK

        if m.tunnel_id in _CDN_TUNNEL_IDS and not has_cdn and m.confidence < 0.75:
            level = _demote(level, 1)
            cal = min(cal, 0.62)

        if m.tunnel_id == "direct_xray_inbound" and r.connectivity.http_reverse_proxy:
            cal = min(cal, 0.50)
            level = ConfidenceLevel.WEAK

        updated.append(m.model_copy(update={
            "calibrated_confidence": round(cal, 3),
            "confidence_level": level,
        }))

    # Among CDN variants, demote lower-confidence duplicates
    cdn_in_updated = [m for m in updated if m.tunnel_id in _CDN_TUNNEL_IDS]
    if len(cdn_in_updated) >= 2:
        winner = max(cdn_in_updated, key=lambda m: m.calibrated_confidence)
        demoted_ids = {m.tunnel_id for m in cdn_in_updated if m.tunnel_id != winner.tunnel_id}
        final: list[TunnelTypeMatch] = []
        for m in updated:
            if m.tunnel_id in demoted_ids and m.calibrated_confidence < winner.calibrated_confidence:
                final.append(m.model_copy(update={
                    "calibrated_confidence": min(m.calibrated_confidence, winner.calibrated_confidence - 0.15),
                    "confidence_level": _demote(m.confidence_level, 1),
                }))
            else:
                final.append(m)
        updated = final

    return updated


def _apply_deployment_conflict_rules(
    guesses: list[DeploymentGuess],
    r: AnalysisResult,
) -> list[DeploymentGuess]:
    if not guesses:
        return guesses

    cdn_guesses = [g for g in guesses if g.name in _CDN_DEPLOYMENT_NAMES]
    direct_guesses = [g for g in guesses if g.name in _DIRECT_DEPLOYMENT_NAMES]
    best_cdn = max(cdn_guesses, key=lambda g: g.confidence, default=None)
    cdn_strong = best_cdn and best_cdn.confidence >= 0.70 and _cdn_detected(r)

    updated: list[DeploymentGuess] = []
    for g in guesses:
        cal = g.calibrated_confidence
        level = g.confidence_level

        if cdn_strong and g.name in _DIRECT_DEPLOYMENT_NAMES and g.name != "Reverse Proxy":
            cal = min(cal, 0.52)
            level = _demote(level, 2)

        if g.name == "Reverse Proxy" and cdn_strong and not r.connectivity.http_reverse_proxy:
            cal = min(cal, 0.48)
            level = ConfidenceLevel.WEAK

        if g.name in _CDN_DEPLOYMENT_NAMES and not _cdn_detected(r) and g.confidence < 0.55:
            level = _demote(level, 1)

        updated.append(g.model_copy(update={
            "calibrated_confidence": round(cal, 3),
            "confidence_level": level,
        }))

    # Keep only top CDN at STRONG+ when multiple CDN guesses fire
    cdn_updated = [g for g in updated if g.name in _CDN_DEPLOYMENT_NAMES and g.confidence >= 0.55]
    if len(cdn_updated) >= 2:
        winner = max(cdn_updated, key=lambda g: g.calibrated_confidence)
        final: list[DeploymentGuess] = []
        for g in updated:
            if g.name in _CDN_DEPLOYMENT_NAMES and g.name != winner.name and g.confidence >= 0.55:
                final.append(g.model_copy(update={
                    "calibrated_confidence": min(g.calibrated_confidence, 0.58),
                    "confidence_level": ConfidenceLevel.WEAK,
                }))
            else:
                final.append(g)
        updated = final

    return updated


def build_confidence_calibration(
    r: AnalysisResult,
    tunnel: TunnelAnalysis,
    deployment: DeploymentAnalysis,
    dpi: DPIDetectabilityReport,
    camouflage: TrafficCamouflageReport,
    origin: OriginExposureReport,
) -> tuple[ConfidenceCalibrationReport, TunnelAnalysis, DeploymentAnalysis]:
    """Calibrate conclusions with 4-tier evidence and conflict resolution."""
    live = _live_proxy_ok(r)
    insights: list[CalibratedInsight] = []

    new_matches: list[TunnelTypeMatch] = []
    for match in tunnel.detected_types:
        if not match.evidence:
            continue
        ev_joined = " ".join(match.evidence).lower()
        direct_obs = "cname=" in ev_joined or (
            "internet_e2e_verified" in ev_joined
            and any(tok in ev_joined for tok in ("panel=", "http_server=", "tls_fingerprint=", "cfargotunnel"))
        )
        cal, level = calibrate_evidence(
            match.confidence,
            live=live,
            evidence_count=len(match.evidence),
            direct_observation=direct_obs,
            heuristic_only=match.confidence < 0.4 and len(match.evidence) < 2,
        )
        new_matches.append(match.model_copy(update={
            "calibrated_confidence": cal,
            "confidence_level": level,
        }))

    new_matches = _apply_tunnel_conflict_rules(new_matches, r)

    for match in new_matches:
        insights.append(CalibratedInsight(
            category="Tunnel",
            title=match.name,
            description=match.description or match.traffic_flow,
            confidence=match.confidence_level,
            evidence=match.evidence[:4],
            raw_confidence=match.confidence,
            calibrated_confidence=match.calibrated_confidence,
        ))

    primary_level = ConfidenceLevel.SPECULATIVE
    primary_cal = tunnel.primary_confidence
    if new_matches:
        top = max(new_matches, key=lambda m: m.calibrated_confidence)
        primary_cal = top.calibrated_confidence
        primary_level = top.confidence_level

    new_tunnel = tunnel.model_copy(update={
        "detected_types": new_matches,
        "primary_confidence": primary_cal,
        "primary_confidence_level": primary_level,
    })

    new_guesses: list[DeploymentGuess] = []
    for guess in deployment.guesses:
        if guess.confidence < 0.35:
            cal, level = calibrate_evidence(
                guess.confidence, live=live, evidence_count=0, heuristic_only=True,
            )
        else:
            direct_obs = guess.confidence >= 0.75 and _cdn_detected(r) and guess.name in _CDN_DEPLOYMENT_NAMES
            cal, level = calibrate_evidence(
                guess.confidence,
                live=live,
                evidence_count=1 if guess.confidence >= 0.6 else 0,
                direct_observation=direct_obs,
                heuristic_only=guess.confidence < 0.45,
            )
        new_guesses.append(guess.model_copy(update={
            "calibrated_confidence": cal,
            "confidence_level": level,
        }))

    new_guesses = _apply_deployment_conflict_rules(new_guesses, r)

    for guess in new_guesses:
        if guess.confidence < 0.35:
            continue
        insights.append(CalibratedInsight(
            category="Deployment",
            title=guess.name,
            description=guess.description,
            confidence=guess.confidence_level,
            evidence=[f"heuristic_confidence={guess.confidence:.2f}"],
            raw_confidence=guess.confidence,
            calibrated_confidence=guess.calibrated_confidence,
        ))

    if dpi.score is not None:
        insights.append(CalibratedInsight(
            category="DPI",
            title=f"DPI resistance {dpi.score}/100",
            description=dpi.summary,
            confidence=ConfidenceLevel.STRONG if live else ConfidenceLevel.WEAK,
            evidence=[e for f in dpi.factors[:4] for e in f.evidence[:1]],
            raw_confidence=dpi.score / 100,
            calibrated_confidence=dpi.score / 100,
        ))
    if camouflage.score is not None:
        insights.append(CalibratedInsight(
            category="Camouflage",
            title=f"Traffic camouflage {camouflage.score}/100",
            description=camouflage.summary,
            confidence=ConfidenceLevel.STRONG if live else ConfidenceLevel.WEAK,
            evidence=[e for f in camouflage.layers[:4] for e in f.evidence[:1]],
            raw_confidence=camouflage.score / 100,
            calibrated_confidence=camouflage.score / 100,
        ))
    if origin.risk_score is not None:
        origin_conf = (
            ConfidenceLevel.STRONG if origin.factors
            else ConfidenceLevel.SPECULATIVE
        )
        insights.append(CalibratedInsight(
            category="Origin",
            title=f"Origin exposure {origin.risk_score}/100 ({origin.exposure_level})",
            description=origin.summary,
            confidence=origin_conf,
            evidence=[e for f in origin.factors[:4] for e in f.evidence[:1]],
            raw_confidence=origin.risk_score / 100,
            calibrated_confidence=origin.risk_score / 100,
        ))

    if not insights:
        return ConfidenceCalibrationReport(
            summary="No calibratable conclusions — run full analysis first.",
        ), new_tunnel, deployment.model_copy(update={"guesses": new_guesses})

    proven = sum(1 for i in insights if i.confidence == ConfidenceLevel.PROVEN)
    strong = sum(1 for i in insights if i.confidence == ConfidenceLevel.STRONG)
    weak = sum(1 for i in insights if i.confidence == ConfidenceLevel.WEAK)
    spec = sum(1 for i in insights if i.confidence == ConfidenceLevel.SPECULATIVE)
    summary = (
        f"{proven} Proven, {strong} Strong, {weak} Weak, {spec} Speculative "
        f"(live test {'on' if live else 'off'})."
    )

    report = ConfidenceCalibrationReport(summary=summary, insights=insights)
    new_deploy = deployment.model_copy(update={"guesses": new_guesses})
    return report, new_tunnel, new_deploy
