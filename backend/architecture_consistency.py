"""Single source of truth helpers — align tabs/exports with ArchitectureDiagnosticsReport."""

from __future__ import annotations

from backend.architecture_diagnostics import build_architecture_diagnostics
from backend.models import (
    AnalysisResult,
    ArchitectureDiagnosticsReport,
    DeploymentAnalysis,
    DeploymentGuess,
    DeploymentSetupGuide,
    TunnelAnalysis,
    TunnelTypeMatch,
)

_CDN_GUESS_NAMES = frozenset({
    "CDN Fronted",
    "Cloudflare CDN",
    "Arvan CDN",
    "Akamai CDN",
    "Fastly CDN",
    "AWS CloudFront",
    "BunnyCDN",
    "Gcore CDN",
})

_CDN_TUNNEL_SUFFIX = "_cdn"
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


def ensure_architecture_diagnostics(r: AnalysisResult) -> ArchitectureDiagnosticsReport:
    if r.architecture_diagnostics.endpoint and r.architecture_diagnostics.assessment_title:
        return r.architecture_diagnostics
    return build_architecture_diagnostics(r)


def cdn_fronting_tier(r: AnalysisResult) -> str:
    diag = ensure_architecture_diagnostics(r)
    if diag.cdn_fronting_tier:
        return diag.cdn_fronting_tier
    for line in diag.infrastructure:
        if line.label == "CDN fronting":
            return line.status
    return "unconfirmed"


def cdn_edge_proven(r: AnalysisResult) -> bool:
    return cdn_fronting_tier(r) == "confirmed"


def cdn_scenario_allowed(r: AnalysisResult) -> bool:
    return cdn_fronting_tier(r) in ("confirmed", "probable")


def cap_tunnel_confidence(tunnel_id: str, confidence: float, r: AnalysisResult) -> float:
    if tunnel_id in _CDN_TUNNEL_IDS or tunnel_id.endswith(_CDN_TUNNEL_SUFFIX):
        tier = cdn_fronting_tier(r)
        if tier == "unconfirmed":
            return min(confidence, 0.42)
        if tier == "probable":
            return min(confidence, 0.62)
    if tunnel_id == "direct_vps" and not cdn_edge_proven(r):
        return max(confidence, 0.48)
    return confidence


def catalog_status_for_topology(tunnel_id: str, r: AnalysisResult, match_conf: float) -> str:
    if match_conf >= 0.30:
        return f"COMPATIBLE  {int(match_conf * 100)}%  (evidence-weighted)"
    tier = cdn_fronting_tier(r)
    if tunnel_id == "direct_vps":
        if cdn_edge_proven(r):
            return "UNLIKELY — CDN edge proven on wire"
        return "COMPATIBLE — not ruled out (no contradicting proof)"
    if tunnel_id in _CDN_TUNNEL_IDS:
        if tier == "unconfirmed":
            return "UNCONFIRMED — insufficient CDN edge proof"
        if tier == "probable":
            return "POSSIBLE — weak CDN hints only"
    return "UNKNOWN — insufficient evidence"


def _align_deployment(r: AnalysisResult, diag: ArchitectureDiagnosticsReport) -> DeploymentAnalysis:
    d = r.deployment
    tier = diag.cdn_fronting_tier or cdn_fronting_tier(r)
    new_guesses: list[DeploymentGuess] = []
    cdn_type = d.cdn_type
    if tier == "unconfirmed":
        cdn_type = None
    elif tier == "probable" and cdn_type:
        cdn_type = cdn_type  # keep label but capped confidence

    for g in d.guesses:
        conf = g.confidence
        desc = g.description
        if g.name in _CDN_GUESS_NAMES:
            if tier == "unconfirmed":
                conf = min(conf, 0.40)
                desc = (
                    "CDN not confirmed on wire — DNS/ASN alone is insufficient. "
                    + (desc or "")
                ).strip()
            elif tier == "probable":
                conf = min(conf, 0.58)
                desc = (desc or "") + " (probable CDN hint — not proven path)"
        if g.name == "Direct VPS" and tier == "unconfirmed":
            conf = max(conf, 0.52)
        new_guesses.append(g.model_copy(update={"confidence": round(conf, 3), "description": desc}))

    new_guesses.sort(key=lambda x: x.confidence, reverse=True)
    uncertain = list(d.uncertain_fields)
    if tier == "unconfirmed" and "CDN edge IPs (not origin/backend)" in uncertain:
        uncertain = [u for u in uncertain if "CDN edge" not in u]
    if diag.origin_ip_status == "unknown" and "Real server IP" not in uncertain:
        uncertain.append("Origin IP (not proven client-side)")

    return d.model_copy(update={
        "guesses": new_guesses,
        "cdn_type": cdn_type,
        "uncertain_fields": list(dict.fromkeys(uncertain)),
    })


def _align_tunnel_analysis(r: AnalysisResult, diag: ArchitectureDiagnosticsReport) -> TunnelAnalysis:
    ta = r.tunnel_analysis
    matches: list[TunnelTypeMatch] = []
    for m in ta.detected_types:
        conf = cap_tunnel_confidence(m.tunnel_id, m.confidence, r)
        ev = list(m.evidence)
        if m.tunnel_id in _CDN_TUNNEL_IDS and cdn_fronting_tier(r) == "unconfirmed":
            ev.append("cdn_fronting=unconfirmed (DNS/ASN not proof)")
        matches.append(m.model_copy(update={"confidence": conf, "evidence": ev}))
    primary = diag.primary_scenario_label or ta.primary_type
    primary_conf = ta.primary_confidence
    if matches:
        top = max(matches, key=lambda x: x.confidence)
        if cdn_fronting_tier(r) == "unconfirmed" and top.tunnel_id in _CDN_TUNNEL_IDS:
            direct = next((m for m in matches if m.tunnel_id == "direct_vps"), None)
            if direct:
                primary = direct.name
                primary_conf = direct.confidence
        else:
            primary = top.name
            primary_conf = top.confidence
    return ta.model_copy(update={
        "detected_types": matches,
        "primary_type": primary,
        "primary_confidence": primary_conf,
    })


def _align_setup_guide(sg: DeploymentSetupGuide, diag: ArchitectureDiagnosticsReport) -> DeploymentSetupGuide:
    facts = [f for f in sg.infrastructure_facts if not f.startswith("Detected CDN:")]
    if diag.cdn_fronting_tier == "confirmed":
        for line in diag.infrastructure:
            if line.label == "CDN fronting":
                facts.append(f"CDN fronting (confirmed): {line.detail}")
    elif diag.cdn_fronting_tier in ("unconfirmed", "probable"):
        facts.append(
            f"CDN fronting: {diag.cdn_fronting_tier} — do not treat DNS provider or ASN as CDN proof."
        )
    facts.append(f"Origin IP: {diag.origin_ip_status}")
    summary = (
        f"Evidence-based architecture: {diag.assessment_title}. "
        f"{diag.assessment_summary}"
    )
    return sg.model_copy(update={
        "detected_scenario": diag.assessment_title,
        "scenario_confidence": 0.55 if "probable" in diag.assessment_title.lower() else 0.48,
        "summary": summary,
        "infrastructure_facts": facts,
    })


def align_analysis_with_architecture(r: AnalysisResult) -> AnalysisResult:
    """Apply ArchitectureDiagnosticsReport across deployment, tunnels, and setup guide."""
    diag = ensure_architecture_diagnostics(r)
    deployment = _align_deployment(r, diag)
    tunnel_analysis = _align_tunnel_analysis(r, diag)
    setup_guide = _align_setup_guide(r.setup_guide, diag)
    return r.model_copy(update={
        "architecture_diagnostics": diag,
        "deployment": deployment,
        "tunnel_analysis": tunnel_analysis,
        "setup_guide": setup_guide,
    })
