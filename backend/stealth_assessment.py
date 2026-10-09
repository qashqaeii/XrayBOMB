"""DPI stealth, traffic camouflage, origin exposure, and confidence calibration.

All scores are derived only from observed analysis data (config fields, DNS, probes,
live Xray test). When insufficient signals exist, scores stay None — never fabricated.
"""

from __future__ import annotations

from backend.camouflage_intelligence import build_camouflage_report
from backend.confidence_engine import build_confidence_calibration
from backend.dpi_intelligence import build_dpi_report
from backend.models import AnalysisResult
from backend.origin_intelligence import build_origin_exposure_report
from backend.stealth_common import format_risk_factors, format_score, score_bar

__all__ = [
    "assess_stealth",
    "build_camouflage_report",
    "build_confidence_calibration",
    "build_dpi_report",
    "build_origin_exposure_report",
    "format_risk_factors",
    "format_score",
    "score_bar",
]


def assess_stealth(r: AnalysisResult) -> AnalysisResult:
    """Compute stealth metrics from observed analysis data only."""
    dpi = build_dpi_report(r)
    camouflage = build_camouflage_report(r)
    origin = build_origin_exposure_report(r)
    calibration, tunnel, deployment = build_confidence_calibration(
        r, r.tunnel_analysis, r.deployment, dpi, camouflage, origin,
    )
    return r.model_copy(update={
        "dpi": dpi,
        "camouflage": camouflage,
        "origin_exposure": origin,
        "confidence_calibration": calibration,
        "tunnel_analysis": tunnel,
        "deployment": deployment,
    })
