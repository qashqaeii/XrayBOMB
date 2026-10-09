"""Shared helpers for stealth / intelligence scoring."""

from __future__ import annotations

from typing import Optional

from backend.models import AnalysisResult, ConfidenceLevel, ParsedConfig, RiskFactor, TestStatus, TransportType

_SCORE_NEUTRAL = 50
_BROWSER_FPS = frozenset({"chrome", "firefox", "safari", "ios", "android", "edge", "random"})
_ALT_TLS_PORTS = frozenset({8443, 2053, 2083, 2087, 2096, 443})
_INSUFFICIENT = "Insufficient observed signals — no score computed."


def clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def grade(score: Optional[int], *, higher_is_better: bool = True) -> str:
    if score is None:
        return "—"
    s = score if higher_is_better else 100 - score
    if s >= 90:
        return "A"
    if s >= 75:
        return "B"
    if s >= 60:
        return "C"
    if s >= 45:
        return "D"
    return "F"


def score_bar(score: Optional[int], width: int = 10) -> str:
    if score is None:
        return "—" * width
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def format_score(score: Optional[int], *, suffix: str = "/100") -> str:
    if score is None:
        return "N/A"
    return f"{score}{suffix}"


def factor(
    title: str,
    description: str,
    impact: int,
    *,
    confidence: ConfidenceLevel,
    evidence: list[str],
) -> RiskFactor:
    clean = [e for e in evidence if e and e.strip()]
    if not clean:
        raise ValueError(f"RiskFactor requires observed evidence: {title}")
    return RiskFactor(
        title=title,
        description=description,
        impact=impact,
        confidence=confidence,
        evidence=clean,
    )


def composite_score(factors: list[RiskFactor]) -> Optional[int]:
    if not factors:
        return None
    return clamp(_SCORE_NEUTRAL + sum(f.impact for f in factors))


def weighted_composite(
    factors: list[RiskFactor],
    *,
    synergy_bonus: int = 0,
    penalty_cap: int = 45,
    bonus_cap: int = 40,
) -> Optional[int]:
    """Dynamic score: dampen stacked penalties/bonuses, apply synergy."""
    if not factors:
        return None
    pos = sum(f.impact for f in factors if f.impact > 0)
    neg = sum(f.impact for f in factors if f.impact < 0)
    pos = min(pos, bonus_cap)
    neg = max(neg, -penalty_cap)
    return clamp(_SCORE_NEUTRAL + pos + neg + synergy_bonus)


def effective_transport(c: ParsedConfig) -> TransportType:
    if c.transport_type != TransportType.UNKNOWN:
        return c.transport_type
    raw = str(c.extra.get("type") or c.extra.get("net") or "").lower()
    mapping = {
        "tcp": TransportType.TCP,
        "ws": TransportType.WS,
        "grpc": TransportType.GRPC,
        "httpupgrade": TransportType.HTTPUPGRADE,
        "http": TransportType.HTTPUPGRADE,
        "xhttp": TransportType.XHTTP,
        "splithttp": TransportType.XHTTP,
        "quic": TransportType.QUIC,
    }
    return mapping.get(raw, TransportType.UNKNOWN)


def live_proxy_ok(r: AnalysisResult) -> bool:
    from backend.e2e_validity import evaluate_xray_test_result

    return evaluate_xray_test_result(r.xray_test).internet_verified


def exit_ip(r: AnalysisResult) -> Optional[str]:
    return r.xray_test.exit_ip or r.xray_test.leak_check.proxy_exit_ip


def has_analyzable_config(c: ParsedConfig) -> bool:
    return bool(c.address and c.port)


def format_risk_factors(factors: list[RiskFactor], *, limit: int = 12) -> list[str]:
    if not factors:
        return ["  (no observed signals)"]
    lines: list[str] = []
    for f in factors[:limit]:
        sign = "+" if f.impact >= 0 else ""
        lines.append(f"  [{f.confidence.value}] {f.title} ({sign}{f.impact})")
        lines.append(f"      {f.description}")
        for ev in f.evidence[:2]:
            lines.append(f"      ↳ {ev}")
    return lines
