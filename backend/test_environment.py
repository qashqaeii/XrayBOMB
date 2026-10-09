"""Describe where tests run from (VPN/proxy limitations)."""

from __future__ import annotations

import platform
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from backend.models import LeakCheckResult, XrayTestResult


class TestEnvironmentReport(BaseModel):
    platform: str = ""
    vpn_guidance: str = ""
    trust_env_direct_http: bool = False
    baseline_ip_sources: list[dict[str, Any]] = Field(default_factory=list)
    baseline_status: str = "unknown"
    baseline_inconclusive: bool = False
    baseline_notes: list[str] = Field(default_factory=list)
    active_proxy_env: Optional[str] = None
    run_id: Optional[str] = None
    limitations: list[str] = Field(default_factory=list)


def _sanitize_proxy_env_value(raw: str) -> str:
    """Never expose credentials from proxy URLs in reports."""
    try:
        if "://" in raw:
            key, url = raw.split("=", 1)
            parsed = urlparse(url.strip())
            host = parsed.hostname or "?"
            port = parsed.port
            scheme = parsed.scheme or "proxy"
            hostport = f"{host}:{port}" if port else host
            return f"{key}={scheme}://{hostport}"
        return raw.split("=")[0] + "=<set>"
    except Exception:
        return "<proxy-env-set>"


def _detect_proxy_env() -> Optional[str]:
    import os

    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        val = os.environ.get(key)
        if val:
            return _sanitize_proxy_env_value(f"{key}={val}")
    return None


def build_test_environment_report(
    *,
    baseline_ip_sources: Optional[list[dict[str, Any]]] = None,
    baseline_status: str = "unknown",
    baseline_inconclusive: bool = False,
    baseline_notes: Optional[list[str]] = None,
    run_id: Optional[str] = None,
) -> TestEnvironmentReport:
    system = platform.system()
    limitations = [
        "trust_env=False skips Python HTTP_PROXY; it does not bypass OS VPN/TUN or Proxifier routes.",
        "VPN/Proxifier active state cannot be inferred reliably from IP equality or mismatch alone.",
    ]
    if system == "Windows":
        vpn_guidance = (
            "برای baseline تمیز، V2Ray/Proxifier/VPN را یک‌بار خاموش کنید و دوباره Analyze بزنید. "
            "trust_env=False فقط متغیرهای پراکسی Python را کنار می‌گذارد؛ "
            "مسیر TUN/VPN/Proxifier سطح سیستم را تضمین نمی‌کند."
        )
    else:
        vpn_guidance = (
            "Turn VPN/proxy off once for a clean baseline. trust_env=False does not remove OS-level VPN/TUN routes."
        )
    return TestEnvironmentReport(
        platform=system,
        vpn_guidance=vpn_guidance,
        trust_env_direct_http=False,
        baseline_ip_sources=baseline_ip_sources or [],
        baseline_status=baseline_status,
        baseline_inconclusive=baseline_inconclusive,
        baseline_notes=baseline_notes or [],
        active_proxy_env=_detect_proxy_env(),
        run_id=run_id,
        limitations=limitations,
    )


def build_test_environment_from_run(
    leak: LeakCheckResult,
    xray_test: Optional[XrayTestResult] = None,
) -> TestEnvironmentReport:
    """Build environment section from the same run's baseline/leak data."""
    return build_test_environment_report(
        baseline_ip_sources=list(leak.baseline_samples),
        baseline_status=leak.baseline_status,
        baseline_inconclusive=leak.baseline_inconclusive,
        baseline_notes=[n for n in leak.notes if n][:12],
        run_id=xray_test.run_id if xray_test else None,
    )
