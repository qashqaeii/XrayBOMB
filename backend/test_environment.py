"""Describe where tests run from (VPN/proxy limitations)."""

from __future__ import annotations

import platform
from typing import Any, Optional

from pydantic import BaseModel, Field


class TestEnvironmentReport(BaseModel):
    platform: str = ""
    vpn_guidance: str = ""
    trust_env_direct_http: bool = False
    baseline_ip_sources: list[dict[str, Any]] = Field(default_factory=list)
    baseline_inconclusive: bool = False
    baseline_notes: list[str] = Field(default_factory=list)
    active_proxy_env: Optional[str] = None


def _detect_proxy_env() -> Optional[str]:
    import os

    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        val = os.environ.get(key)
        if val:
            return f"{key}={val}"
    return None


def build_test_environment_report(
    *,
    baseline_ip_sources: Optional[list[dict[str, Any]]] = None,
    baseline_inconclusive: bool = False,
    baseline_notes: Optional[list[str]] = None,
) -> TestEnvironmentReport:
    system = platform.system()
    if system == "Windows":
        vpn_guidance = (
            "برای مقایسهٔ IP پایه و IP خروجی، VPN/پروکسی سیستم را یک‌بار خاموش و یک‌بار روشن "
            "و دوباره تست کنید. trust_env=False فقط پروکسی محیطی Python را دور می‌زند؛ "
            "مسیر TUN/VPN سطح سیستم‌عامل را قطعی حذف نمی‌کند."
        )
    else:
        vpn_guidance = (
            "Direct HTTP uses trust_env=False (no HTTP_PROXY). OS-level VPN/TUN may still affect routes; "
            "compare results with VPN on/off when baseline looks inconclusive."
        )
    return TestEnvironmentReport(
        platform=system,
        vpn_guidance=vpn_guidance,
        trust_env_direct_http=False,
        baseline_ip_sources=baseline_ip_sources or [],
        baseline_inconclusive=baseline_inconclusive,
        baseline_notes=baseline_notes or [],
        active_proxy_env=_detect_proxy_env(),
    )
