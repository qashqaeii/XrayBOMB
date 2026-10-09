"""Shared criteria: when an Xray run truly verified internet via this config."""

from __future__ import annotations

from dataclasses import dataclass

from backend.models import TestStatus, XrayTestResult

# Contract for generate_204-style probes (not arbitrary HTTP 200 pages).
E2E_PROBE_URL = "https://www.gstatic.com/generate_204"
E2E_PRIMARY_STATUS = 204
E2E_FALLBACK_200_MAX_BODY_BYTES = 512


@dataclass(frozen=True)
class InternetE2EValidity:
    """Single source of truth for downstream reports."""

    internet_verified: bool
    stage: str
    reason: str

    @property
    def proxy_usable_for_analysis(self) -> bool:
        return self.internet_verified


def evaluate_e2e_http_contract(status_code: int, body_len: int) -> tuple[bool, str]:
    if status_code == E2E_PRIMARY_STATUS:
        return True, "generate_204 contract (HTTP 204)"
    if status_code == 200 and body_len <= E2E_FALLBACK_200_MAX_BODY_BYTES:
        return True, f"minimal HTTP 200 body ({body_len} B) — generate_204 variant"
    return False, (
        f"HTTP response does not match E2E contract "
        f"(status={status_code}, body={body_len} B; expected 204 or small 200)"
    )


def evaluate_xray_test_result(x: XrayTestResult) -> InternetE2EValidity:
    """Derive final internet verification from stored run fields (no network I/O)."""
    if x.config_validation == TestStatus.INVALID:
        return InternetE2EValidity(False, "config_validation", "Config rejected by xray -test")
    if x.proxy_test == TestStatus.NOT_TESTED:
        return InternetE2EValidity(
            False,
            "not_run",
            "No SOCKS/internet E2E was performed for this run",
        )
    if x.proxy_test != TestStatus.VALID:
        return InternetE2EValidity(False, "proxy_probe", x.summary or "Proxy E2E probe failed")
    if not x.socks_handshake_verified:
        return InternetE2EValidity(False, "socks_handshake", "SOCKS auth/handshake not verified for this run")
    if not x.process_alive_after_e2e:
        return InternetE2EValidity(
            False,
            "process_exit",
            "Xray process exited before the run could be marked verified — proxy probe invalidated",
        )
    if not x.e2e_contract_ok:
        return InternetE2EValidity(False, "e2e_contract", x.e2e_contract_detail or "E2E HTTP contract failed")
    if not x.internet_e2e_verified:
        return InternetE2EValidity(False, "incomplete", x.summary or "E2E verification incomplete")
    return InternetE2EValidity(True, "verified", x.summary or "Internet E2E verified for this config/run")


def invalidate_proxy_after_process_loss(x: XrayTestResult, *, reason: str) -> None:
    """Ensure a dead process cannot leave a usable VALID proxy_test for analysis."""
    x.proxy_test = TestStatus.INVALID
    x.internet_e2e_verified = False
    x.process_alive_after_e2e = False
    x.e2e_contract_ok = False
    x.e2e_contract_detail = reason
    if reason not in x.errors:
        x.errors.append(reason)
