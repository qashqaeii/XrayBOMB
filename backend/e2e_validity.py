"""Shared criteria: when an Xray run truly verified internet via this config."""

from __future__ import annotations

from dataclasses import dataclass

from backend.models import TestStatus, XrayTestResult

E2E_PROBE_URL = "https://www.gstatic.com/generate_204"
E2E_ENDPOINT_LABEL = "www.gstatic.com/generate_204"


@dataclass(frozen=True)
class InternetE2EValidity:
    """Single source of truth for downstream reports."""

    internet_verified: bool
    stage: str
    reason: str

    @property
    def proxy_usable_for_analysis(self) -> bool:
        return self.internet_verified


def evaluate_e2e_http_contract(
    status_code: int,
    body: bytes,
    *,
    url: str = E2E_PROBE_URL,
) -> tuple[bool, str]:
    """
    Verify response for a specific E2E probe URL.
    Failure means this endpoint was not confirmed — not a blanket invalid config verdict.
    """
    probe = url.rstrip("/")
    if probe.endswith("generate_204") or "generate_204" in probe:
        if status_code == 204:
            if len(body) == 0:
                return True, f"{E2E_ENDPOINT_LABEL}: HTTP 204 empty body"
            return True, f"{E2E_ENDPOINT_LABEL}: HTTP 204 ({len(body)} B body)"
        return False, (
            f"E2E not verified at {E2E_ENDPOINT_LABEL}: expected HTTP 204, "
            f"got {status_code} ({len(body)} B) — does not prove config fails for all destinations"
        )
    return False, f"E2E not verified: no contract defined for probe URL {url!r}"


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
