"""Sample plugin: test reachability of common Iranian sites."""

from __future__ import annotations

import httpx

from backend.models import AnalysisResult, ParsedConfig, SiteReachabilityResult, TestStatus

IRAN_SITES = [
    ("IRNA", "https://www.irna.ir"),
    ("Filimo", "https://www.filimo.com"),
    ("Digikala", "https://www.digikala.com"),
    ("AParat", "https://www.aparat.com"),
]


def _test_sites_sync() -> list[dict]:
    results = []
    with httpx.Client(timeout=8, follow_redirects=True, verify=False) as client:
        for name, url in IRAN_SITES:
            try:
                r = client.head(url)
                ok = r.status_code < 500
                results.append({"name": name, "url": url, "ok": ok, "status": r.status_code})
            except Exception as exc:
                results.append({"name": name, "url": url, "ok": False, "error": str(exc)[:80]})
    return results


def analyze(result: AnalysisResult, config: ParsedConfig) -> AnalysisResult:
    """Plugin hook: append IR site reachability to raw_data."""
    try:
        sites = _test_sites_sync()
    except Exception:
        sites = []

    result.raw_data.setdefault("plugins", {})["iran_sites"] = sites

    if result.xray_test.proxy_test == TestStatus.VALID:
        for s in sites:
            if s.get("ok"):
                result.xray_test.site_reachability.append(SiteReachabilityResult(
                    name=f"IR:{s['name']}",
                    url=s["url"],
                    status=TestStatus.VALID,
                    http_status=s.get("status"),
                    details="Direct reachability from client (not via tunnel)",
                ))

    return result
