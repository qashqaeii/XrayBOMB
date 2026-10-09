"""HTTP response fingerprinting — CDN headers, panel detection."""

from __future__ import annotations

import re
from typing import Optional

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

_CDN_SERVER_MAP = {
    "arvancloud": "ArvanCloud",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fastly": "Fastly",
    "amazons3": "CloudFront",
    "cloudfront": "CloudFront",
    "bunnycdn": "Bunny",
    "gcore": "Gcore",
}

_PANEL_PATTERNS: list[tuple[str, str]] = [
    (r"3x-ui", "3x-ui"),
    (r"X_UI_BASE_PATH", "3x-ui"),
    (r"set-cookie:\s*3x-ui=", "3x-ui"),
    (r"marzban", "Marzban"),
    (r"x-ui", "3x-ui"),
]


def _detect_cdn_from_headers(headers: dict[str, str]) -> Optional[str]:
    server = (headers.get("server") or "").lower()
    for key, name in _CDN_SERVER_MAP.items():
        if key in server:
            return name
    for h in ("x-arvan", "x-cache", "cf-ray", "x-sid"):
        if h in headers:
            if h in ("x-arvan", "x-sid"):
                return "ArvanCloud"
            if h == "cf-ray":
                return "Cloudflare"
    return None


def _detect_panel(headers: dict[str, str], body: str) -> Optional[str]:
    combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower() + body.lower()
    for pattern, name in _PANEL_PATTERNS:
        if re.search(pattern, combined, re.I):
            return name
    if "sign in" in body.lower() and "3x-ui" in combined:
        return "3x-ui"
    return None


def _detect_reverse_proxy_server(headers: dict[str, str]) -> Optional[str]:
    server = (headers.get("server") or "").lower()
    if "nginx" in server:
        return "nginx"
    if "caddy" in server:
        return "caddy"
    if "apache" in server:
        return "apache"
    if "openresty" in server:
        return "openresty"
    return None


async def probe_http_fingerprint(
    host: str,
    port: int,
    path: str = "/",
    sni: Optional[str] = None,
    timeout: float = 12.0,
) -> dict:
    """
    Probe HTTPS/HTTP and extract CDN, panel, and reverse-proxy signals.
    Uses the domain name (not resolved IP) so CDN headers are visible.
    """
    path = path if path.startswith("/") else f"/{path}"
    scheme = "https" if port in (443, 8443, 2053, 2083) else "http"
    authority = f"{host}:{port}" if port not in (80, 443) else host
    url = f"{scheme}://{authority}{path}"

    out: dict = {
        "url": url,
        "http_server": None,
        "cdn_detected": None,
        "panel_detected": None,
        "reverse_proxy_server": None,
        "status_code": None,
        "headers": {},
        "error": None,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            req_host = sni or host
            resp = await client.get(url, headers={"Host": req_host, "User-Agent": "XrayBOMB-Probe/1.0"})
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            body = resp.text[:8000] if resp.text else ""

            out["status_code"] = resp.status_code
            out["http_server"] = hdrs.get("server")
            out["headers"] = {k: hdrs[k] for k in (
                "server", "x-cache", "x-sid", "x-arvan", "cf-ray", "via", "set-cookie",
            ) if k in hdrs}
            out["cdn_detected"] = _detect_cdn_from_headers(hdrs)
            out["panel_detected"] = _detect_panel(hdrs, body)
            out["reverse_proxy_server"] = _detect_reverse_proxy_server(hdrs)
    except Exception as exc:
        logger.debug("HTTP fingerprint probe failed for %s: %s", url, exc)
        out["error"] = str(exc)

    return out
