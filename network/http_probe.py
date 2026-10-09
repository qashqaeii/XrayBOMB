"""HTTP response fingerprinting — CDN headers, panel detection, WS handshake."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import re
import socket
import ssl
import time
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


_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85511"
_BASELINE_HEADER_KEYS = (
    "server", "connection", "upgrade", "sec-websocket-version",
    "x-cache", "x-sid", "x-arvan", "cf-ray", "via",
)


def classify_http_baseline_status(status_code: Optional[int], headers: dict[str, str]) -> tuple[str, str]:
    """
    Map HTTP GET baseline to connectivity status label and note.
    HTTP 400 with Sec-WebSocket-Version is expected for some WS-only inbounds — not a hard failure.
    """
    if status_code is None:
        return "Invalid", "No HTTP status"
    hdrs = {k.lower(): v for k, v in headers.items()}
    ws_hint = "sec-websocket-version" in hdrs
    if status_code == 101:
        return "Valid", "HTTP 101 on plain GET (unusual — WS path may accept upgrade early)"
    if status_code == 400 and ws_hint:
        return "Valid", (
            f"HTTP {status_code} with Sec-WebSocket-Version — WS-only listener behavior, not connect failure"
        )
    if status_code < 500:
        note = f"HTTP {status_code}"
        if ws_hint:
            note += " (Sec-WebSocket-Version present)"
        return "Valid", note
    return "Warning", f"HTTP {status_code}"


async def probe_http_baseline(
    connect_host: str,
    port: int,
    path: str,
    host_header: str,
    *,
    use_tls: bool = False,
    tls_sni: Optional[str] = None,
    timeout: float = 12.0,
) -> dict:
    """GET baseline against connect IP with correct Host header (no WS upgrade)."""
    path = path if path.startswith("/") else f"/{path}"
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{connect_host}:{port}{path}"
    out: dict = {
        "url": url,
        "host_header": host_header,
        "status_code": None,
        "latency_ms": None,
        "headers": {},
        "http_server": None,
        "cdn_detected": None,
        "reverse_proxy_server": None,
        "websocket_hint": False,
        "status_label": "Invalid",
        "note": "",
        "error": None,
    }
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, trust_env=False) as client:
            resp = await client.get(
                url,
                headers={
                    "Host": host_header,
                    "User-Agent": "Mozilla/5.0 (XrayBOMB-Probe)",
                    "Accept": "*/*",
                },
            )
            out["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            out["status_code"] = resp.status_code
            out["headers"] = {k: hdrs[k] for k in _BASELINE_HEADER_KEYS if k in hdrs}
            out["http_server"] = hdrs.get("server")
            out["cdn_detected"] = _detect_cdn_from_headers(hdrs)
            out["reverse_proxy_server"] = _detect_reverse_proxy_server(hdrs)
            out["websocket_hint"] = "sec-websocket-version" in hdrs
            label, note = classify_http_baseline_status(resp.status_code, hdrs)
            out["status_label"] = label
            out["note"] = note
    except Exception as exc:
        logger.debug("HTTP baseline failed %s: %s", url, exc)
        out["error"] = str(exc)[:200]
    return out


def _expected_ws_accept(key: str) -> str:
    digest = hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def _parse_http_response(raw: bytes) -> tuple[int, dict[str, str], str]:
    text = raw.decode("latin-1", errors="replace")
    if "\r\n\r\n" not in text:
        return 0, {}, text[:400]
    head, _rest = text.split("\r\n\r\n", 1)
    lines = head.split("\r\n")
    status_code = 0
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return status_code, headers, head[:500]


def validate_websocket_handshake_response(
    status_code: int,
    headers: dict[str, str],
    ws_key: str,
) -> tuple[bool, list[str], dict[str, str]]:
    """Validate RFC6455 handshake response fields (independent of post-handshake timeout)."""
    checks: list[str] = []
    ok = True
    expected = _expected_ws_accept(ws_key.strip())
    received = (headers.get("sec-websocket-accept") or "").strip()
    debug = {
        "ws_key": ws_key,
        "expected_accept": expected,
        "received_accept": received,
    }
    if status_code != 101:
        checks.append(f"status={status_code} (expected 101)")
        ok = False
    else:
        checks.append("status=101 Switching Protocols")
    upgrade = (headers.get("upgrade") or "").lower()
    if upgrade != "websocket":
        checks.append(f"Upgrade={upgrade or 'missing'} (expected websocket)")
        ok = False
    else:
        checks.append("Upgrade=websocket")
    conn = (headers.get("connection") or "").lower()
    if "upgrade" not in conn:
        checks.append(f"Connection={conn or 'missing'} (expected Upgrade)")
        ok = False
    else:
        checks.append("Connection contains Upgrade")
    if not received:
        checks.append("Sec-WebSocket-Accept missing")
        ok = False
    elif received != expected:
        checks.append(
            f"Sec-WebSocket-Accept mismatch expected={expected} received={received}"
        )
        ok = False
    else:
        checks.append("Sec-WebSocket-Accept valid")
    return ok, checks, debug


def _sync_websocket_handshake(
    connect_host: str,
    port: int,
    path: str,
    host_header: str,
    *,
    use_tls: bool,
    tls_sni: Optional[str],
    timeout: float,
) -> dict:
    path = path if path.startswith("/") else f"/{path}"
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"User-Agent: XrayBOMB-Probe/1.0\r\n"
        f"\r\n"
    ).encode("ascii")

    out: dict = {
        "status_code": None,
        "handshake_ok": False,
        "checks": [],
        "headers": {},
        "accept_debug": {},
        "ws_key": ws_key,
        "error": None,
        "post_handshake_note": None,
    }
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((connect_host, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=tls_sni or host_header)
        sock.settimeout(timeout)
        sock.sendall(request)
        chunks: list[bytes] = []
        while b"\r\n\r\n" not in b"".join(chunks) and sum(len(c) for c in chunks) < 8192:
            try:
                part = sock.recv(4096)
            except socket.timeout:
                break
            if not part:
                break
            chunks.append(part)
        raw = b"".join(chunks)
        status_code, headers, _preview = _parse_http_response(raw)
        out["status_code"] = status_code
        out["headers"] = {k: headers[k] for k in (
            "upgrade", "connection", "sec-websocket-accept", "server",
        ) if k in headers}
        ok, checks, debug = validate_websocket_handshake_response(status_code, headers, ws_key)
        out["handshake_ok"] = ok
        out["checks"] = checks
        out["accept_debug"] = debug
        if ok:
            out["post_handshake_note"] = (
                "Handshake validated; post-upgrade read/timeout is separate from handshake success."
            )
    except Exception as exc:
        out["error"] = str(exc)[:200]
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
    return out


async def probe_websocket_handshake(
    connect_host: str,
    port: int,
    path: str,
    host_header: str,
    *,
    use_tls: bool = False,
    tls_sni: Optional[str] = None,
    timeout: float = 12.0,
) -> dict:
    loop = asyncio.get_event_loop()
    start = time.perf_counter()
    result = await loop.run_in_executor(
        None,
        lambda: _sync_websocket_handshake(
            connect_host, port, path, host_header,
            use_tls=use_tls, tls_sni=tls_sni, timeout=timeout,
        ),
    )
    result["latency_ms"] = round((time.perf_counter() - start) * 1000, 2)
    result["host_header"] = host_header
    return result
