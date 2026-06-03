"""Transport-specific connectivity probes."""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Optional

import httpx

from backend.models import ParsedConfig, TestStatus, TransportTestResult, TransportType
from utils.logger import get_logger

logger = get_logger(__name__)


async def test_grpc(host: str, port: int, service_name: Optional[str], sni: Optional[str]) -> TransportTestResult:
    result = TransportTestResult(transport="gRPC")
    url = f"https://{host}:{port}/{service_name or ''}"
    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, http2=True) as client:
            headers = {":authority": sni or host} if sni else {}
            resp = await client.get(url, headers=headers)
            result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            result.status = TestStatus.VALID if resp.status_code < 500 else TestStatus.WARNING
            result.details = f"HTTP/2 response {resp.status_code}"
    except Exception as exc:
        result.status = TestStatus.INVALID
        result.details = str(exc)[:200]
    return result


async def test_quic_probe(host: str, port: int) -> TransportTestResult:
    result = TransportTestResult(transport="QUIC")
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            start = time.perf_counter()
            resp = await client.get(f"https://{host}:{port}/", headers={"Alt-Svc": "h3=\":443\""})
            result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            alt_svc = resp.headers.get("alt-svc", "")
            if "h3" in alt_svc.lower() or "quic" in alt_svc.lower():
                result.status = TestStatus.VALID
                result.details = f"Alt-Svc: {alt_svc[:100]}"
            else:
                result.status = TestStatus.WARNING
                result.details = "No QUIC/H3 Alt-Svc header detected"
    except Exception as exc:
        result.status = TestStatus.INVALID
        result.details = str(exc)[:200]
    return result


async def test_reality_fingerprint(config: ParsedConfig, host: str, port: int) -> TransportTestResult:
    result = TransportTestResult(transport="REALITY")
    if not config.reality:
        result.status = TestStatus.SKIPPED
        result.details = "REALITY not enabled in config"
        return result
    if not config.public_key:
        result.status = TestStatus.INVALID
        result.details = "Missing REALITY public key"
        return result
    sni = config.sni or host
    start = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        loop = asyncio.get_event_loop()

        def _probe() -> str:
            import socket
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    return ssock.version() or "unknown"

        version = await loop.run_in_executor(None, _probe)
        result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        result.status = TestStatus.VALID
        result.details = f"TLS probe OK ({version}), pbk present, sid={'yes' if config.short_id else 'no'}"
    except Exception as exc:
        result.status = TestStatus.WARNING
        result.details = f"REALITY params present but TLS probe failed: {exc}"[:200]
    return result


async def test_websocket_with_headers(
    host: str, port: int, path: str, host_header: str, sni: Optional[str],
) -> TransportTestResult:
    import websocket

    result = TransportTestResult(transport="WebSocket")
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    scheme = "wss" if port == 443 else "ws"
    url = f"{scheme}://{host}:{port}{path}"

    def _ws() -> tuple[bool, str]:
        try:
            ws = websocket.create_connection(
                url, timeout=12,
                header={"Host": host_header, "User-Agent": "Mozilla/5.0"},
                sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            ws.close()
            return True, "WebSocket upgrade OK"
        except Exception as exc:
            return False, str(exc)[:200]

    start = time.perf_counter()
    loop = asyncio.get_event_loop()
    ok, detail = await loop.run_in_executor(None, _ws)
    result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
    result.status = TestStatus.VALID if ok else TestStatus.INVALID
    result.details = detail
    return result


async def run_transport_tests(config: ParsedConfig, connect_host: str) -> list[TransportTestResult]:
    port = config.port or 443
    sni = config.sni or config.host or config.address
    tests: list[TransportTestResult] = []

    if config.transport_type == TransportType.GRPC:
        tests.append(await test_grpc(connect_host, port, config.service_name, sni))
    elif config.transport_type == TransportType.QUIC:
        tests.append(await test_quic_probe(connect_host, port))
    elif config.transport_type == TransportType.WS:
        tests.append(await test_websocket_with_headers(
            connect_host, port, config.path or "/", config.host or sni or connect_host, sni,
        ))

    if config.reality:
        tests.append(await test_reality_fingerprint(config, connect_host, port))

    return tests
