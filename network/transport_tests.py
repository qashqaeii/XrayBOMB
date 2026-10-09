"""Transport-specific connectivity probes (external — not Xray-core handshake)."""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Optional

import httpx

from backend.models import ParsedConfig, TestStatus, TransportTestResult, TransportType
from network.http_probe import probe_websocket_handshake
from network.transport_security import uses_tls_layer, websocket_scheme
from utils.helpers import is_ip_address
from utils.logger import get_logger

logger = get_logger(__name__)


async def test_grpc(host: str, port: int, service_name: Optional[str], sni: Optional[str]) -> TransportTestResult:
    result = TransportTestResult(transport="gRPC")
    result.status = TestStatus.UNSUPPORTED
    result.details = (
        "Public HTTP/2 GET is not gRPC protocol verification — "
        "use xray-core end-to-end test for gRPC transport."
    )
    return result


async def test_quic_probe(host: str, port: int) -> TransportTestResult:
    result = TransportTestResult(transport="QUIC")
    result.status = TestStatus.NOT_TESTED
    try:
        async with httpx.AsyncClient(timeout=10, verify=False, trust_env=False) as client:
            start = time.perf_counter()
            resp = await client.get(f"https://{host}:{port}/")
            result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            alt_svc = resp.headers.get("alt-svc", "")
            if alt_svc:
                result.details = f"Alt-Svc announcement only: {alt_svc[:120]} (not QUIC handshake proof)"
                result.status = TestStatus.INCONCLUSIVE
            else:
                result.details = "No Alt-Svc — QUIC not confirmed without dedicated probe"
                result.status = TestStatus.NOT_TESTED
    except Exception as exc:
        result.status = TestStatus.INVALID
        result.details = str(exc)[:200]
    return result


async def test_reality_fingerprint(config: ParsedConfig, host: str, port: int) -> TransportTestResult:
    result = TransportTestResult(transport="REALITY")
    if not config.reality:
        result.status = TestStatus.NOT_APPLICABLE
        result.details = "REALITY not enabled in config"
        return result
    result.status = TestStatus.UNSUPPORTED
    result.details = (
        "REALITY authentication cannot be verified with a generic TLS probe — "
        "requires xray-core with configured publicKey/shortId."
    )
    return result


def _resolve_host_header(config: ParsedConfig, connect_host: str) -> str:
    """Host header for HTTP/WS when connecting to IP or domain."""
    if config.host:
        return config.host
    if config.sni:
        return config.sni
    if not is_ip_address(config.address):
        return config.address
    return connect_host


async def test_websocket_with_headers(
    config: ParsedConfig,
    connect_host: str,
    port: int,
    path: str,
    host_header: str,
    sni: Optional[str],
) -> TransportTestResult:
    result = TransportTestResult(transport="WebSocket")
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    scheme = websocket_scheme(config)
    host_header = _resolve_host_header(config, host_header or connect_host)
    tls_sni = sni or host_header

    start = time.perf_counter()
    hs = await probe_websocket_handshake(
        connect_host,
        port,
        path,
        host_header,
        use_tls=(scheme == "wss"),
        tls_sni=tls_sni,
    )
    result.latency_ms = round((time.perf_counter() - start) * 1000, 2)

    if hs.get("handshake_ok"):
        result.status = TestStatus.VALID
        result.details = f"101 OK — Host={host_header}; " + "; ".join(hs.get("checks") or [])
    elif hs.get("status_code") == 101:
        result.status = TestStatus.WARNING
        result.details = (
            f"HTTP 101 but validation incomplete — Host={host_header}; "
            + "; ".join(hs.get("checks") or [])
        )
    elif hs.get("error"):
        result.status = TestStatus.INVALID
        result.details = f"Host={host_header}; {hs['error']}"
    else:
        code = hs.get("status_code")
        checks = "; ".join(hs.get("checks") or [])
        result.status = TestStatus.INVALID
        result.details = f"HTTP {code or '?'} — Host={host_header}; {checks}"

    return result


async def run_transport_tests(config: ParsedConfig, connect_host: str) -> list[TransportTestResult]:
    port = config.port or 443
    sni = config.sni or config.host or config.address
    host_header = _resolve_host_header(config, connect_host)
    tests: list[TransportTestResult] = []

    if config.transport_type == TransportType.GRPC:
        tests.append(await test_grpc(connect_host, port, config.service_name, sni))
    elif config.transport_type == TransportType.QUIC:
        tests.append(await test_quic_probe(connect_host, port))
    elif config.transport_type == TransportType.WS:
        tests.append(await test_websocket_with_headers(
            config, connect_host, port, config.path or "/", host_header, sni,
        ))

    if config.reality:
        tests.append(await test_reality_fingerprint(config, connect_host, port))

    return tests
