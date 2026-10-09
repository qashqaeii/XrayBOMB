"""Transport-specific connectivity probes (external — not Xray-core handshake)."""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Optional

import httpx

from backend.models import ParsedConfig, TestStatus, TransportTestResult, TransportType
from network.transport_security import uses_tls_layer, websocket_scheme
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


async def test_websocket_with_headers(
    config: ParsedConfig,
    connect_host: str,
    port: int,
    path: str,
    host_header: str,
    sni: Optional[str],
) -> TransportTestResult:
    import websocket

    result = TransportTestResult(transport="WebSocket")
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    scheme = websocket_scheme(config)
    url = f"{scheme}://{connect_host}:{port}{path}"
    tls_sni = sni or host_header or connect_host

    def _ws() -> tuple[bool, str]:
        try:
            sslopt = None
            if scheme == "wss":
                sslopt = {"cert_reqs": ssl.CERT_NONE, "server_hostname": tls_sni}
            ws = websocket.create_connection(
                url,
                timeout=12,
                host=tls_sni if scheme == "wss" else connect_host,
                header={"Host": host_header, "User-Agent": "Mozilla/5.0"},
                sslopt=sslopt,
            )
            ws.close()
            return True, f"WebSocket upgrade OK ({scheme}, SNI={tls_sni}, Host={host_header})"
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
    host_header = config.host or config.sni or connect_host
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
