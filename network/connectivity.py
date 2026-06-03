"""Network connectivity testing."""

from __future__ import annotations

import asyncio
import socket
import ssl
import time
from typing import Optional

import httpx
import websocket

from backend.models import ConnectivityResult, ParsedConfig, TestStatus, TransportType
from network.latency_benchmark import benchmark_tcp_latency
from network.transport_tests import run_transport_tests
from utils.helpers import is_ip_address
from utils.logger import get_logger

logger = get_logger(__name__)


async def test_dns_resolve(hostname: str) -> tuple[TestStatus, Optional[float]]:
    """Test DNS resolution latency."""
    if is_ip_address(hostname):
        return TestStatus.VALID, 0.0
    start = time.perf_counter()
    try:
        loop = asyncio.get_event_loop()
        await loop.getaddrinfo(hostname, None)
        latency = (time.perf_counter() - start) * 1000
        return TestStatus.VALID, round(latency, 2)
    except socket.gaierror as exc:
        logger.debug("DNS resolve failed: %s", exc)
        return TestStatus.INVALID, None


async def test_tcp_connect(host: str, port: int, timeout: float = 10) -> tuple[TestStatus, Optional[float]]:
    """Test TCP connection."""
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        latency = (time.perf_counter() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return TestStatus.VALID, round(latency, 2)
    except Exception as exc:
        logger.debug("TCP connect failed: %s", exc)
        return TestStatus.INVALID, None


async def test_tls_handshake(
    host: str,
    port: int,
    sni: Optional[str] = None,
    timeout: float = 10,
) -> tuple[TestStatus, Optional[float]]:
    """Test TLS handshake."""
    sni = sni or host
    start = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        loop = asyncio.get_event_loop()

        def _handshake() -> None:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                    ssock.do_handshake()

        await loop.run_in_executor(None, _handshake)
        latency = (time.perf_counter() - start) * 1000
        return TestStatus.VALID, round(latency, 2)
    except Exception as exc:
        logger.debug("TLS handshake failed: %s", exc)
        return TestStatus.INVALID, None


async def test_websocket_upgrade(host: str, port: int, path: str, sni: Optional[str] = None) -> TestStatus:
    """Test WebSocket upgrade."""
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    scheme = "wss" if port == 443 else "ws"
    url = f"{scheme}://{host}:{port}{path}"

    def _ws_test() -> bool:
        try:
            ws = websocket.create_connection(
                url,
                timeout=10,
                header={"Host": sni or host},
                sslopt={"cert_reqs": ssl.CERT_NONE},
            )
            ws.close()
            return True
        except Exception:
            return False

    try:
        loop = asyncio.get_event_loop()
        ok = await loop.run_in_executor(None, _ws_test)
        return TestStatus.VALID if ok else TestStatus.INVALID
    except Exception:
        return TestStatus.INVALID


async def test_http_response(host: str, port: int, sni: Optional[str] = None) -> tuple[TestStatus, Optional[int]]:
    """Test HTTP/HTTPS response."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            headers = {"Host": sni} if sni else {}
            response = await client.get(url, headers=headers)
            if response.status_code < 500:
                return TestStatus.VALID, response.status_code
            return TestStatus.WARNING, response.status_code
    except Exception as exc:
        logger.debug("HTTP test failed: %s", exc)
        return TestStatus.INVALID, None


async def test_packet_loss(host: str, port: int, count: int = 4) -> Optional[float]:
    """Estimate packet loss via repeated TCP connect attempts."""
    successes = 0
    for _ in range(count):
        status, _ = await test_tcp_connect(host, port, timeout=5)
        if status == TestStatus.VALID:
            successes += 1
    loss = ((count - successes) / count) * 100
    return round(loss, 1)


async def run_connectivity_tests(config: ParsedConfig) -> ConnectivityResult:
    """Run all connectivity tests for a config."""
    result = ConnectivityResult()
    host = config.address
    port = config.port or 443
    sni = config.sni or config.host or host

    result.dns_resolve, result.dns_latency_ms = await test_dns_resolve(host)
    if result.dns_resolve == TestStatus.INVALID:
        result.errors.append("DNS resolution failed")

    connect_host = host
    if not is_ip_address(host) and result.dns_resolve == TestStatus.VALID:
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(host, port)
            connect_host = infos[0][4][0]
        except Exception:
            pass

    result.tcp_connect, result.tcp_latency_ms = await test_tcp_connect(connect_host, port)
    if result.tcp_connect == TestStatus.INVALID:
        result.errors.append("TCP connection failed")

    if config.tls or config.reality or port == 443:
        result.tls_handshake, result.tls_latency_ms = await test_tls_handshake(connect_host, port, sni)
        if result.tls_handshake == TestStatus.INVALID:
            result.errors.append("TLS handshake failed")

    if config.transport_type == TransportType.WS:
        result.websocket_upgrade = await test_websocket_upgrade(host, port, config.path or "/", sni)
        if result.websocket_upgrade == TestStatus.INVALID:
            result.errors.append("WebSocket upgrade failed")
    else:
        result.websocket_upgrade = TestStatus.SKIPPED

    transport_tests = await run_transport_tests(config, connect_host)
    result.transport_tests = transport_tests
    for tt in transport_tests:
        if tt.transport == "gRPC":
            result.grpc_test = tt.status
        elif tt.transport == "QUIC":
            result.quic_test = tt.status
        elif tt.transport == "REALITY":
            result.reality_test = tt.status
        elif tt.transport == "WebSocket":
            result.websocket_upgrade = tt.status

    if connect_host and result.tcp_connect == TestStatus.VALID:
        result.latency_benchmark = await benchmark_tcp_latency(connect_host, port)

    result.http_response, result.http_status_code = await test_http_response(connect_host, port, sni)

    latencies = [v for v in [result.dns_latency_ms, result.tcp_latency_ms, result.tls_latency_ms] if v is not None]
    if latencies:
        result.latency_ms = round(sum(latencies), 2)

    result.packet_loss_percent = await test_packet_loss(connect_host, port)

    return result
