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
from network.http_probe import classify_http_baseline_status, probe_http_baseline, probe_http_fingerprint
from network.latency_benchmark import benchmark_tcp_latency
from network.transport_security import http_scheme, uses_tls_layer, websocket_scheme
from network.transport_tests import run_transport_tests
from utils.helpers import is_ip_address
from utils.logger import get_logger

logger = get_logger(__name__)


async def test_dns_resolve(hostname: str) -> tuple[TestStatus, Optional[float]]:
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
    *,
    verify: bool = False,
) -> tuple[TestStatus, Optional[float]]:
    sni = sni or host
    start = time.perf_counter()
    try:
        ctx = ssl.create_default_context()
        if verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
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


async def test_websocket_upgrade(config: ParsedConfig, connect_host: str, port: int, path: str) -> TestStatus:
    path = path or "/"
    if not path.startswith("/"):
        path = "/" + path
    scheme = websocket_scheme(config)
    host_header = config.host or config.sni or connect_host
    sni = config.sni or host_header
    url = f"{scheme}://{connect_host}:{port}{path}"

    def _ws_test() -> bool:
        try:
            sslopt = None
            if scheme == "wss":
                sslopt = {"cert_reqs": ssl.CERT_NONE, "server_hostname": sni}
            ws = websocket.create_connection(
                url,
                timeout=10,
                host=host_header,
                header={"Host": host_header},
                sslopt=sslopt,
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


async def test_http_response(
    config: ParsedConfig,
    connect_host: str,
    port: int,
    sni: Optional[str] = None,
) -> tuple[TestStatus, Optional[int], str, dict]:
    host_header = config.host or sni or connect_host
    path = config.path or "/"
    use_tls = uses_tls_layer(config)
    baseline = await probe_http_baseline(
        connect_host,
        port,
        path,
        host_header,
        use_tls=use_tls,
        tls_sni=sni or host_header,
    )
    if baseline.get("error"):
        return TestStatus.INVALID, None, baseline["error"], baseline
    code = baseline.get("status_code")
    label, note = classify_http_baseline_status(code, baseline.get("headers") or {})
    status_map = {
        "Valid": TestStatus.VALID,
        "Warning": TestStatus.WARNING,
        "Invalid": TestStatus.INVALID,
    }
    return status_map.get(label, TestStatus.INVALID), code, note, baseline


async def test_tcp_connection_failure_rate(host: str, port: int, count: int = 4) -> Optional[float]:
    successes = 0
    for _ in range(count):
        status, _ = await test_tcp_connect(host, port, timeout=5)
        if status == TestStatus.VALID:
            successes += 1
    return round(((count - successes) / count) * 100, 1)


async def run_connectivity_tests(
    config: ParsedConfig,
    *,
    connect_host: Optional[str] = None,
    resolved_ips: Optional[list[str]] = None,
) -> ConnectivityResult:
    result = ConnectivityResult()
    host = config.address
    port = config.port or 443
    tls_sni = config.sni or config.host or host

    result.dns_resolve, result.dns_latency_ms = await test_dns_resolve(host)
    if result.dns_resolve == TestStatus.INVALID:
        result.errors.append("DNS resolution failed for connect address")

    if connect_host:
        tcp_target = connect_host
    elif not is_ip_address(host) and result.dns_resolve == TestStatus.VALID:
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(host, port)
            tcp_target = infos[0][4][0]
        except Exception:
            tcp_target = host
    else:
        tcp_target = host

    if resolved_ips and len(resolved_ips) > 1:
        result.errors.append(f"Multiple connect IPs: {', '.join(resolved_ips[:6])}")

    result.tcp_connect, result.tcp_latency_ms = await test_tcp_connect(tcp_target, port)
    if result.tcp_connect == TestStatus.INVALID:
        result.errors.append("TCP connection failed")

    if uses_tls_layer(config) or port == 443:
        result.tls_handshake, result.tls_latency_ms = await test_tls_handshake(
            tcp_target, port, tls_sni, verify=False,
        )
        if result.tls_handshake == TestStatus.INVALID:
            result.errors.append("TLS handshake probe failed (unverified probe mode)")

    transport_tests = await run_transport_tests(config, tcp_target)
    result.transport_tests = transport_tests

    ws_from_transport = next((t for t in transport_tests if t.transport == "WebSocket"), None)
    if config.transport_type == TransportType.WS:
        if ws_from_transport:
            result.websocket_upgrade = ws_from_transport.status
            result.websocket_upgrade_note = ws_from_transport.details
            if "101 OK" in ws_from_transport.details or ws_from_transport.status == TestStatus.VALID:
                result.websocket_handshake_validated = True
                result.websocket_handshake_status_code = 101
                result.websocket_handshake_checks = [
                    p.strip() for p in ws_from_transport.details.split(";") if p.strip()
                ]
        else:
            result.websocket_upgrade = await test_websocket_upgrade(config, tcp_target, port, config.path or "/")
            if result.websocket_upgrade == TestStatus.INVALID:
                result.websocket_upgrade_note = (
                    "External WS probe failed — may differ from xray-core parameters; "
                    "check end-to-end xray test."
                )
    else:
        result.websocket_upgrade = TestStatus.NOT_APPLICABLE

    for tt in transport_tests:
        if tt.transport == "gRPC":
            result.grpc_test = tt.status
        elif tt.transport == "QUIC":
            result.quic_test = tt.status
        elif tt.transport == "REALITY":
            result.reality_test = tt.status

    if tcp_target and result.tcp_connect == TestStatus.VALID:
        result.latency_benchmark = await benchmark_tcp_latency(tcp_target, port)

    http_status, code, http_note, baseline = await test_http_response(config, tcp_target, port, tls_sni)
    result.http_response = http_status
    result.http_status_code = code
    result.http_response_note = http_note
    result.http_baseline_status = http_status
    result.http_baseline_status_code = code
    result.http_baseline_note = http_note
    result.http_baseline_latency_ms = baseline.get("latency_ms")
    result.http_baseline_headers = baseline.get("headers") or {}
    if baseline.get("http_server") and not result.http_server_header:
        result.http_server_header = baseline.get("http_server")
    if baseline.get("cdn_detected") and not result.http_cdn_detected:
        result.http_cdn_detected = baseline.get("cdn_detected")
    if baseline.get("reverse_proxy_server") and not result.http_reverse_proxy:
        result.http_reverse_proxy = baseline.get("reverse_proxy_server")

    if not is_ip_address(host):
        fp = await probe_http_fingerprint(
            host, port, config.path or "/", sni=tls_sni or host,
        )
        result.http_probe_url = fp.get("url")
        result.http_server_header = fp.get("http_server")
        result.http_cdn_detected = fp.get("cdn_detected")
        result.http_panel_detected = fp.get("panel_detected")
        result.http_reverse_proxy = fp.get("reverse_proxy_server")
        result.http_probe_headers = fp.get("headers") or {}
        if fp.get("status_code") and result.http_response == TestStatus.PENDING:
            sc = fp["status_code"]
            result.http_response = TestStatus.VALID if sc < 500 else TestStatus.WARNING
            result.http_status_code = sc

    latencies = [v for v in [result.dns_latency_ms, result.tcp_latency_ms, result.tls_latency_ms] if v is not None]
    if latencies:
        result.latency_ms = round(sum(latencies), 2)

    failure_rate = await test_tcp_connection_failure_rate(tcp_target, port)
    result.tcp_connection_failure_rate = failure_rate
    result.packet_loss_percent = failure_rate

    return result
