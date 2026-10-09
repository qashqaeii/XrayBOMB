"""Xray config testing with isolated SOCKS and verified end-to-end checks."""

from __future__ import annotations

import asyncio
import secrets
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.e2e_validity import (
    E2E_PROBE_URL,
    evaluate_e2e_http_contract,
    evaluate_xray_test_result,
    invalidate_proxy_after_process_loss,
)
from backend.models import ParsedConfig, ProtocolType, TestStatus, XrayTestResult
from utils.config_fingerprint import config_fingerprint
from utils.logger import get_logger
from utils.port_allocator import DEFAULT_LOOPBACK, allocate_loopback_port
from utils.socks_client import make_async_socks_client
from xray.manager import XrayBackgroundRun, XrayManager
from xray.proxy_diagnostics import run_all_proxy_diagnostics
from xray.stream_builder import build_stream_settings

logger = get_logger(__name__)

MAX_PORT_START_RETRIES = 3
LOG_LIMIT = 8000


def _build_outbound(config: ParsedConfig) -> Optional[dict]:
    stream = build_stream_settings(config)
    protocol = config.protocol

    if protocol == ProtocolType.VLESS:
        return {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": config.address,
                    "port": config.port,
                    "users": [{
                        "id": config.uuid or "",
                        "encryption": "none",
                        "flow": config.flow or "",
                    }],
                }],
            },
            "streamSettings": stream,
        }

    if protocol == ProtocolType.VMESS:
        return {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": config.address,
                    "port": config.port,
                    "users": [{
                        "id": config.uuid or "",
                        "alterId": 0,
                        "security": config.encryption or "auto",
                    }],
                }],
            },
            "streamSettings": stream,
        }

    if protocol == ProtocolType.TROJAN:
        return {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": config.address,
                    "port": config.port,
                    "password": config.password or "",
                }],
            },
            "streamSettings": stream,
        }

    if protocol == ProtocolType.SHADOWSOCKS:
        return {
            "tag": "proxy",
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": config.address,
                    "port": config.port,
                    "method": config.encryption or "aes-256-gcm",
                    "password": config.password or "",
                }],
            },
        }

    if protocol == ProtocolType.HYSTERIA2:
        return {
            "tag": "proxy",
            "protocol": "hysteria2",
            "settings": {
                "servers": [{
                    "address": config.address,
                    "port": config.port,
                    "password": config.password or "",
                    "sni": config.sni or config.address,
                }],
            },
        }

    if protocol == ProtocolType.TUIC:
        return {
            "tag": "proxy",
            "protocol": "tuic",
            "settings": {
                "servers": [{
                    "address": config.address,
                    "port": config.port,
                    "uuid": config.uuid or "",
                    "password": config.password or "",
                    "sni": config.sni or config.address,
                }],
            },
        }

    return None


async def _test_socks_e2e(
    host: str,
    port: int,
    *,
    username: str,
    password: str,
) -> tuple[TestStatus, Optional[float], bool, str]:
    import time

    start = time.perf_counter()
    try:
        async with make_async_socks_client(
            port, host=host, username=username, password=password, timeout=25,
        ) as client:
            resp = await client.get(E2E_PROBE_URL)
            latency = round((time.perf_counter() - start) * 1000, 2)
            body_len = len(resp.content or b"")
            ok, detail = evaluate_e2e_http_contract(resp.status_code, body_len)
            if ok:
                return TestStatus.VALID, latency, True, f"{detail} ({latency} ms)"
            return TestStatus.INVALID, latency, False, detail
    except Exception as exc:
        return TestStatus.INVALID, None, False, f"Proxy E2E failed: {exc}"[:200]


def _finalize_run(result: XrayTestResult) -> None:
    validity = evaluate_xray_test_result(result)
    result.internet_e2e_verified = validity.internet_verified
    if validity.internet_verified:
        result.status = TestStatus.VALID
    elif result.proxy_test == TestStatus.NOT_TESTED and result.config_validation == TestStatus.VALID:
        result.status = TestStatus.VALID
    elif result.proxy_test != TestStatus.NOT_TESTED and not validity.internet_verified:
        result.status = TestStatus.INVALID


async def test_config_with_xray(
    config: ParsedConfig,
    manager: Optional[XrayManager] = None,
    real_proxy_test: bool = True,
) -> XrayTestResult:
    run_id = uuid.uuid4().hex[:12]
    manager = manager or XrayManager()
    result = XrayTestResult(
        run_id=run_id,
        started_at=datetime.now(timezone.utc),
        config_fingerprint=config_fingerprint(config),
        socks_host=DEFAULT_LOOPBACK,
        proxy_test=TestStatus.NOT_TESTED if not real_proxy_test else TestStatus.PENDING,
    )

    if not manager.is_installed():
        result.status = TestStatus.SKIPPED
        result.summary = "⚠ Xray-core not installed. Use Download Xray in toolbar."
        result.errors.append("Binary not found — click Download Xray to install automatically.")
        return result

    result.xray_version = manager.get_version()
    outbound = _build_outbound(config)
    if not outbound:
        result.status = TestStatus.SKIPPED
        result.summary = f"Protocol {config.protocol.value} not supported for xray test yet."
        return result

    test_host = config.address
    bg_run: Optional[XrayBackgroundRun] = None
    tmpdir_obj = tempfile.TemporaryDirectory()
    socks_user = ""
    socks_pass = ""

    try:
        config_path = Path(tmpdir_obj.name) / "test_config.json"
        val_status = TestStatus.PENDING
        val_detail = ""

        for attempt in range(MAX_PORT_START_RETRIES):
            if bg_run:
                manager.stop_run(bg_run)
                bg_run = None

            socks_port = allocate_loopback_port(DEFAULT_LOOPBACK)
            socks_user = f"run_{run_id[:8]}"
            socks_pass = secrets.token_hex(16)
            result.socks_port = socks_port
            result.socks_auth_user = socks_user

            xray_config = manager.build_temp_config(
                outbound,
                inbound_port=socks_port,
                listen_host=DEFAULT_LOOPBACK,
                socks_user=socks_user,
                socks_pass=socks_pass,
            )
            manager.write_config(xray_config, config_path)

            val_status, val_detail = manager.validate_config_file(config_path)
            result.config_validation = val_status
            result.config_validation_detail = val_detail[:500]
            if val_status == TestStatus.INVALID:
                result.status = TestStatus.INVALID
                result.summary = "Config rejected by xray-core validation"
                result.errors.append(val_detail[:300])
                result.proxy_test = TestStatus.NOT_TESTED
                return result

            if not real_proxy_test:
                break

            bg_run = manager.start_background(
                config_path,
                socks_host=DEFAULT_LOOPBACK,
                socks_port=socks_port,
                socks_user=socks_user,
                socks_pass=socks_pass,
            )
            result.process_pid = bg_run.proc.pid

            ready, ready_msg = await manager.wait_ready(bg_run, deadline_sec=22.0)
            if ready:
                result.socks_handshake_verified = True
                break
            manager.stop_run(bg_run)
            bg_run = None
            if attempt + 1 >= MAX_PORT_START_RETRIES:
                result.status = TestStatus.INVALID
                result.summary = ready_msg
                result.errors.append(ready_msg)
                invalidate_proxy_after_process_loss(result, reason=ready_msg)
                return result

        if not real_proxy_test:
            result.proxy_test = TestStatus.NOT_TESTED
            result.internet_e2e_verified = False
            result.status = TestStatus.VALID if val_status == TestStatus.VALID else TestStatus.INVALID
            result.summary = (
                "Config validated by xray run -test only — no internet/SOCKS E2E; "
                "no claim of successful outbound connectivity."
            )
            _finalize_run(result)
            return result

        assert bg_run is not None
        result.proxy_test, result.proxy_latency_ms, contract_ok, proxy_msg = await _test_socks_e2e(
            DEFAULT_LOOPBACK,
            result.socks_port,
            username=socks_user,
            password=socks_pass,
        )
        result.e2e_contract_ok = contract_ok
        result.e2e_contract_detail = proxy_msg

        if not bg_run.is_alive():
            invalidate_proxy_after_process_loss(result, reason="Xray process exited during E2E test")
            result.status = TestStatus.INVALID
            result.summary = result.errors[-1]
            result.exit_code = bg_run.poll_exit()
            result.log_output = bg_run.filtered_log()
            return result

        if result.proxy_test != TestStatus.VALID or not contract_ok:
            result.status = TestStatus.INVALID
            result.summary = proxy_msg
            result.log_output = bg_run.filtered_log()
            invalidate_proxy_after_process_loss(result, reason=proxy_msg)
            return result

        try:
            sites, speed, leak = await run_all_proxy_diagnostics(
                result.socks_port,
                test_host,
                socks_host=DEFAULT_LOOPBACK,
                socks_user=socks_user,
                socks_pass=socks_pass,
                run_id=run_id,
            )
            result.site_reachability = sites
            result.speed_test = speed
            result.leak_check = leak
            result.exit_ip = leak.proxy_exit_ip
            result.exit_country = leak.proxy_exit_country
        except Exception as exc:
            logger.warning("Proxy diagnostics failed: %s", exc)
            result.errors.append(f"Diagnostics: {exc}")

        result.process_alive_after_e2e = bg_run.is_alive()
        if not result.process_alive_after_e2e:
            invalidate_proxy_after_process_loss(result, reason="Xray exited after diagnostics")
            result.status = TestStatus.INVALID
            result.summary = result.errors[-1]
            result.exit_code = bg_run.poll_exit()
            result.log_output = bg_run.filtered_log()
            return result

        result.internet_e2e_verified = True
        parts = [proxy_msg, "SOCKS per-run auth verified"]
        if result.exit_ip:
            parts.append(f"Exit IP (this run): {result.exit_ip} ({result.exit_country or '?'})")
        if result.speed_test.download_mbps:
            parts.append(
                f"Short download sample: {result.speed_test.download_mbps} Mbps (not sustained throughput)"
            )
        result.summary = " | ".join(parts)
        result.log_output = bg_run.filtered_log()
        _finalize_run(result)

    finally:
        manager.stop_run(bg_run)
        tmpdir_obj.cleanup()

    return result
