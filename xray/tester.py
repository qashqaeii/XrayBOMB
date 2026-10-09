"""Xray config testing with isolated SOCKS and verified end-to-end checks."""

from __future__ import annotations

import asyncio
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from backend.models import ParsedConfig, ProtocolType, TestStatus, XrayTestResult
from network.geo import lookup_client_geo
from utils.config_fingerprint import config_fingerprint
from utils.logger import get_logger
from utils.port_allocator import DEFAULT_LOOPBACK, allocate_loopback_port
from utils.socks_client import make_async_socks_client
from xray.manager import XrayBackgroundRun, XrayManager
from xray.proxy_diagnostics import run_all_proxy_diagnostics
from xray.stream_builder import build_stream_settings

logger = get_logger(__name__)

E2E_HTTPS_URL = "https://www.gstatic.com/generate_204"
E2E_EXPECTED_STATUSES = frozenset({204, 200})


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


async def _test_socks_e2e(host: str, port: int) -> tuple[TestStatus, Optional[float], str]:
    import time

    start = time.perf_counter()
    try:
        async with make_async_socks_client(port, timeout=25, host=host) as client:
            resp = await client.get(E2E_HTTPS_URL)
            latency = round((time.perf_counter() - start) * 1000, 2)
            if resp.status_code in E2E_EXPECTED_STATUSES:
                return TestStatus.VALID, latency, f"HTTPS E2E OK via SOCKS5 ({latency} ms)"
            return TestStatus.INVALID, latency, f"Unexpected HTTPS status {resp.status_code}"
    except Exception as exc:
        return TestStatus.INVALID, None, f"Proxy E2E failed: {exc}"[:200]


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

    client_geo = await lookup_client_geo()
    client_ip = client_geo.get("ip") if client_geo else None
    test_host = config.address

    bg_run: Optional[XrayBackgroundRun] = None
    tmpdir_obj = tempfile.TemporaryDirectory()
    try:
        config_path = Path(tmpdir_obj.name) / "test_config.json"
        socks_port = allocate_loopback_port(DEFAULT_LOOPBACK)
        result.socks_port = socks_port

        xray_config = manager.build_temp_config(
            outbound,
            inbound_port=socks_port,
            listen_host=DEFAULT_LOOPBACK,
        )
        manager.write_config(xray_config, config_path)

        val_status, val_detail = manager.validate_config_file(config_path)
        result.config_validation = val_status
        result.config_validation_detail = val_detail[:500]
        if val_status == TestStatus.INVALID:
            result.status = TestStatus.INVALID
            result.summary = "Config rejected by xray-core validation"
            result.errors.append(val_detail[:300])
            return result

        if not real_proxy_test:
            code, stdout, stderr = manager.run_test(config_path, timeout=12)
            result.exit_code = code
            result.log_output = (stdout + "\n" + stderr).strip()[:LOG_LIMIT]
            if code == 0:
                result.status = TestStatus.VALID
                result.summary = "xray-core accepted config (non-E2E mode)."
            else:
                result.status = TestStatus.INVALID
                result.summary = f"xray startup failed (exit {code})"
            return result

        bg_run = manager.start_background(
            config_path,
            socks_host=DEFAULT_LOOPBACK,
            socks_port=socks_port,
        )
        result.process_pid = bg_run.proc.pid

        ready, ready_msg = await manager.wait_ready(bg_run, deadline_sec=22.0)
        if not ready:
            result.status = TestStatus.INVALID
            result.summary = ready_msg
            result.log_output = bg_run.filtered_log()
            result.exit_code = bg_run.poll_exit()
            result.errors.append(ready_msg)
            return result

        result.proxy_test, result.proxy_latency_ms, proxy_msg = await _test_socks_e2e(
            DEFAULT_LOOPBACK, socks_port,
        )

        proc_alive = bg_run.is_alive()
        if not proc_alive:
            result.status = TestStatus.INVALID
            result.summary = "Xray process exited during E2E test"
            result.exit_code = bg_run.poll_exit()
            result.log_output = bg_run.filtered_log()
            result.errors.append("Process not alive after proxy test")
            return result

        if result.proxy_test != TestStatus.VALID:
            result.status = TestStatus.INVALID
            result.summary = proxy_msg
            result.log_output = bg_run.filtered_log()
            return result

        try:
            sites, speed, leak = await run_all_proxy_diagnostics(
                socks_port,
                test_host,
                client_ip,
                socks_host=DEFAULT_LOOPBACK,
            )
            result.site_reachability = sites
            result.speed_test = speed
            result.leak_check = leak
            result.exit_ip = leak.proxy_exit_ip
            result.exit_country = leak.proxy_exit_country
        except Exception as exc:
            logger.warning("Proxy diagnostics failed: %s", exc)
            result.errors.append(f"Diagnostics: {exc}")

        if not bg_run.is_alive():
            result.status = TestStatus.INVALID
            result.summary = "Xray exited after diagnostics"
            result.exit_code = bg_run.poll_exit()
            return result

        result.status = TestStatus.VALID
        parts = [proxy_msg, ready_msg]
        if result.exit_ip:
            parts.append(f"Exit IP: {result.exit_ip} ({result.exit_country or '?'})")
        if result.speed_test.download_mbps:
            parts.append(f"Short download estimate: {result.speed_test.download_mbps} Mbps (not sustained speed)")
        ok_sites = [s.name for s in result.site_reachability if s.status == TestStatus.VALID]
        if ok_sites:
            parts.append(f"Reachability probes: {', '.join(ok_sites[:4])}")
        result.summary = " | ".join(parts)
        result.log_output = bg_run.filtered_log()

    finally:
        manager.stop_run(bg_run)
        tmpdir_obj.cleanup()

    return result


LOG_LIMIT = 8000
