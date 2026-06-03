"""Xray config testing with real SOCKS proxy validation."""



from __future__ import annotations



import asyncio

import tempfile

from pathlib import Path

from typing import Optional



from backend.models import ParsedConfig, ProtocolType, TestStatus, XrayTestResult

from network.geo import lookup_client_geo

from utils.socks_client import make_async_socks_client

from xray.manager import XrayManager

from xray.proxy_diagnostics import run_all_proxy_diagnostics

from xray.stream_builder import build_stream_settings

from utils.logger import get_logger



logger = get_logger(__name__)



SOCKS_PORT = 10808





def _build_outbound(config: ParsedConfig) -> Optional[dict]:

    """Convert ParsedConfig to xray outbound."""

    stream = build_stream_settings(config)

    protocol = config.protocol



    if protocol == ProtocolType.VLESS:

        return {

            "tag": "proxy", "protocol": "vless",

            "settings": {"vnext": [{"address": config.address, "port": config.port,

                "users": [{"id": config.uuid or "", "encryption": "none", "flow": config.flow or ""}]}]},

            "streamSettings": stream,

        }



    if protocol == ProtocolType.VMESS:

        return {

            "tag": "proxy", "protocol": "vmess",

            "settings": {"vnext": [{"address": config.address, "port": config.port,

                "users": [{"id": config.uuid or "", "alterId": 0, "security": config.encryption or "auto"}]}]},

            "streamSettings": stream,

        }



    if protocol == ProtocolType.TROJAN:

        return {

            "tag": "proxy", "protocol": "trojan",

            "settings": {"servers": [{"address": config.address, "port": config.port, "password": config.password or ""}]},

            "streamSettings": stream,

        }



    if protocol == ProtocolType.SHADOWSOCKS:

        return {

            "tag": "proxy", "protocol": "shadowsocks",

            "settings": {"servers": [{"address": config.address, "port": config.port,

                "method": config.encryption or "aes-256-gcm", "password": config.password or ""}]},

        }



    if protocol == ProtocolType.HYSTERIA2:

        return {

            "tag": "proxy", "protocol": "hysteria2",

            "settings": {"servers": [{

                "address": config.address, "port": config.port,

                "password": config.password or "",

                "sni": config.sni or config.address,

            }]},

        }



    if protocol == ProtocolType.TUIC:

        return {

            "tag": "proxy", "protocol": "tuic",

            "settings": {"servers": [{

                "address": config.address, "port": config.port,

                "uuid": config.uuid or "",

                "password": config.password or "",

                "sni": config.sni or config.address,

            }]},

        }



    return None





async def _test_socks_proxy(port: int = SOCKS_PORT) -> tuple[TestStatus, Optional[float], str]:

    import time

    start = time.perf_counter()

    try:

        async with make_async_socks_client(port, timeout=20) as client:

            resp = await client.get("http://www.gstatic.com/generate_204")

            latency = round((time.perf_counter() - start) * 1000, 2)

            if resp.status_code in (204, 200):

                return TestStatus.VALID, latency, f"Proxy OK via SOCKS5 ({latency} ms)"

            return TestStatus.WARNING, latency, f"Unexpected status {resp.status_code}"

    except Exception as exc:

        return TestStatus.INVALID, None, f"Proxy test failed: {exc}"[:200]





async def test_config_with_xray(

    config: ParsedConfig,

    manager: Optional[XrayManager] = None,

    real_proxy_test: bool = True,

) -> XrayTestResult:

    """Test config using xray-core with proxy diagnostics."""

    result = XrayTestResult(socks_port=SOCKS_PORT)

    manager = manager or XrayManager()



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

    test_host = config.sni or config.address



    proc = None

    with tempfile.TemporaryDirectory() as tmpdir:

        config_path = Path(tmpdir) / "test_config.json"

        xray_config = manager.build_temp_config(outbound, inbound_port=SOCKS_PORT)

        manager.write_config(xray_config, config_path)



        if real_proxy_test:

            proc = manager.start_background(config_path)

            await asyncio.sleep(3)

            result.proxy_test, result.proxy_latency_ms, proxy_msg = await _test_socks_proxy(SOCKS_PORT)



            if result.proxy_test in (TestStatus.VALID, TestStatus.WARNING):

                try:

                    sites, speed, leak = await run_all_proxy_diagnostics(

                        SOCKS_PORT, test_host, client_ip,

                    )

                    result.site_reachability = sites

                    result.speed_test = speed

                    result.leak_check = leak

                    result.exit_ip = leak.proxy_exit_ip

                    result.exit_country = leak.proxy_exit_country

                except Exception as exc:

                    logger.warning("Proxy diagnostics failed: %s", exc)

                    result.errors.append(f"Diagnostics: {exc}")



            try:

                import psutil

                from psutil import NoSuchProcess

                proc_alive = False

                if proc:

                    try:

                        proc_alive = psutil.Process(proc.pid).is_running()

                    except NoSuchProcess:

                        proc_alive = proc.poll() is None

                if proc_alive or result.proxy_test in (TestStatus.VALID, TestStatus.WARNING):

                    result.status = (

                        TestStatus.VALID if result.proxy_test == TestStatus.VALID else TestStatus.WARNING

                    )

                    parts = [proxy_msg]

                    if result.exit_ip:

                        parts.append(f"Exit IP: {result.exit_ip} ({result.exit_country or '?'})")

                    if result.speed_test.download_mbps:

                        parts.append(f"Speed: {result.speed_test.download_mbps} Mbps")

                    ok_sites = [s.name for s in result.site_reachability if s.status == TestStatus.VALID]

                    if ok_sites:

                        parts.append(f"Sites OK: {', '.join(ok_sites)}")

                    result.summary = " | ".join(parts)

                elif proc:

                    stderr = proc.stderr.read() if proc.stderr else ""

                    result.status = TestStatus.INVALID

                    result.summary = "Xray process exited unexpectedly"

                    result.log_output = stderr or ""

            except ImportError:

                result.status = TestStatus.VALID if result.proxy_test == TestStatus.VALID else TestStatus.WARNING

                result.summary = proxy_msg



            if proc:

                manager.stop_process(proc)

        else:

            code, stdout, stderr = manager.run_test(config_path, timeout=12)

            log = (stdout + "\n" + stderr).strip()

            result.log_output = log

            log_lower = log.lower()

            if "failed" in log_lower or "error" in log_lower:

                result.status = TestStatus.WARNING if "started" in log_lower else TestStatus.INVALID

                result.summary = "Xray started with warnings." if result.status == TestStatus.WARNING else "Xray failed to start."

            else:

                result.status = TestStatus.VALID

                result.summary = "Xray-core accepted the config and started successfully."



    return result


