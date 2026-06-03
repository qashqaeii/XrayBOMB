"""Main configuration analyzer orchestrator."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.cert_transparency import lookup_cert_transparency
from backend.cloud_sync import sync_upload
from backend.config_parser import parse_input
from backend.config_validator import validate_config
from backend.deployment_guide import build_deployment_setup_guide
from backend.intelligence import analyze_threats
from backend.tunnel_detection import analyze_tunnels
from backend.models import (
    AnalysisResult,
    BatchAnalysisResult,
    CertTransparencyResult,
    ParsedConfig,
    TestStatus,
    TracerouteResult,
    XrayTestResult,
)
from backend.plugins import get_plugin_manager
from backend.security import (
    analyze_deployment,
    analyze_security,
    apply_traceroute_to_deployment,
    build_reproduction_guide,
)
from dns_analyzer.resolver import analyze_dns
from network.cdn_detector import lookup_ip_intelligence
from network.connectivity import run_connectivity_tests
from network.traceroute import run_traceroute
from network.tunnel import build_tunnel_route
from tls.analyzer import analyze_tls
from xray.manager import XrayManager
from xray.tester import test_config_with_xray
from utils.helpers import is_ip_address
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)

STAGES = [
    "Validate", "DNS", "Network", "Tunnel", "Connectivity",
    "TLS", "Traceroute", "Threat Intel", "Cert Transparency",
    "Deployment", "Security", "Reproduction", "Xray Test", "Plugins",
]

# Max configs analyzed concurrently in batch mode
BATCH_PARALLEL_LIMIT = 4


class ConfigAnalyzer:
    """Orchestrates full config analysis pipeline."""

    def __init__(self, run_xray_test: Optional[bool] = None) -> None:
        settings = get_settings()
        self.run_xray_test = run_xray_test if run_xray_test is not None else settings.run_xray_test

    async def _lookup_network(self, ips: list[str], reverse_dns: dict) -> list:
        if not ips:
            return []
        return list(await asyncio.gather(*[
            lookup_ip_intelligence(ip, reverse_dns) for ip in ips
        ]))

    async def _run_traceroute(self, config: ParsedConfig, connect_host: str) -> TracerouteResult:
        settings = get_settings()
        if not settings.enable_traceroute:
            return TracerouteResult()
        target = config.address if not is_ip_address(config.address) else connect_host
        if not target:
            return TracerouteResult()
        try:
            return await asyncio.wait_for(run_traceroute(target, max_hops=12), timeout=18.0)
        except asyncio.TimeoutError:
            return TracerouteResult(errors=["Traceroute capped at 18s"])

    async def _run_cert_ct(self, config: ParsedConfig) -> CertTransparencyResult:
        settings = get_settings()
        if not settings.enable_cert_transparency:
            return CertTransparencyResult()
        domain = config.sni or (config.address if not is_ip_address(config.address) else "")
        if domain:
            return await lookup_cert_transparency(domain)
        return CertTransparencyResult()

    async def _run_threat_intel(self, network_results: list) -> list:
        settings = get_settings()
        if not settings.enable_threat_intel or not network_results:
            return []
        threat_intel = await analyze_threats(network_results)
        for ip_intel, threat in zip(network_results, threat_intel):
            ip_intel.reputation_score = threat.reputation_score
            ip_intel.is_datacenter = threat.is_datacenter
            ip_intel.is_residential = threat.is_residential
        return threat_intel

    async def analyze(
        self,
        config: ParsedConfig,
        progress_callback: Optional[Callable[[str], None]] = None,
        stage_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> AnalysisResult:
        settings = get_settings()
        total = len(STAGES)

        def log(msg: str) -> None:
            logger.info(msg)
            if progress_callback:
                progress_callback(msg)

        def stage(idx: int, name: str) -> None:
            if stage_callback:
                stage_callback(idx, total, name)
            log(f"[{idx}/{total}] {name}...")

        stage(1, "Validate")
        validation = validate_config(config)
        log(f"Analyzing {config.protocol.value} → {config.address}:{config.port}")

        stage(2, "DNS")
        dns_host = config.sni or config.address
        dns_result = await analyze_dns(dns_host)
        ips = dns_result.all_resolved_ips or ([config.address] if is_ip_address(config.address) else [])
        connect_host = ips[0] if ips else config.address

        # Parallel I/O: network lookups, connectivity, TLS, traceroute, cert transparency
        stage(3, "Network + Connectivity + TLS")
        log("Running network, connectivity, TLS, traceroute, and CT in parallel...")
        (
            network_results,
            connectivity,
            tls_result,
            traceroute,
            cert_ct,
        ) = await asyncio.gather(
            self._lookup_network(ips[:5], dns_result.reverse_dns),
            run_connectivity_tests(config),
            analyze_tls(config, connect_host),
            self._run_traceroute(config, connect_host),
            self._run_cert_ct(config),
        )
        log(f"Network: {len(network_results)} IP(s) | Connectivity: {connectivity.tcp_connect.value}")

        # Parallel: tunnel route + threat intel
        stage(4, "Tunnel + Threat Intel")
        tunnel, threat_intel = await asyncio.gather(
            build_tunnel_route(network_results),
            self._run_threat_intel(network_results),
        )

        stage(10, "Deployment")
        deployment = analyze_deployment(config, dns_result, network_results, connectivity)
        deployment = apply_traceroute_to_deployment(deployment, traceroute.hop_count)

        stage(11, "Security")
        security = analyze_security(config, tls_result, connectivity, network_results)

        stage(12, "Reproduction")
        reproduction = build_reproduction_guide(config)

        stage(13, "Xray Test")
        xray_manager = XrayManager()
        xray_installed = xray_manager.is_installed()
        if self.run_xray_test and xray_installed:
            xray_result = await test_config_with_xray(
                config, xray_manager, real_proxy_test=settings.real_proxy_test,
            )
        else:
            if self.run_xray_test and not xray_installed:
                log("Xray-core not installed — skipping live test.")
            xray_result = XrayTestResult(
                status=TestStatus.SKIPPED,
                summary="⚠ Xray-core not installed. Use Download Xray in toolbar.",
                errors=["Xray-core binary not found in ~/.xray_analyzer/xray/"],
            )

        tunnel_analysis = analyze_tunnels(
            config, dns_result, network_results, connectivity,
            deployment, traceroute, tunnel,
        )
        setup_guide = build_deployment_setup_guide(
            config, deployment, tls_result, dns_result, network_results,
            connectivity, tunnel, traceroute, xray_result, tunnel_analysis,
        )

        result = AnalysisResult(
            config=config,
            validation=validation,
            dns=dns_result,
            network=network_results,
            connectivity=connectivity,
            tls=tls_result,
            deployment=deployment,
            security=security,
            reproduction=reproduction,
            setup_guide=setup_guide,
            xray_test=xray_result,
            tunnel=tunnel,
            tunnel_analysis=tunnel_analysis,
            traceroute=traceroute,
            threat_intel=threat_intel,
            cert_transparency=cert_ct,
            xray_installed=xray_installed,
            raw_data={},
        )

        stage(14, "Plugins")
        result = get_plugin_manager().run_hooks(result, config)
        plugin_data = dict(result.raw_data.get("plugins", {}))

        result.raw_data = {
            "config_dict": config.model_dump(),
            "validation": validation.model_dump(),
            "dns": dns_result.model_dump(),
            "network": [n.model_dump() for n in network_results],
            "connectivity": connectivity.model_dump(),
            "tls": tls_result.model_dump(mode="json"),
            "deployment": deployment.model_dump(),
            "security": security.model_dump(),
            "reproduction": reproduction.model_dump(),
            "setup_guide": setup_guide.model_dump(),
            "xray_test": xray_result.model_dump(),
            "tunnel": tunnel.model_dump(),
            "tunnel_analysis": tunnel_analysis.model_dump(),
            "traceroute": traceroute.model_dump(),
            "threat_intel": [t.model_dump() for t in threat_intel],
            "cert_transparency": cert_ct.model_dump(),
            "xray_installed": xray_installed,
        }
        if plugin_data:
            result.raw_data["plugins"] = plugin_data

        if settings.cloud_sync_url:
            await sync_upload(result)

        log("Analysis complete.")
        return result

    async def analyze_text(
        self,
        text: str,
        progress_callback: Optional[Callable[[str], None]] = None,
        stage_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> BatchAnalysisResult:
        """Parse and analyze text input (supports multiple configs)."""
        configs = parse_input(text)
        if not configs:
            raise ValueError("No valid configuration found in input.")
        batch = BatchAnalysisResult(total=len(configs))

        if len(configs) == 1:
            try:
                batch.results.append(
                    await self.analyze(configs[0], progress_callback, stage_callback)
                )
            except Exception as exc:
                batch.errors.append(f"Config 1: {exc}")
            return batch

        log = progress_callback
        if log:
            log(f"Batch mode: analyzing {len(configs)} configs (up to {BATCH_PARALLEL_LIMIT} parallel)...")

        sem = asyncio.Semaphore(BATCH_PARALLEL_LIMIT)

        async def run_one(index: int, cfg: ParsedConfig) -> AnalysisResult:
            async with sem:
                if log:
                    log(f"Starting config {index + 1}/{len(configs)}: {cfg.protocol.value} {cfg.address}:{cfg.port}")
                return await self.analyze(cfg, progress_callback, None)

        outcomes = await asyncio.gather(
            *[run_one(i, cfg) for i, cfg in enumerate(configs)],
            return_exceptions=True,
        )
        for i, outcome in enumerate(outcomes):
            if isinstance(outcome, Exception):
                batch.errors.append(f"Config {i + 1}: {outcome}")
            else:
                batch.results.append(outcome)
                if log:
                    log(f"Finished config {i + 1}/{len(configs)} — score {outcome.security.score}/100")
        return batch

    def analyze_sync(
        self,
        text: str,
        progress_callback=None,
        stage_callback=None,
    ) -> BatchAnalysisResult:
        """Synchronous wrapper for GUI threading."""
        return asyncio.run(self.analyze_text(text, progress_callback, stage_callback))
