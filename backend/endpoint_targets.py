"""Separate DNS/connect targets: address vs SNI vs HTTP Host."""

from __future__ import annotations

import asyncio
from typing import Optional

from pydantic import BaseModel, Field

from backend.models import DNSAnalysis, ParsedConfig
from dns_analyzer.resolver import analyze_dns
from utils.helpers import is_ip_address


class EndpointTargets(BaseModel):
    connect_address: str = ""
    connect_port: int = 443
    tls_sni: Optional[str] = None
    http_host: Optional[str] = None
    dns_connect: DNSAnalysis = Field(default_factory=DNSAnalysis)
    dns_sni: Optional[DNSAnalysis] = None
    dns_host: Optional[DNSAnalysis] = None
    resolved_connect_ips: list[str] = Field(default_factory=list)
    primary_connect_ip: Optional[str] = None


def _host_for_dns(host: str) -> Optional[str]:
    if not host or is_ip_address(host):
        return None
    return host


async def resolve_endpoint_targets(config: ParsedConfig) -> EndpointTargets:
    connect_address = config.address
    port = config.port or 443
    tls_sni = config.sni or None
    http_host = config.host or config.sni or None

    connect_host_dns = _host_for_dns(connect_address)
    sni_host = _host_for_dns(tls_sni) if tls_sni else None
    host_header_dns = _host_for_dns(http_host) if http_host else None

    tasks: list = []
    labels: list[str] = []
    if connect_host_dns:
        tasks.append(analyze_dns(connect_host_dns))
        labels.append("connect")
    if sni_host and sni_host != connect_host_dns:
        tasks.append(analyze_dns(sni_host))
        labels.append("sni")
    elif sni_host:
        labels.append("sni_same")

    if host_header_dns and host_header_dns not in (connect_host_dns, sni_host):
        tasks.append(analyze_dns(host_header_dns))
        labels.append("host")

    dns_results: dict[str, DNSAnalysis] = {}
    if tasks:
        resolved = await asyncio.gather(*tasks)
        idx = 0
        for label in labels:
            if label == "sni_same":
                continue
            dns_results[label] = resolved[idx]
            idx += 1

    dns_connect = dns_results.get("connect") or DNSAnalysis(hostname=connect_host_dns or connect_address)
    dns_sni = dns_results.get("sni")
    if "sni_same" in labels and connect_host_dns:
        dns_sni = dns_connect

    dns_host_analysis = dns_results.get("host")

    if is_ip_address(connect_address):
        resolved_ips = [connect_address]
    else:
        resolved_ips = list(dns_connect.all_resolved_ips or dns_connect.a_records or [])

    primary_ip = resolved_ips[0] if resolved_ips else (connect_address if is_ip_address(connect_address) else None)

    return EndpointTargets(
        connect_address=connect_address,
        connect_port=port,
        tls_sni=tls_sni,
        http_host=http_host,
        dns_connect=dns_connect,
        dns_sni=dns_sni,
        dns_host=dns_host_analysis,
        resolved_connect_ips=resolved_ips,
        primary_connect_ip=primary_ip,
    )
