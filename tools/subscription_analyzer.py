"""Enhanced subscription analyzer — nodes, DCs, CDNs."""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Callable, Optional

from backend.config_parser import fetch_subscription
from network.cdn_detector import lookup_ip_intelligence
from tools.datacenter_registry import identify_provider
from tools.ip_probe import resolve_host
from utils.helpers import is_ip_address


async def analyze_subscription(
    url: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    url = url.strip()
    if not url:
        return "Enter subscription URL."
    if not url.startswith(("http://", "https://")):
        return "URL must start with http:// or https://"

    if progress:
        progress("Fetching subscription...")
    try:
        configs = await fetch_subscription(url)
    except Exception as exc:
        return f"Subscription Analyzer — FAILED\n\n  Error: {exc}"

    protos: Counter[str] = Counter()
    transports: Counter[str] = Counter()
    countries: Counter[str] = Counter()
    cdns: Counter[str] = Counter()
    dcs: Counter[str] = Counter()
    ports: Counter[int] = Counter()
    reality = tls = ws = grpc = 0
    unique_hosts: set[str] = set()
    unique_ips: set[str] = set()

    for c in configs:
        p = c.protocol.value if hasattr(c.protocol, "value") else str(c.protocol)
        protos[p] += 1
        t = c.transport_type.value if hasattr(c.transport_type, "value") else str(c.transport_type)
        transports[t] += 1
        if c.port:
            ports[c.port] += 1
        if c.reality:
            reality += 1
        if c.tls:
            tls += 1
        if t == "ws":
            ws += 1
        if t == "grpc":
            grpc += 1
        if c.address:
            unique_hosts.add(c.address)
            if is_ip_address(c.address):
                unique_ips.add(c.address)

    # Resolve + classify unique targets (limit for speed)
    hosts_to_probe = list(unique_hosts)[:20]
    for i, host in enumerate(hosts_to_probe):
        if progress:
            progress(f"Analyzing node {i + 1}/{len(hosts_to_probe)}: {host[:40]}...")
        ip = host if is_ip_address(host) else await resolve_host(host)
        if not ip:
            continue
        unique_ips.add(ip)
        try:
            intel = await lookup_ip_intelligence(ip)
            if intel.country_code:
                countries[intel.country_code] += 1
            if intel.cdn_detected and intel.cdn_confidence >= 0.55:
                cdns[intel.cdn_detected] += 1
            providers = identify_provider(asn=intel.asn or "", org=intel.organization or "", isp=intel.isp or "")
            matched = False
            for prov in providers:
                if prov.tunnel_origin or prov.cdn_front:
                    dcs[prov.name] += 1
                    matched = True
                    break
            if not matched and intel.is_datacenter:
                dcs[intel.organization or "Unknown DC"] += 1
        except Exception:
            pass

    lines = [
        "Subscription Analyzer",
        "═" * 58,
        "",
        f"  Nodes parsed : {len(configs)}",
        f"  Unique hosts : {len(unique_hosts)}",
        f"  Unique IPs   : {len(unique_ips)} (sampled {len(hosts_to_probe)})",
        "",
        "── Protocols ──",
    ]
    for proto, cnt in protos.most_common():
        lines.append(f"  {proto:<14} {cnt}")

    lines.extend(["", "── Transports ──"])
    for tr, cnt in transports.most_common():
        lines.append(f"  {tr:<14} {cnt}")

    lines.extend([
        "",
        "── Security ──",
        f"  REALITY : {reality}",
        f"  TLS     : {tls}",
        f"  WS      : {ws}",
        f"  gRPC    : {grpc}",
        "",
        "── Top ports ──",
    ])
    for port, cnt in ports.most_common(8):
        lines.append(f"  {port:<6} {cnt}")

    if countries:
        lines.extend(["", "── Countries (by resolved IP) ──"])
        for cc, cnt in countries.most_common(10):
            lines.append(f"  {cc:<6} {cnt}")

    if dcs:
        lines.extend(["", "── Datacenters / providers ──"])
        for name, cnt in dcs.most_common(10):
            lines.append(f"  {name:<22} {cnt}")

    if cdns:
        lines.extend(["", "── CDNs detected ──"])
        for name, cnt in cdns.most_common():
            lines.append(f"  {name:<16} {cnt}")

    lines.extend([
        "",
        "── Health hints ──",
        f"  REALITY ratio : {reality}/{len(configs)} ({100 * reality // max(len(configs), 1)}%)",
    ])
    if reality < len(configs) * 0.5:
        lines.append("  ⚠ Low REALITY share — consider upgrading nodes for IR filtering")
    if len(unique_hosts) < 3:
        lines.append("  ⚠ Low host diversity — single point of failure risk")

    return "\n".join(lines)


def analyze_subscription_sync(**kwargs) -> str:
    return asyncio.run(analyze_subscription(**kwargs))
