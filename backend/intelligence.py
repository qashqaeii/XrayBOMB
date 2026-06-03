"""Threat intelligence and reputation heuristics."""

from __future__ import annotations

import asyncio
import socket

from backend.models import IPIntelligence, ThreatIntel
from utils.logger import get_logger

logger = get_logger(__name__)

DC_KEYWORDS = [
    "datacenter", "hosting", "cloud", "server", "vps", "digitalocean",
    "linode", "vultr", "hetzner", "ovh", "amazon", "google", "microsoft",
    "alibaba", "tencent", "arvan", "cloudflare",
]

RESIDENTIAL_KEYWORDS = ["residential", "broadband", "cable", "dsl", "fiber", "telecom", "mobile"]

# Simple DNSBL-style checks (reverse DNS zone queries)
DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]


def _reverse_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(reversed(parts))
    return ip


def _check_dnsbl(ip: str) -> list[str]:
    hits: list[str] = []
    rev = _reverse_ip(ip)
    for zone in DNSBL_ZONES:
        query = f"{rev}.{zone}"
        try:
            socket.gethostbyname(query)
            hits.append(zone)
        except socket.gaierror:
            pass
        except Exception:
            pass
    return hits


def analyze_threat_intel(ip_intel: IPIntelligence) -> ThreatIntel:
    org = (ip_intel.organization or ip_intel.isp or "").lower()
    intel = ThreatIntel(ip=ip_intel.ip)

    intel.is_datacenter = bool(ip_intel.datacenter) or any(kw in org for kw in DC_KEYWORDS)
    intel.is_residential = any(kw in org for kw in RESIDENTIAL_KEYWORDS) and not intel.is_datacenter

    score = 70
    notes: list[str] = []

    if intel.is_datacenter:
        score -= 5
        notes.append("Datacenter/hosting IP detected")
    if intel.is_residential:
        score += 10
        notes.append("Residential ISP pattern detected")

    if ip_intel.cdn_detected:
        score += 5
        notes.append(f"CDN fronted ({ip_intel.cdn_detected})")

    blocklist = _check_dnsbl(ip_intel.ip)
    intel.blocklist_hits = blocklist
    if blocklist:
        score -= 30
        notes.append(f"Listed on blocklist(s): {', '.join(blocklist)}")
    else:
        notes.append("No major DNSBL hits")

    intel.reputation_score = max(0, min(100, score))
    intel.notes = notes
    return intel


async def analyze_threats(network: list[IPIntelligence]) -> list[ThreatIntel]:
    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, analyze_threat_intel, ip) for ip in network]
    return list(await asyncio.gather(*tasks))
