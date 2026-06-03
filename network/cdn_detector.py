"""Network intelligence and CDN detection."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Optional

from backend.models import IPIntelligence
from network.geo import lookup_geo_ip
from utils.country import country_flag
from utils.logger import get_logger

logger = get_logger(__name__)

# Known CDN IP ranges and ASN patterns (heuristic)
CDN_SIGNATURES: dict[str, dict] = {
    "Cloudflare": {
        "asns": ["AS13335", "13335"],
        "org_keywords": ["cloudflare", "cloudflarenet"],
        "cname_keywords": ["cloudflare"],
    },
    "ArvanCloud": {
        "asns": ["AS202468", "202468", "AS50810"],
        "org_keywords": ["arvan", "arvancloud", "afranet"],
        "cname_keywords": ["arvan", "arvancloud"],
    },
    "Akamai": {
        "asns": ["AS20940", "20940", "AS16625"],
        "org_keywords": ["akamai", "akamaitechnologies"],
    },
    "Fastly": {
        "asns": ["AS54113", "54113"],
        "org_keywords": ["fastly"],
    },
    "CloudFront": {
        "asns": ["AS16509", "16509"],
        "org_keywords": ["amazon", "cloudfront", "aws"],
    },
    "Bunny": {
        "asns": ["AS200325", "200325"],
        "org_keywords": ["bunny", "bunnynet"],
    },
    "Gcore": {
        "asns": ["AS199524", "199524"],
        "org_keywords": ["gcore"],
    },
}

# Cloudflare IP ranges (partial, for heuristic)
CLOUDFLARE_CIDRS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


def _ip_in_cidr(ip: str, cidrs: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c) for c in cidrs)
    except ValueError:
        return False


def detect_cdn(
    ip: str,
    org: Optional[str] = None,
    reverse_names: Optional[list[str]] = None,
    asn: Optional[str] = None,
) -> tuple[Optional[str], float]:
    """Detect CDN from IP, org, reverse DNS, and ASN."""
    reverse_names = reverse_names or []
    org_lower = (org or "").lower()
    combined = " ".join(reverse_names).lower()
    asn_norm = (asn or "").upper().replace("AS", "")

    best_cdn: Optional[str] = None
    best_confidence = 0.0

    for cdn_name, sig in CDN_SIGNATURES.items():
        confidence = 0.0
        if _ip_in_cidr(ip, CLOUDFLARE_CIDRS) and cdn_name == "Cloudflare":
            confidence = max(confidence, 0.85)
        for asn_sig in sig.get("asns", []):
            asn_sig_norm = asn_sig.upper().replace("AS", "")
            if asn_norm and (asn_norm == asn_sig_norm or asn_norm.endswith(asn_sig_norm)):
                confidence = max(confidence, 0.90)
        for kw in sig.get("org_keywords", []):
            if kw in org_lower or kw in combined:
                confidence = max(confidence, 0.75)
        for kw in sig.get("cname_keywords", []):
            if kw in combined:
                confidence = max(confidence, 0.70)
        if confidence > best_confidence:
            best_confidence = confidence
            best_cdn = cdn_name

    return best_cdn, best_confidence


async def lookup_ip_intelligence(ip: str, reverse_names: Optional[list[str]] = None) -> IPIntelligence:
    """Gather IP intelligence using ipwhois, geo API, and heuristics."""
    info = IPIntelligence(ip=ip)

    # Primary geo lookup (rich country data)
    geo = await lookup_geo_ip(ip)
    if geo:
        info.country = geo.get("country")
        info.country_code = geo.get("country_code")
        info.country_flag = country_flag(info.country_code)
        info.region = geo.get("region")
        info.city = geo.get("city")
        info.isp = geo.get("isp")
        info.organization = geo.get("organization")
        info.asn = geo.get("asn")

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _sync_ipwhois, ip)
        if not info.asn:
            info.asn = result.get("asn")
        if not info.isp:
            info.isp = result.get("isp")
        if not info.organization:
            info.organization = result.get("org") or result.get("description")
        if not info.country_code and result.get("country"):
            info.country_code = result.get("country")
            info.country_flag = country_flag(info.country_code)
            if not info.country:
                info.country = result.get("country")

        org_text = (info.organization or info.isp or "").lower()
        dc_keywords = ["datacenter", "hosting", "cloud", "server", "vps", "digitalocean", "linode", "vultr", "hetzner", "ovh"]
        if any(kw in org_text for kw in dc_keywords):
            info.datacenter = info.organization or info.isp
            info.is_datacenter = True

    except Exception as exc:
        logger.debug("IP whois lookup failed for %s: %s", ip, exc)

    cdn, confidence = detect_cdn(ip, info.organization or info.isp, reverse_names, info.asn)
    info.cdn_detected = cdn
    info.cdn_confidence = confidence

    if info.datacenter:
        info.is_datacenter = True

    return info


def _sync_ipwhois(ip: str) -> dict:
    """Synchronous IP WHOIS lookup."""
    try:
        from ipwhois import IPWhois

        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1)
        entities = result.get("entities", [])
        org = ""
        if entities:
            org = str(entities[0])
        asn_desc = result.get("asn_description", "")
        network = result.get("network", {}) or {}
        country = network.get("country") if isinstance(network, dict) else None

        return {
            "asn": f"AS{result.get('asn')}" if result.get("asn") else None,
            "isp": asn_desc,
            "org": org or asn_desc,
            "description": asn_desc,
            "country": country,
            "region": None,
            "city": None,
        }
    except Exception:
        return {}
