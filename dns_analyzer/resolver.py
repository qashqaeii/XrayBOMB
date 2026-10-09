"""DNS resolver implementation."""

from __future__ import annotations

import asyncio
import socket
from typing import Optional

import dns.asyncresolver
import dns.reversename

from backend.models import DNSAnalysis
from dns_analyzer.provider import detect_dns_provider
from utils.helpers import is_ip_address
from utils.logger import get_logger

logger = get_logger(__name__)

RESOLVER = dns.asyncresolver.Resolver()
RESOLVER.timeout = 5
RESOLVER.lifetime = 10


async def _query(hostname: str, rdtype: str) -> tuple[list[str], Optional[int]]:
    """Query DNS records of given type."""
    try:
        answers = await RESOLVER.resolve(hostname, rdtype)
        values = [str(r) for r in answers]
        ttl = answers.rrset.ttl if answers.rrset else None
        return values, ttl
    except Exception as exc:
        logger.debug("DNS %s query for %s failed: %s", rdtype, hostname, exc)
        return [], None


async def reverse_dns(ip: str) -> list[str]:
    """Perform reverse DNS lookup."""
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = await RESOLVER.resolve(rev_name, "PTR")
        return [str(r).rstrip(".") for r in answers]
    except Exception:
        return []


async def _check_dnssec(hostname: str) -> Optional[bool]:
    try:
        answers = await RESOLVER.resolve(hostname, "DNSKEY")
        return bool(answers)
    except Exception:
        try:
            answers = await RESOLVER.resolve(hostname, "DS")
            return bool(answers)
        except Exception:
            return None


async def _doh_lookup(hostname: str) -> dict[str, list[str]]:
    """Resolve via DNS-over-HTTPS for comparison."""
    results: dict[str, list[str]] = {}
    doh_providers = {
        "cloudflare": f"https://cloudflare-dns.com/dns-query?name={hostname}&type=A",
        "google": f"https://dns.google/resolve?name={hostname}&type=A",
    }
    import httpx
    for name, url in doh_providers.items():
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(url, headers={"Accept": "application/dns-json"})
                data = resp.json()
                answers = data.get("Answer", [])
                ips = [a.get("data", "") for a in answers if a.get("type") in (1, 28)]
                if ips:
                    results[name] = ips
        except Exception:
            pass
    return results


async def analyze_dns(hostname: str) -> DNSAnalysis:
    """Perform comprehensive DNS analysis."""
    result = DNSAnalysis(hostname=hostname)

    if is_ip_address(hostname):
        result.all_resolved_ips = [hostname]
        ptr = await reverse_dns(hostname)
        result.reverse_dns = ptr
        return result

    a_records, a_ttl = await _query(hostname, "A")
    aaaa_records, aaaa_ttl = await _query(hostname, "AAAA")
    cname_records, _ = await _query(hostname, "CNAME")
    mx_records, _ = await _query(hostname, "MX")
    txt_records, _ = await _query(hostname, "TXT")

    ns_records, _ = await _query(hostname, "NS")
    zone_ns = ns_records
    if not zone_ns and "." in hostname:
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            zone = ".".join(parts[i:])
            zone_ns, _ = await _query(zone, "NS")
            if zone_ns:
                break

    result.a_records = a_records
    result.aaaa_records = aaaa_records
    result.cname_records = cname_records
    result.mx_records = mx_records
    result.txt_records = txt_records
    result.ttl = a_ttl or aaaa_ttl
    result.local_resolver_ips = list(a_records)
    result.dnssec = await _check_dnssec(hostname)
    result.doh_results = await _doh_lookup(hostname)

    # Union all resolver sources — CDN detection must not rely on a single resolver view
    all_ipv4: list[str] = list(dict.fromkeys(a_records))
    for ips in result.doh_results.values():
        for ip in ips:
            if ip and ":" not in ip and ip not in all_ipv4:
                all_ipv4.append(ip)
    result.all_resolved_ips = all_ipv4 + aaaa_records

    local_set = set(a_records)
    doh_union = {ip for ips in result.doh_results.values() for ip in ips if ":" not in ip}
    if local_set and doh_union and local_set != doh_union:
        result.dns_split_detected = True
        result.dns_split_note = (
            f"Local A: {', '.join(a_records) or 'none'} | "
            f"DoH: {', '.join(sorted(doh_union))} — geo/split DNS likely"
        )

    if not result.all_resolved_ips:
        result.errors.append(f"No A/AAAA records found for {hostname}")
        try:
            loop = asyncio.get_event_loop()
            infos = await loop.getaddrinfo(hostname, None)
            ips = list({info[4][0] for info in infos})
            result.all_resolved_ips = ips
            if ips:
                result.a_records = [ip for ip in ips if ":" not in ip]
                result.aaaa_records = [ip for ip in ips if ":" in ip]
        except socket.gaierror as exc:
            result.errors.append(f"System DNS resolution failed: {exc}")

    for ip in result.all_resolved_ips[:5]:
        ptr = await reverse_dns(ip)
        result.reverse_dns.extend(ptr)

    result.reverse_dns = list(dict.fromkeys(result.reverse_dns))

    result.ns_records = list(dict.fromkeys(zone_ns))
    provider, prov_conf, prov_evidence = detect_dns_provider(result.ns_records)
    result.dns_provider = provider
    result.dns_provider_confidence = prov_conf
    result.dns_provider_evidence = prov_evidence

    return result
