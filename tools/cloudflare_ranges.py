"""Cloudflare IPv4 ranges — live fetch from official publish list only."""

from __future__ import annotations

import random
import re

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

CF_IPV4_URL = "https://www.cloudflare.com/ips-v4"

REGION_OPTIONS = (
    "Auto (Best Latency)",
    "Germany",
    "Netherlands",
    "Finland",
    "Turkey",
    "France",
    "All Cloudflare",
)

SCAN_SOURCE_MODES = (
    "Cloudflare live list",
    "Custom CIDR ranges",
    "Custom IP list",
)

_cached_cidrs: list[str] | None = None


def _cidr_to_sample_ips(cidr: str, count: int = 8) -> list[str]:
    """Sample random host IPs from an IPv4 CIDR."""
    if "/" not in cidr:
        return [cidr]
    base, prefix = cidr.split("/")
    try:
        p = int(prefix)
    except ValueError:
        return []
    if p > 30:
        return [base]
    parts = [int(x) for x in base.split(".")]
    ip_int = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    mask = (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF
    network = ip_int & mask
    host_bits = 32 - p
    max_hosts = min((1 << host_bits) - 2, 512)
    if max_hosts <= 0:
        return [base]
    samples: set[int] = set()
    while len(samples) < min(count, max_hosts):
        offset = random.randint(1, max_hosts)
        samples.add(network + offset)
    return [".".join(str((n >> (8 * i)) & 0xFF) for i in range(3, -1, -1)) for n in sorted(samples)]


async def fetch_cloudflare_cidrs(*, refresh: bool = False) -> list[str]:
    """Fetch official Cloudflare IPv4 CIDRs — no hardcoded fake ranges."""
    global _cached_cidrs
    if _cached_cidrs and not refresh:
        return _cached_cidrs

    try:
        async with httpx.AsyncClient(timeout=15, trust_env=False, follow_redirects=True) as client:
            r = await client.get(CF_IPV4_URL)
            r.raise_for_status()
            cidrs = [
                line.strip()
                for line in r.text.splitlines()
                if re.match(r"^\d+\.\d+\.\d+\.\d+/\d+", line.strip())
            ]
            if cidrs:
                _cached_cidrs = cidrs
                logger.info("Loaded %d Cloudflare IPv4 ranges from %s", len(cidrs), CF_IPV4_URL)
                return cidrs
    except Exception as exc:
        logger.warning("CF IP fetch failed: %s", exc)

    if _cached_cidrs:
        return _cached_cidrs
    return []


def sample_ips_from_cidrs(cidrs: list[str], max_ips: int = 48) -> list[str]:
    """Sample up to max_ips host addresses from published CIDR list."""
    if not cidrs:
        return []
    per_subnet = max(2, max_ips // min(len(cidrs), 24))
    ips: list[str] = []
    shuffled = list(cidrs)
    random.shuffle(shuffled)
    for cidr in shuffled:
        ips.extend(_cidr_to_sample_ips(cidr, per_subnet))
        if len(ips) >= max_ips:
            break
    random.shuffle(ips)
    return ips[:max_ips]


async def resolve_scan_ips(
    region: str,
    max_ips: int = 48,
    *,
    mode: str = "Cloudflare live list",
    custom_text: str = "",
) -> tuple[list[str], str, list[str]]:
    from tools.ip_list_parser import build_scan_list

    cf_cidrs: list[str] = []
    if mode == "Cloudflare live list":
        cf_cidrs = await fetch_cloudflare_cidrs()
    return build_scan_list(
        mode=mode,
        custom_text=custom_text,
        region=region,
        max_ips=max_ips,
        cf_cidrs=cf_cidrs,
    )
