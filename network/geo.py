"""IP geolocation lookup with caching and multi-provider fallbacks."""

from __future__ import annotations

import asyncio
from typing import Any, Optional

import httpx

from utils.iran_network import is_iranian_network_identity
from utils.geo_cache import GeoCache
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)

GEO_FIELDS = "status,country,countryCode,regionName,city,isp,org,as,query,message"
_cache = GeoCache()

# Do not use system HTTP_PROXY — breaks lookup when VPN/tunnel is active.
_HTTP = {"timeout": 12.0, "trust_env": False, "follow_redirects": True}


def _normalize_result(data: dict[str, Any], *, source: str) -> dict:
    data = {**data, "source": source}
    return data


async def _fetch_public_ip(client: httpx.AsyncClient) -> Optional[str]:
    for url in (
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
    ):
        try:
            r = await client.get(url)
            r.raise_for_status()
            if "json" in url:
                return r.json().get("ip")
            return r.text.strip()
        except Exception as exc:
            logger.debug("Public IP fetch failed %s: %s", url, exc)
    return None


async def _lookup_ip_api(client: httpx.AsyncClient, ip: Optional[str]) -> Optional[dict]:
    settings = get_settings()
    path = ip or ""
    base = f"http://ip-api.com/json/{path}"
    params: dict = {"fields": GEO_FIELDS}
    if settings.ip_api_key:
        params["key"] = settings.ip_api_key
    try:
        response = await client.get(base, params=params)
        response.raise_for_status()
        data = response.json()
        if data.get("status") == "success":
            return _normalize_result(
                {
                    "ip": data.get("query") or ip or "",
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("as", "").split()[0] if data.get("as") else None,
                },
                source="ip-api.com",
            )
        logger.debug("ip-api fail: %s", data.get("message"))
    except Exception as exc:
        logger.debug("ip-api error: %s", exc)
    return None


async def _lookup_ipwho(client: httpx.AsyncClient, ip: Optional[str]) -> Optional[dict]:
    url = f"https://ipwho.is/{ip}" if ip else "https://ipwho.is/"
    try:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            return None
        conn = data.get("connection") or {}
        asn_raw = conn.get("asn")
        asn = f"AS{asn_raw}" if isinstance(asn_raw, int) else str(asn_raw or "")
        return _normalize_result(
            {
                "ip": data.get("ip") or ip or "",
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "isp": conn.get("isp") or conn.get("org"),
                "organization": conn.get("org"),
                "asn": asn if asn.startswith("AS") else None,
            },
            source="ipwho.is",
        )
    except Exception as exc:
        logger.debug("ipwho error: %s", exc)
    return None


def _client_cache_key() -> str:
    return "__client__"


def _correct_iran_mobile_geo(result: dict) -> dict:
    """Iranian mobile IPs are often geolabeled AZ/TR — trust ASN/ISP."""
    if not result:
        return result
    if result.get("country_code") == "IR":
        return result
    if is_iranian_network_identity(
        asn=result.get("asn"),
        isp=result.get("isp"),
        organization=result.get("organization"),
    ):
        return {
            **result,
            "country": "Iran",
            "country_code": "IR",
            "geo_corrected": True,
        }
    return result


def _client_geo_score(result: dict) -> tuple[int, int, int]:
    """Higher is better — prefer Iranian ASN, then IR country, then ipwho source."""
    iran_id = int(
        is_iranian_network_identity(
            asn=result.get("asn"),
            isp=result.get("isp"),
            organization=result.get("organization"),
        )
    )
    ir_cc = int(result.get("country_code") == "IR")
    ipwho = int(result.get("source") == "ipwho.is")
    return (iran_id, ir_cc, ipwho)


def _pick_best_client_geo(candidates: list[dict]) -> dict:
    if not candidates:
        return {}
    best = max(candidates, key=_client_geo_score)
    return _correct_iran_mobile_geo(best)


async def _discover_public_ips(client: httpx.AsyncClient) -> list[str]:
    """Collect candidate public IPs — Iranian mobile ISPs return different IPs per service."""
    ips: list[str] = []

    def _add(ip: Optional[str]) -> None:
        if ip and ip not in ips:
            ips.append(ip)

    auto = await _lookup_ipwho(client, None)
    if auto and auto.get("ip"):
        _add(auto["ip"])

    for url, parser in (
        ("https://api.ipify.org?format=json", lambda r: r.json().get("ip")),
        ("https://ifconfig.me/ip", lambda r: r.text.strip()),
    ):
        try:
            r = await client.get(url)
            r.raise_for_status()
            _add(parser(r))
        except Exception as exc:
            logger.debug("Public IP fetch failed %s: %s", url, exc)

    return ips


async def _lookup_client_geo_candidates(client: httpx.AsyncClient) -> list[dict]:
    """Resolve geo for every discovered public IP; pick best Iranian match."""
    candidates: list[dict] = []
    seen_ips: set[str] = set()

    auto = await _lookup_ipwho(client, None)
    if auto and auto.get("ip"):
        candidates.append(auto)
        seen_ips.add(auto["ip"])

    for ip in await _discover_public_ips(client):
        if ip in seen_ips:
            continue
        seen_ips.add(ip)
        result = await _lookup_ipwho(client, ip)
        if result and result.get("ip"):
            candidates.append(result)

    return candidates


async def lookup_geo_ip(ip: Optional[str] = None, *, refresh: bool = False) -> dict:
    """Lookup geolocation; tries ip-api then ipwho.is (no system proxy)."""
    cache_key = ip if ip else "__probe__"
    if not refresh:
        cached = _cache.get(cache_key)
        if cached:
            return cached

    async with httpx.AsyncClient(**_HTTP) as client:
        for provider in (_lookup_ip_api, _lookup_ipwho):
            result = await provider(client, ip)
            if result and result.get("ip"):
                _cache.set(cache_key, result)
                return result

        if not ip:
            pub = await _fetch_public_ip(client)
            if pub:
                for provider in (_lookup_ip_api, _lookup_ipwho):
                    result = await provider(client, pub)
                    if result:
                        _cache.set(cache_key, result)
                        return result

    return {}


async def lookup_client_geo(*, refresh: bool = True) -> dict:
    """Get geolocation of the client's public IP (fresh by default).

    Iranian mobile ISPs (Irancell/MCI/Rightel) often expose multiple egress IPs:
    ipwho.is may return 5.117.x (IR) while ipify returns 31.171.x (AZ). We query
    all candidates and prefer the one with a known Iranian ASN/ISP.
    """
    cache_key = _client_cache_key()
    if not refresh:
        cached = _cache.get(cache_key)
        if cached:
            return cached

    async with httpx.AsyncClient(**_HTTP) as client:
        candidates = await _lookup_client_geo_candidates(client)
        result = _pick_best_client_geo(candidates)
        if result:
            _cache.set(cache_key, result)
            return result

        result = await _lookup_ip_api(client, None)
        if result and result.get("ip"):
            result = _correct_iran_mobile_geo(result)
            _cache.set(cache_key, result)
            return result

    return {}
