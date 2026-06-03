"""IP geolocation lookup with caching."""

from __future__ import annotations

import asyncio
from typing import Optional

import httpx

from utils.geo_cache import GeoCache
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)

GEO_FIELDS = "status,country,countryCode,regionName,city,isp,org,as,query,message"
_cache = GeoCache()


async def lookup_geo_ip(ip: Optional[str] = None) -> dict:
    """Lookup geolocation via ip-api.com with local cache."""
    cached = _cache.get(ip or "")
    if cached:
        return cached

    settings = get_settings()
    base = f"http://ip-api.com/json/{ip or ''}"
    params: dict = {"fields": GEO_FIELDS}
    if settings.ip_api_key:
        params["key"] = settings.ip_api_key

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get(base, params=params)
            response.raise_for_status()
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "ip": data.get("query", ip or ""),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "organization": data.get("org"),
                    "asn": data.get("as", "").split()[0] if data.get("as") else None,
                }
                _cache.set(ip or "", result)
                return result
            logger.debug("Geo lookup failed: %s", data.get("message"))
    except Exception as exc:
        logger.debug("Geo API error for %s: %s", ip, exc)
    return {}


async def lookup_client_geo() -> dict:
    """Get geolocation of the client's public IP."""
    return await lookup_geo_ip(None)
