"""Client network profile — ipwho.is-style network identity."""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Callable, Optional

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

_IPWHO = "https://ipwho.is/"
_HTTP = {"timeout": 12.0, "trust_env": False, "follow_redirects": True}

_MOBILE_KW = ("mobile", "mci", "irancell", "mtn", "rightel", "hamrah")
_FTTH_KW = ("fiber", "ftth", "mokhaberat", "telecommunication")
_ADSL_KW = ("adsl", "dsl", "parsonline", "shatel", "asiatech", "hiweb", "afranet")
_DC_KW = ("datacenter", "hosting", "cloud", "server", "vps")


def _line(label: str, value: Any) -> str:
    if value is None or value == "":
        return f"  {label:<14}: —"
    return f"  {label:<14}: {value}"


def _guess_connection_type(isp: str, org: str, asn: str) -> str:
    blob = f"{isp} {org} {asn}".lower()
    if any(k in blob for k in _DC_KW):
        return "Datacenter / VPN egress"
    if any(k in blob for k in _MOBILE_KW):
        return "Mobile"
    if any(k in blob for k in _FTTH_KW):
        return "FTTH / Fixed"
    if any(k in blob for k in _ADSL_KW):
        return "ADSL / ISP"
    return "Unknown (check ASN)"


async def _reverse_dns(ip: str) -> str:
    try:
        loop = asyncio.get_event_loop()
        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return name
    except Exception:
        return "—"


async def _fetch_ipv6() -> Optional[str]:
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get("https://api64.ipify.org?format=json")
            r.raise_for_status()
            ip = r.json().get("ip", "")
            if ":" in ip:
                return ip
    except Exception:
        pass
    return None


def _format_profile(data: dict[str, Any], *, ipv6: Optional[str], rdns: str, conn_type: str) -> str:
    conn = data.get("connection") or {}
    tz = data.get("timezone") or {}
    flag = data.get("flag") or {}
    ip = data.get("ip", "")

    lines = [
        "Client Network Profile",
        "═" * 52,
        "",
        _line("IPv4", ip),
        _line("IPv6", ipv6 or "not detected"),
        _line("IP type", data.get("type")),
        _line("Reverse DNS", rdns),
        _line("Conn. type", conn_type),
        "",
        _line("Continent", f"{data.get('continent')} ({data.get('continent_code')})"
               if data.get("continent") else None),
        _line("Country", f"{data.get('country')} ({data.get('country_code')})"
               if data.get("country") else None),
        _line("Region", f"{data.get('region')} ({data.get('region_code')})"
               if data.get("region") else None),
        _line("City", data.get("city")),
        _line("Coordinates", f"{data.get('latitude')}, {data.get('longitude')}"
               if data.get("latitude") is not None else None),
        _line("Postal", data.get("postal")),
        _line("EU", data.get("is_eu")),
        "",
        "── Connection ──",
        _line("ASN", conn.get("asn")),
        _line("ISP", conn.get("isp")),
        _line("Org", conn.get("org")),
        _line("Domain", conn.get("domain")),
        "",
        "── Timezone ──",
        _line("ID", tz.get("id")),
        _line("Abbr", tz.get("abbr")),
        _line("UTC", tz.get("utc")),
        _line("Offset", tz.get("offset")),
        _line("DST", tz.get("is_dst")),
        "",
        "── Flag ──",
        _line("Emoji", flag.get("emoji")),
        "",
        f"  Source        : ipwho.is + live IPv6/rDNS probes",
        f"  Conn. type    : heuristic from ASN/org keywords",
    ]
    return "\n".join(lines)


async def _fetch_ipwho(ip: Optional[str] = None) -> dict[str, Any]:
    url = f"{_IPWHO}{ip}" if ip else _IPWHO
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()
            if data.get("success"):
                return data
    except Exception as exc:
        logger.debug("ipwho.is error: %s", exc)
    return {}


async def _fetch_public_ip() -> Optional[str]:
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get("https://api.ipify.org?format=json")
            r.raise_for_status()
            return r.json().get("ip")
    except Exception:
        return None


async def build_client_profile(progress: Optional[Callable[[str], None]] = None) -> str:
    if progress:
        progress("Querying ipwho.is...")
    data = await _fetch_ipwho()
    if not data.get("ip"):
        pub = await _fetch_public_ip()
        if pub:
            if progress:
                progress(f"Retry ipwho.is for {pub}...")
            data = await _fetch_ipwho(pub)

    if not data.get("success"):
        return (
            "Client Network Profile — lookup failed\n"
            "═" * 52 + "\n\n"
            "  Could not reach ipwho.is. Check internet or disable system proxy.\n"
        )

    ip = data.get("ip", "")
    if progress:
        progress("IPv6 + reverse DNS...")
    ipv6, rdns = await asyncio.gather(_fetch_ipv6(), _reverse_dns(ip))
    conn = data.get("connection") or {}
    conn_type = _guess_connection_type(
        conn.get("isp", ""),
        conn.get("org", ""),
        conn.get("asn", ""),
    )
    return _format_profile(data, ipv6=ipv6, rdns=rdns, conn_type=conn_type)


def build_client_profile_sync(**kwargs) -> str:
    return asyncio.run(build_client_profile(**kwargs))
