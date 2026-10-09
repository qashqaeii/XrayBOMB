"""Client geo lookup — provider order and explicit public IP."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path


def _load_geo():
    path = Path(__file__).resolve().parents[1] / "network" / "geo.py"
    spec = importlib.util.spec_from_file_location("geo", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_lookup_client_geo_prefers_iranian_asn_over_az_ipify(monkeypatch):
    """Irancell: ipwho auto=IR, ipify=AZ — must keep the Iranian ASN result."""
    geo_mod = _load_geo()

    async def fake_ipwho(_client, ip):
        if ip is None:
            return {
                "ip": "5.117.38.208",
                "country": "Iran",
                "country_code": "IR",
                "asn": "AS44244",
                "isp": "Iran Cell Service And Communication Company",
                "source": "ipwho.is",
            }
        if ip == "31.171.101.253":
            return {
                "ip": "31.171.101.253",
                "country": "Azerbaijan",
                "country_code": "AZ",
                "asn": "AS12345",
                "isp": "Foreign Gateway",
                "source": "ipwho.is",
            }
        return None

    async def fake_discover(_client):
        return ["5.117.38.208", "31.171.101.253"]

    monkeypatch.setattr(geo_mod, "_lookup_ipwho", fake_ipwho)
    monkeypatch.setattr(geo_mod, "_discover_public_ips", fake_discover)
    monkeypatch.setattr(geo_mod._cache, "get", lambda _ip: None)
    monkeypatch.setattr(geo_mod._cache, "set", lambda _ip, _data: None)

    result = asyncio.run(geo_mod.lookup_client_geo(refresh=True))

    assert result["ip"] == "5.117.38.208"
    assert result["country_code"] == "IR"


def test_lookup_client_geo_corrects_iran_asn_with_wrong_country(monkeypatch):
    """When only AZ-labeled IP is seen but ASN is Irancell, force IR."""
    geo_mod = _load_geo()

    async def fake_ipwho(_client, ip):
        return {
            "ip": "5.117.38.208",
            "country": "Azerbaijan",
            "country_code": "AZ",
            "asn": "AS44244",
            "isp": "Iran Cell Service And Communication Company",
            "source": "ipwho.is",
        }

    async def fake_discover(_client):
        return ["5.117.38.208"]

    monkeypatch.setattr(geo_mod, "_lookup_ipwho", fake_ipwho)
    monkeypatch.setattr(geo_mod, "_discover_public_ips", fake_discover)
    monkeypatch.setattr(geo_mod._cache, "get", lambda _ip: None)
    monkeypatch.setattr(geo_mod._cache, "set", lambda _ip, _data: None)

    result = asyncio.run(geo_mod.lookup_client_geo(refresh=True))

    assert result["country_code"] == "IR"
    assert result.get("geo_corrected") is True
