"""Tests for multi-source DNS union and split detection."""

import asyncio
import importlib.util
from pathlib import Path


def _load_resolver():
    path = Path(__file__).resolve().parents[1] / "dns_analyzer" / "resolver.py"
    spec = importlib.util.spec_from_file_location("resolver", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_dns_union_includes_doh_ips(monkeypatch):
    resolver = _load_resolver()

    async def fake_query(hostname, rdtype):
        if rdtype == "A":
            return ["178.83.46.253"], 300
        return [], None

    async def fake_doh(hostname):
        return {"cloudflare": ["185.143.233.234", "185.143.234.234"]}

    monkeypatch.setattr(resolver, "_query", fake_query)
    monkeypatch.setattr(resolver, "_doh_lookup", fake_doh)
    async def _no_dnssec(hostname):
        return None

    monkeypatch.setattr(resolver, "_check_dnssec", _no_dnssec)
    async def _no_ptr(ip):
        return []
    monkeypatch.setattr(resolver, "reverse_dns", _no_ptr)

    result = asyncio.run(resolver.analyze_dns("vip.example.ir"))

    assert "178.83.46.253" in result.all_resolved_ips
    assert "185.143.233.234" in result.all_resolved_ips
    assert result.dns_split_detected is True
