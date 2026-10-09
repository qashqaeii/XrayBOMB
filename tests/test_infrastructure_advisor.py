"""Tests for infrastructure marketplace advisor."""

from tools.infrastructure_advisor import filter_listings, build_marketplace_report_sync
from tools.infrastructure_catalog import LISTINGS


def test_filter_germany_vps_tunnel():
    items = filter_listings(
        country="Germany",
        category="VPS / Cloud Servers",
        role="Tunnel exit (REALITY / VLESS origin)",
        tier="Any budget",
    )
    assert len(items) >= 3
    assert any(i.name == "Hetzner" for i in items)


def test_filter_iran_cdn():
    items = filter_listings(country="Iran (local services)", category="All categories", role="All roles", tier="Any budget")
    assert any("Arvan" in i.name for i in items)


def test_marketplace_report_sync_no_probe():
    text = build_marketplace_report_sync(
        country="Any region", category="All categories", role="All roles", tier="Any budget",
        live_probe=False,
    )
    assert "Infrastructure Marketplace" in text
    assert len(LISTINGS) >= 20


def test_tunnel_planner():
    from tools.tunnel_route_planner import GOALS, build_tunnel_plan
    plan = build_tunnel_plan(GOALS[0], "Germany")
    assert "Germany" in plan
