"""Tests for network tools."""

from tools.ip_probe import score_latency_iran, score_clean_ip_cf
from tools.provider_catalog import COUNTRY_CATALOG, TARGET_COUNTRIES
from tools.cloudflare_ranges import _cidr_to_sample_ips


def test_score_latency_iran_good_ping():
    score, notes = score_latency_iran(100.0, 110.0, 0.0)
    assert score >= 85


def test_score_latency_iran_high_loss():
    score, _ = score_latency_iran(200.0, 250.0, 15.0)
    assert score < 70


def test_clean_ip_score_tls_and_blocklist():
    score_ok, _ = score_clean_ip_cf(True, True, 90.0, 100.0, 0.0, [], "DE", "DE")
    score_bl, _ = score_clean_ip_cf(True, True, 90.0, 100.0, 0.0, ["zen.spamhaus.org"], "DE", "DE")
    assert score_ok > score_bl


def test_germany_has_providers():
    assert "Germany" in TARGET_COUNTRIES
    assert len(COUNTRY_CATALOG["Germany"].providers) >= 8


def test_listings_catalog_size():
    from tools.infrastructure_catalog import LISTINGS
    assert len(LISTINGS) >= 50


def test_cidr_sampling():
    ips = _cidr_to_sample_ips("104.16.0.0/24", count=4)
    assert len(ips) == 4
    assert all(ip.startswith("104.16.") for ip in ips)
