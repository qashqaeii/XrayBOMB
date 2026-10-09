"""Tests for VPS datacenter tools."""

from tools.ip_list_parser import parse_ip_lines
from tools.multi_dc_compare import COMPARE_COUNTRIES


def test_compare_countries_list():
    assert "Germany" in COMPARE_COUNTRIES
    assert len(COMPARE_COUNTRIES) >= 6


def test_vps_ip_ranker_parse():
    ips, _ = parse_ip_lines("1.1.1.1\n8.8.8.8\n")
    assert len(ips) == 2
