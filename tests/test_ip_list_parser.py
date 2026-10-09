"""Tests for IP list / CIDR parser."""

from tools.ip_list_parser import parse_cidr_lines, parse_ip_lines, build_scan_list


def test_parse_ip_lines():
    text = "104.16.0.1\n172.64.0.2\n# comment\n"
    ips, errs = parse_ip_lines(text)
    assert ips == ["104.16.0.1", "172.64.0.2"]
    assert not errs


def test_parse_cidr_expands():
    ips, errs = parse_cidr_lines("104.16.0.0/30", max_ips=10)
    assert len(ips) >= 2
    assert all(ip.startswith("104.16.0.") for ip in ips)


def test_build_scan_custom_ip_list():
    ips, label, _ = build_scan_list(mode="Custom IP list", custom_text="1.1.1.1\n8.8.8.8", max_ips=10)
    assert "1.1.1.1" in ips
    assert "Custom IP list" in label


def test_build_scan_custom_cidr():
    ips, label, _ = build_scan_list(mode="Custom CIDR ranges", custom_text="192.0.2.0/29", max_ips=20)
    assert ips
    assert "CIDR" in label
