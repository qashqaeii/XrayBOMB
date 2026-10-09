"""Tests for port scanner."""

import pytest

from tools.port_scanner import scan_ports_sync, PRESETS


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost"])
def test_localhost_scan_returns_report(host: str):
    text = scan_ports_sync(host, (80, 443), progress=None)
    assert "Port Scanner" in text
