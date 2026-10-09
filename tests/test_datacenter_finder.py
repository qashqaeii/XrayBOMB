"""Tests for datacenter finder sync entrypoint."""

import asyncio

from tools.datacenter_finder import benchmark_datacenters_sync


def test_benchmark_sync_imports_asyncio():
    """Regression: sync wrapper must not raise NameError for asyncio."""
    assert asyncio is not None


def test_benchmark_returns_result_structure():
    result = benchmark_datacenters_sync(country="Germany", samples=2)
    assert result.country == "Germany"
    assert result.country_code == "DE"
    assert isinstance(result.results, list)
    assert len(result.results) >= 1
