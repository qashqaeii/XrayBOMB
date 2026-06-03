"""Tests for proxy site reachability configuration."""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "proxy_diagnostics",
    Path(__file__).resolve().parent.parent / "xray" / "proxy_diagnostics.py",
)
_mod = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(_mod)

SITE_TESTS = _mod.SITE_TESTS
_is_lenient_reachability = _mod._is_lenient_reachability


def test_site_tests_include_youtube_and_instagram():
    names = {name for name, _ in SITE_TESTS}
    assert "YouTube" in names
    assert "Instagram" in names


def test_youtube_url_uses_generate_204():
    urls = dict(SITE_TESTS)
    assert "youtube.com/generate_204" in urls["YouTube"]


def test_lenient_reachability_for_instagram_403():
    assert _is_lenient_reachability("https://www.instagram.com/", 403) is True


def test_lenient_reachability_rejects_500():
    assert _is_lenient_reachability("https://www.youtube.com/generate_204", 503) is False
