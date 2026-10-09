"""Tests for HTTP fingerprint CDN/panel detection."""

import importlib.util
from pathlib import Path


def _load_http_probe():
    path = Path(__file__).resolve().parents[1] / "network" / "http_probe.py"
    spec = importlib.util.spec_from_file_location("http_probe", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_arvan_cdn_from_server_header():
    mod = _load_http_probe()
    cdn = mod._detect_cdn_from_headers({
        "server": "ArvanCloud",
        "x-cache": "BYPASS",
        "x-sid": "6980",
    })
    assert cdn == "ArvanCloud"


def test_panel_3x_ui_cookie():
    mod = _load_http_probe()
    panel = mod._detect_panel(
        {"set-cookie": "3x-ui=abc; Path=/panel/"},
        "<html><script>window.X_UI_BASE_PATH</script></html>",
    )
    assert panel == "3x-ui"


def test_no_nginx_when_arvan_only():
    mod = _load_http_probe()
    rp = mod._detect_reverse_proxy_server({"server": "ArvanCloud"})
    assert rp is None
