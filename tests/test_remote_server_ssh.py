
def test_parse_ip_api_blob():
    from tools.remote_server_ssh import _parse_ip_api_blob

    text = '1.2.3.4\n{"countryCode":"DE","country":"Germany","isp":"Hetzner","query":"1.2.3.4"}'
    data = _parse_ip_api_blob(text)
    assert data.get("countryCode") == "DE"


def test_count_http_ok():
    from tools.remote_server_ssh import _count_http_ok

    out = "Google HTTPS:\n200 0.45s\nGitHub:\n000 12s"
    assert _count_http_ok(out) == 1
