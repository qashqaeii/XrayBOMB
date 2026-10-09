from tools.iran_operator import is_iranian_network_identity, resolve_iran_operator


def test_asn_mci():
    r = resolve_iran_operator(country_code="IR", asn="AS197207 Mobile Communication Company of Iran")
    assert r and r.operator == "MCI"


def test_asn_irancell():
    r = resolve_iran_operator(country_code="IR", asn="AS44244")
    assert r and r.operator == "Irancell"


def test_iranian_identity_ignores_wrong_geo_label():
    assert is_iranian_network_identity(
        asn="AS44244",
        isp="Iran Cell Service And Communication Company",
    )
