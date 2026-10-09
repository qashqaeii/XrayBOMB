"""CDN detection must not treat ASN-only as strong CDN proof."""

from network.cdn_detector import detect_cdn


def test_asn_only_arvan_low_confidence():
    cdn, conf = detect_cdn("185.204.169.162", org="Generic Hosting LLC", asn="AS50810")
    assert cdn == "ArvanCloud" or cdn is None
    if cdn:
        assert conf <= 0.45


def test_asn_with_org_keyword_higher():
    cdn, conf = detect_cdn(
        "185.204.169.162",
        org="ArvanCloud CDN edge",
        asn="AS50810",
    )
    assert cdn == "ArvanCloud"
    assert conf >= 0.70
