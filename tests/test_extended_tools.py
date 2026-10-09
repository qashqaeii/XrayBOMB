"""Tests for extended network tools."""

from tools.infrastructure_similarity import compare_infrastructure_sync
from tools.isp_iran_guide import ISP_DATA, ISPS, build_isp_guide
from tools.reality_analyzer import analyze_reality_config_sync
from tools.config_topology import map_config_topology_sync
from tools.registry import TOOL_SPECS
from tools.output_labels import EDITORIAL, MEASURED


def test_isp_matrix_includes_shatel():
    assert "Shatel" in ISPS
    assert "Shatel" in ISP_DATA
    assert ISP_DATA["Shatel"]["asns"][0] == "AS31549"


def test_registry_has_phase2_tools():
    ids = {t.tool_id for t in TOOL_SPECS}
    for tid in (
        "remote_server", "config_topology", "mtr_visualizer",
        "cf_colo_finder", "infra_similarity", "dnssec_validator",
        "national_cdn", "arvan_inspector",
    ):
        assert tid in ids
    assert len(TOOL_SPECS) >= 38


def test_isp_guide_labels_editorial():
    out = build_isp_guide("MCI (Hamrah-e Aval)")
    assert "editorial" in out.lower() or "reference" in out.lower()


def test_reality_analyzer_parses_link():
    link = (
        "vless://uuid@1.2.3.4:443?encryption=none&security=reality"
        "&sni=www.cloudflare.com&fp=chrome&pbk=abc&sid=abcd&type=tcp#test"
    )
    out = analyze_reality_config_sync(text=link)
    assert "REALITY" in out
    assert "www.cloudflare.com" in out


def test_infra_similarity_same_config():
    link = "vless://uuid@1.2.3.4:443?encryption=none&security=reality&sni=cf.com&type=tcp#a"
    out = compare_infrastructure_sync(text_a=link, text_b=link)
    assert "Similarity:" in out
    pct = int(out.split("Similarity:")[1].split("%")[0].strip().split()[-1])
    assert pct >= 70


def test_output_labels_constants():
    assert "measured" in MEASURED
    assert "editorial" in EDITORIAL
