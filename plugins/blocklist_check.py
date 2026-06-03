"""Sample plugin: enrich threat intel with blocklist checks."""

from __future__ import annotations

from backend.intelligence import analyze_threat_intel
from backend.models import AnalysisResult, IPIntelligence, ParsedConfig, ThreatIntel


def analyze(result: AnalysisResult, config: ParsedConfig) -> AnalysisResult:
    """Plugin hook: run blocklist check on all resolved IPs."""
    plugin_data: list[dict] = []

    for ip_intel in result.network:
        threat = analyze_threat_intel(ip_intel)
        plugin_data.append({
            "ip": ip_intel.ip,
            "reputation": threat.reputation_score,
            "blocklists": threat.blocklist_hits,
            "notes": threat.notes,
        })
        ip_intel.reputation_score = threat.reputation_score
        ip_intel.is_datacenter = threat.is_datacenter

    if not result.threat_intel and result.network:
        result.threat_intel = [
            ThreatIntel(
                ip=t.ip, reputation_score=t.reputation_score,
                blocklist_hits=t.blocklist_hits, notes=t.notes,
                is_datacenter=t.is_datacenter,
            )
            for t in [analyze_threat_intel(ip) for ip in result.network]
        ]

    result.raw_data.setdefault("plugins", {})["blocklist_check"] = plugin_data
    return result
