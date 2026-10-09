"""Format tool results as plain text (English, Iran context)."""

from __future__ import annotations

from backend.models import CleanIPFinderResult, DatacenterFinderResult


def format_clean_ip(r: CleanIPFinderResult) -> str:
    lines = [
        "Cloudflare Clean IP Finder",
        "═" * 58,
        "",
        f"  Scan source  : {r.tips[0].replace('Scan source: ', '') if r.tips else 'live probe'}",
        f"  SNI          : {r.sni}",
        f"  Port         : {r.port}",
        f"  Scanned      : {r.scanned} IP(s)  |  Reachable: {r.reachable}",
        f"  Best IP      : {r.best_ip or '—'}  (measured score {r.best_score or 0})",
        "",
        "── Ranked results (live measurements) ──",
        f"  {'IP':<18} {'Score':>5} {'Avg':>7} {'P95':>7} {'Loss%':>6} {'TLS':>4} {'Geo':>4} {'ISP':<20}",
        "  " + "─" * 72,
    ]
    for row in r.results[:40]:
        tls = "Y" if row.tls_ok else "N"
        bl = " BL" if row.blocklist_hits else ""
        isp = (row.isp or "")[:20]
        lines.append(
            f"  {row.ip:<18} {row.score:>5} {row.avg_ms or '-':>7} {row.p95_ms or '-':>7} "
            f"{row.packet_loss_pct:>5.1f}% {tls:>4} {row.country_code or '?':>4} {isp:<20}{bl}"
        )
    if not r.results:
        lines.append("  (No reachable IPs from your network)")

    lines.extend(["", "── Top 5 detail ──"])
    for row in r.results[:5]:
        lines.append(f"  {row.ip} — score {row.score} (measured)")
        for n in row.notes[:4]:
            lines.append(f"    • {n}")

    if r.best_ip:
        lines.extend([
            "",
            "── Suggested Cloudflare DNS A record ──",
            f"  Type: A   Name: @ or sub   Content: {r.best_ip}   Proxy: per your protocol",
        ])

    if len(r.tips) > 1:
        lines.extend(["", "── Notes ──"])
        for t in r.tips[1:]:
            lines.append(f"  • {t}")
    return "\n".join(lines)


def format_datacenter(r: DatacenterFinderResult) -> str:
    from tools.provider_catalog import COUNTRY_CATALOG, DC_TYPE_NAMES

    catalog = COUNTRY_CATALOG.get(r.country)
    lines = [
        f"Datacenter Finder — {r.country} ({r.country_code})",
        "═" * 58,
        "",
        f"  Providers tested : {len(r.results)}",
        f"  Port             : {r.port}",
        f"  Winner           : {r.winner or '—'}  (score {r.winner_score or 0})",
        f"  Scoring          : latency + loss + geo match + Iran provider weight",
        "",
        "── Rankings ──",
        f"  {'Provider':<20} {'Score':>5} {'Avg':>7} {'P95':>7} {'Loss%':>6} {'ASN':<12} {'Type':<12}",
        "  " + "─" * 72,
    ]
    prov_map = {p.name: p for p in catalog.providers} if catalog else {}
    for p in r.results:
        meta = prov_map.get(p.provider)
        dtype = DC_TYPE_NAMES.get(meta.dc_type, "") if meta else ""
        lines.append(
            f"  {p.provider:<20} {p.score:>5} {p.avg_ms or '-':>7} {p.p95_ms or '-':>7} "
            f"{p.packet_loss_pct:>5.1f}% {(p.asn_hint or '-'):<12} {dtype:<12}"
        )

    lines.extend(["", "── Provider details ──"])
    for p in r.results:
        lines.append(f"  ■ {p.provider} — score {p.score}/100")
        if p.host:
            lines.append(f"      Probe   : {p.host} → {p.ip} ({p.country_code or '?'})")
        if p.asn_hint:
            lines.append(f"      ASN     : {p.asn_hint}")
        if p.iran_notes:
            lines.append(f"      Notes   : {p.iran_notes}")
        if p.blocklist_hits:
            lines.append(f"      Blocklist: {', '.join(p.blocklist_hits)}")
        for n in p.notes[:2]:
            lines.append(f"      • {n}")
        lines.append("")

    if catalog:
        lines.append("── Untested catalog providers (buy links) ──")
        tested = {p.provider for p in r.results}
        for prov in catalog.providers:
            if prov.name not in tested:
                lines.append(f"  • {prov.name} ({prov.asn_hint}) — run Infrastructure Marketplace")

    lines.extend(["", "── Reference ──"])
    for t in r.tips[:4]:
        lines.append(f"  • {t}")
    return "\n".join(lines)
