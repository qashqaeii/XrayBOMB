"""All analysis tab views."""

from __future__ import annotations

import json
from typing import Optional

import customtkinter as ctk

from backend.config_generator import generate_client_config_json
from backend.models import AnalysisResult
from gui.components.copyable_text import CopyableTextbox
from gui.components.two_row_tabs import TwoRowTabBar
from utils.country import format_country
from utils.helpers import mask_sensitive
from utils.settings import get_settings
from utils.ui_theme import BG_DARK, PANEL_PAD


class AnalysisTabs(ctk.CTkFrame):
    """Tabbed view for all analysis sections (two-row tab bar)."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._result: Optional[AnalysisResult] = None

        tab_names = [
            "Dashboard", "Overview", "Protocol Details", "DNS Analysis", "Network Analysis",
            "TLS Analysis", "Intelligence", "Xray Test", "Security Report",
            "Setup Guide", "Reproduction Guide", "Raw Data",
        ]
        self._panels: dict[str, CopyableTextbox] = {}

        self._tab_bar = TwoRowTabBar(self, tab_names)
        self._tab_bar.pack(fill="both", expand=True)

        for name in tab_names:
            panel = CopyableTextbox(
                self._tab_bar.frame(name),
                show_toolbar=True,
                read_only=True,
                font=ctk.CTkFont(family="Consolas", size=12),
                wrap="word",
                fg_color=BG_DARK,
            )
            panel.pack(fill="both", expand=True, padx=PANEL_PAD, pady=PANEL_PAD)
            self._panels[name] = panel

    def _write(self, tab: str, content: str) -> None:
        self._panels[tab].set_text(content)

    def _mask(self, value: Optional[str]) -> str:
        if not value:
            return "N/A"
        if get_settings().mask_secrets_ui:
            return mask_sensitive(value)
        return value

    def get_full_json(self) -> str:
        if not self._result:
            return "{}"
        return self._result.model_dump_json(indent=2)

    def update_result(self, result: AnalysisResult) -> None:
        self._result = result
        self._render_dashboard(result)
        self._render_overview(result)
        self._render_protocol(result)
        self._render_dns(result)
        self._render_network(result)
        self._render_tls(result)
        self._render_intelligence(result)
        self._render_xray(result)
        self._render_security(result)
        self._render_setup_guide(result)
        self._render_reproduction(result)
        self._render_raw(result)

    def _render_dashboard(self, r: AnalysisResult) -> None:
        c = r.config
        t = r.tunnel
        score = r.security.score
        bar_filled = "█" * (score // 10)
        bar_empty = "░" * (10 - score // 10)
        tls_badge = "✓ TLS" if c.tls else "✗ No TLS"
        reality_badge = "✓ REALITY" if c.reality else "○ No Reality"
        cdn_badge = f"CDN: {r.deployment.cdn_type}" if r.deployment.cdn_type else "No CDN"
        proxy = r.xray_test.proxy_test.value

        lines = [
            "╔══════════════════════════════════════════════════╗",
            "║              ANALYSIS DASHBOARD                    ║",
            "╚══════════════════════════════════════════════════╝",
            "",
            f"  Security Score  [{bar_filled}{bar_empty}]  {score}/100",
            f"  Potential Score : {r.security.potential_score}/100",
            "",
            "── Status Badges ──",
            f"  {tls_badge}  |  {reality_badge}  |  {cdn_badge}",
            f"  Validation    : {'✓ Valid' if r.validation.valid else '✗ Issues found'}",
            f"  Proxy Test    : {proxy}",
            "",
            "── Tunnel Route ──",
            f"  {t.route_display or 'N/A'}",
            "",
            "── Quick Stats ──",
            f"  Protocol      : {c.protocol.value}",
            f"  Transport     : {c.transport_type.value}",
            f"  TCP Connect   : {r.connectivity.tcp_connect.value} ({r.connectivity.tcp_latency_ms or '-'} ms)",
            f"  Hop Count     : {r.deployment.hop_count or r.traceroute.hop_count or 'N/A'}",
            f"  Top Deploy    : {r.deployment.guesses[0].name if r.deployment.guesses else 'N/A'}",
            "",
            "── Latency Benchmark ──",
        ]
        lb = r.connectivity.latency_benchmark
        if lb.samples:
            lines.append(f"  min={lb.min_ms}  avg={lb.avg_ms}  p95={lb.p95_ms}  max={lb.max_ms} ms  ({lb.samples} samples)")
        else:
            lines.append("  N/A")

        lines.extend(["", "── Top Recommendations ──"])
        for rec in r.security.recommendations[:4]:
            lines.append(f"  • {rec.title} (+{rec.score_impact})")

        self._write("Dashboard", "\n".join(lines))

    def _render_overview(self, r: AnalysisResult) -> None:
        c = r.config
        t = r.tunnel
        top_deploy = r.deployment.guesses[0] if r.deployment.guesses else None
        lines = [
            "── Tunnel Route ──",
            f"  {t.route_display or 'N/A'}",
            "",
            f"  Client (You)  : {format_country(t.client_country_code, t.client_country)}",
            f"  Client IP     : {t.client_ip or 'N/A'}",
            f"  Server        : {format_country(t.server_country_code, t.server_country)}",
            f"  Server IP     : {t.server_ip or 'N/A'}",
            "",
            f"  Protocol      : {c.protocol.value}",
            f"  Address       : {c.address}:{c.port}",
            f"  Transport     : {c.transport_type.value}",
            f"  Security Score: {r.security.score}/100",
            "",
            "── Validation ──",
        ]
        if r.validation.issues:
            for issue in r.validation.issues:
                icon = "✗" if issue.severity == "error" else "⚠" if issue.severity == "warning" else "ℹ"
                lines.append(f"  {icon} [{issue.severity.upper()}] {issue.message}")
        else:
            lines.append("  ✓ No issues")

        lines.extend([
            "",
            "── Connectivity ──",
            f"  DNS Resolve   : {r.connectivity.dns_resolve.value} ({r.connectivity.dns_latency_ms or '-'} ms)",
            f"  TCP Connect   : {r.connectivity.tcp_connect.value} ({r.connectivity.tcp_latency_ms or '-'} ms)",
            f"  TLS Handshake : {r.connectivity.tls_handshake.value}",
            f"  gRPC          : {r.connectivity.grpc_test.value}",
            f"  QUIC          : {r.connectivity.quic_test.value}",
            f"  REALITY       : {r.connectivity.reality_test.value}",
            f"  WebSocket     : {r.connectivity.websocket_upgrade.value}",
            f"  Packet Loss   : {r.connectivity.packet_loss_percent or '-'}%",
            "",
            "── Top Deployment ──",
        ])
        if top_deploy:
            lines.append(f"  {top_deploy.name}: {top_deploy.confidence * 100:.0f}% — {top_deploy.description}")
        self._write("Overview", "\n".join(lines))

    def _render_protocol(self, r: AnalysisResult) -> None:
        c = r.config
        fields = [
            ("Protocol", c.protocol.value),
            ("Address", c.address),
            ("Port", str(c.port)),
            ("UUID", self._mask(c.uuid)),
            ("Password", self._mask(c.password)),
            ("Encryption", c.encryption or "N/A"),
            ("Flow", c.flow or "N/A"),
            ("Security", c.security or "N/A"),
            ("TLS", str(c.tls)),
            ("Reality", str(c.reality)),
            ("Public Key", self._mask(c.public_key)),
            ("Short ID", self._mask(c.short_id)),
            ("SNI", c.sni or "N/A"),
            ("Host", c.host or "N/A"),
            ("ALPN", c.alpn or "N/A"),
            ("Path", c.path or "N/A"),
            ("Service Name", c.service_name or "N/A"),
            ("Transport Type", c.transport_type.value),
            ("Fingerprint", c.fingerprint or "N/A"),
            ("Allow Insecure", str(c.allow_insecure)),
        ]
        lines = ["Protocol Details", "=" * 50, ""]
        for name, val in fields:
            lines.append(f"  {name:<18}: {val}")
        self._write("Protocol Details", "\n".join(lines))

    def _render_dns(self, r: AnalysisResult) -> None:
        d = r.dns
        lines = [
            "DNS Analysis", "=" * 50, "",
            f"  Hostname     : {d.hostname}",
            f"  TTL          : {d.ttl or 'N/A'}",
            f"  DNSSEC       : {d.dnssec if d.dnssec is not None else 'N/A'}",
            "", "  A Records:",
        ]
        for rec in d.a_records or ["  (none)"]:
            lines.append(f"    • {rec}")
        lines.extend(["", "  AAAA Records:"])
        for rec in d.aaaa_records or ["  (none)"]:
            lines.append(f"    • {rec}")
        lines.extend(["", "  CNAME Records:"])
        for rec in d.cname_records or ["  (none)"]:
            lines.append(f"    • {rec}")
        lines.extend(["", "  MX Records:"])
        for rec in d.mx_records or ["  (none)"]:
            lines.append(f"    • {rec}")
        lines.extend(["", "  TXT Records:"])
        for rec in d.txt_records or ["  (none)"]:
            lines.append(f"    • {rec[:120]}")
        lines.extend(["", "  Reverse DNS:"])
        for rec in d.reverse_dns or ["  (none)"]:
            lines.append(f"    • {rec}")
        if d.doh_results:
            lines.extend(["", "  DoH Comparison:"])
            for provider, ips in d.doh_results.items():
                lines.append(f"    {provider}: {', '.join(ips)}")
        if d.errors:
            lines.extend(["", "  Errors:"])
            for err in d.errors:
                lines.append(f"    ⚠ {err}")
        self._write("DNS Analysis", "\n".join(lines))

    def _render_network(self, r: AnalysisResult) -> None:
        t = r.tunnel
        lines = [
            "Network Intelligence", "=" * 50, "",
            f"  Route         : {t.route_display}",
            f"  Hop Count     : {r.deployment.hop_count or r.traceroute.hop_count or 'N/A'}",
            "",
            "── Traceroute ──",
        ]
        if r.traceroute.hops:
            for hop in r.traceroute.hops[:20]:
                lines.append(f"  {hop.hop:>2}. {hop.ip or '*':<16} {hop.latency_ms or '-':>6} ms  {hop.hostname or ''}")
        else:
            lines.append("  N/A" + (f" ({r.traceroute.errors[0]})" if r.traceroute.errors else ""))

        lines.append("")
        for ip in r.network:
            lines.extend([
                f"  IP           : {ip.ip}",
                f"  Country      : {format_country(ip.country_code, ip.country)}",
                f"  ASN          : {ip.asn or 'N/A'}",
                f"  ISP          : {ip.isp or 'N/A'}",
                f"  Datacenter   : {ip.datacenter or 'N/A'}",
                f"  Reputation   : {ip.reputation_score}/100",
            ])
            if ip.cdn_detected:
                lines.append(f"  CDN          : {ip.cdn_detected} ({ip.cdn_confidence * 100:.0f}%)")
            lines.append("")
        self._write("Network Analysis", "\n".join(lines))

    def _render_tls(self, r: AnalysisResult) -> None:
        t = r.tls
        lines = [
            "TLS Analysis", "=" * 50, "",
            f"  Enabled           : {t.enabled}",
            f"  Version           : {t.version or 'N/A'}",
            f"  Cipher Suite      : {t.cipher_suite or 'N/A'}",
            f"  Certificate Subject: {t.certificate_subject or 'N/A'}",
            f"  Expiry            : {t.certificate_expiry or 'N/A'}",
            f"  Days Until Expiry : {t.days_until_expiry if t.days_until_expiry is not None else 'N/A'}",
            f"  SHA256 Fingerprint: {t.fingerprint_sha256 or 'N/A'}",
        ]
        self._write("TLS Analysis", "\n".join(lines))

    def _render_intelligence(self, r: AnalysisResult) -> None:
        lines = ["Threat Intelligence & Cert Transparency", "=" * 50, "", "── Threat Intel ──"]
        if r.threat_intel:
            for t in r.threat_intel:
                lines.extend([
                    f"  IP: {t.ip}",
                    f"    Reputation  : {t.reputation_score}/100",
                    f"    Datacenter  : {t.is_datacenter}",
                    f"    Residential : {t.is_residential}",
                ])
                for bl in t.blocklist_hits:
                    lines.append(f"    Blocklist   : {bl}")
                for note in t.notes:
                    lines.append(f"    • {note}")
                lines.append("")
        else:
            lines.append("  No data")

        ct = r.cert_transparency
        lines.extend(["── Certificate Transparency (crt.sh) ──", f"  Domain: {ct.domain}", f"  Total: {ct.total_count}"])
        for entry in ct.entries[:20]:
            lines.append(f"    • {entry.subdomain}")
        if ct.errors:
            lines.extend(["  Errors:"] + [f"    ⚠ {e}" for e in ct.errors])

        ta = r.tunnel_analysis
        lines.extend(["", "── Tunnel Type Detection ──", f"  Primary: {ta.primary_type} ({int(ta.primary_confidence * 100)}%)"])
        lines.append(f"  Traffic: {ta.traffic_flow}")
        for t in ta.detected_types:
            lines.append(f"  • {t.name} [{int(t.confidence * 100)}%] — {', '.join(t.evidence[:3])}")

        lines.extend(["", "── Generated Client Config ──", generate_client_config_json(r.config)])
        self._write("Intelligence", "\n".join(lines))

    def _render_xray(self, r: AnalysisResult) -> None:
        x = r.xray_test
        lines = [
            "Xray Core Test & Proxy Diagnostics", "=" * 50, "",
            f"  Xray Installed: {'Yes ✓' if r.xray_installed else 'No ✗'}",
            f"  Status        : {x.status.value}",
            f"  Proxy Test    : {x.proxy_test.value} ({x.proxy_latency_ms or '-'} ms via SOCKS5:{x.socks_port})",
            f"  Exit IP       : {x.exit_ip or 'N/A'} ({x.exit_country or '?'})",
            f"  Version       : {x.xray_version or 'N/A'}",
            f"  Summary       : {x.summary}",
            "",
            "── Site Reachability (via tunnel) ──",
        ]
        if x.site_reachability:
            for s in x.site_reachability:
                icon = "✓" if s.status.value == "Valid" else "✗" if s.status.value == "Invalid" else "⚠"
                lines.append(f"  [{icon}] {s.name:<18} {s.status.value:<8} {s.latency_ms or '-':>6} ms  {s.details[:60]}")
        else:
            lines.append("  (run with Xray installed + Real Proxy Test enabled)")

        st = x.speed_test
        lines.extend([
            "",
            "── Speed Test (1MB via tunnel) ──",
            f"  Status    : {st.status.value}",
            f"  Download  : {st.download_mbps or '-'} Mbps",
            f"  Duration  : {st.duration_sec or '-'} sec",
            f"  Bytes     : {st.bytes_downloaded or 0}",
        ])
        if st.error:
            lines.append(f"  Error     : {st.error}")

        lk = x.leak_check
        lines.extend([
            "",
            "── IP / DNS Leak Check ──",
            f"  Client IP     : {lk.client_ip or 'N/A'}",
            f"  Proxy Exit IP : {lk.proxy_exit_ip or 'N/A'} ({lk.proxy_exit_country or '?'}) colo={lk.proxy_exit_colo or '?'}",
            f"  IP Leak       : {'YES ⚠' if lk.ip_leak else 'No ✓'}",
            f"  Direct DNS A  : {', '.join(lk.direct_dns_ips) or 'N/A'}",
        ])
        for note in lk.notes:
            lines.append(f"    • {note}")

        plugins = r.raw_data.get("plugins", {})
        if plugins:
            lines.extend(["", "── Plugin Results ──"])
            for pname, pdata in plugins.items():
                lines.append(f"  [{pname}]")
                if isinstance(pdata, dict) and "formatted" in pdata:
                    lines.append(f"    Remark: {pdata['formatted']}")
                elif isinstance(pdata, list):
                    for item in pdata[:5]:
                        lines.append(f"    • {item}")

        lines.extend(["", "── Log Output ──", x.log_output or "(no process log — proxy diagnostics mode)"])
        if x.errors:
            lines.extend(["", "── Errors ──"] + x.errors)
        self._write("Xray Test", "\n".join(lines))

    def _render_security(self, r: AnalysisResult) -> None:
        s = r.security
        lines = [
            "Security Report", "=" * 50, "",
            f"  Score         : {s.score}/100",
            f"  Potential     : {s.potential_score}/100",
            "",
            "── Findings ──",
        ]
        for f in s.findings:
            icon = "✓" if f.passed else "✗"
            lines.append(f"  [{icon}] [{f.severity.upper()}] {f.title}: {f.description}")

        lines.extend(["", "── Recommendations ──"])
        for rec in s.recommendations:
            lines.append(f"  • {rec.title} (+{rec.score_impact}): {rec.description}")

        lines.extend(["", "── Deployment Detection ──"])
        for g in r.deployment.guesses:
            bar = "█" * int(g.confidence * 10) + "░" * (10 - int(g.confidence * 10))
            lines.append(f"  {g.name:<22} {g.confidence * 100:5.0f}% [{bar}]")

        if r.deployment.uncertain_fields:
            lines.extend(["", "── Uncertain ──"])
            for field in r.deployment.uncertain_fields:
                lines.append(f"  ✗ {field}")
        self._write("Security Report", "\n".join(lines))

    def _render_setup_guide(self, r: AnalysisResult) -> None:
        g = r.setup_guide
        ta = r.tunnel_analysis
        lines = [
            "Server Setup Guide (data-driven from analysis)",
            "=" * 50,
            "",
            f"Primary tunnel type: {ta.primary_type or g.detected_scenario} ({int(ta.primary_confidence * 100)}%)",
        ]
        if ta.traffic_flow:
            lines.append(f"Traffic flow: {ta.traffic_flow}")
        lines.extend([
            "",
            "── Summary ──",
            f"  {g.summary}",
            "",
            "── Compatible Panels ──",
        ])
        for p in g.recommended_panels:
            lines.append(f"  • {p}")

        for section in g.sections:
            lines.extend(["", f"── {section.title} ──"])
            for step in section.steps:
                lines.append(f"  • {step}")

        if g.checklist:
            lines.extend(["", "── Checklist (actual config values) ──"])
            for item in g.checklist:
                lines.append(f"  ☐ {item}")

        if g.tips:
            lines.extend(["", "── Warnings ──"])
            for tip in g.tips:
                lines.append(f"  ⚠ {tip}")

        self._write("Setup Guide", "\n".join(lines))

    def _render_reproduction(self, r: AnalysisResult) -> None:
        lines = ["Reproduction Guide", "=" * 50, "", "── Reproducible ──"]
        for item in r.reproduction.reproducible:
            val = self._mask(item.value) if item.field in ("UUID", "Password") else (item.value or "Yes")
            lines.append(f"  ✓ {item.field}: {val}")
        lines.extend(["", "── Not Reproducible ──"])
        for item in r.reproduction.not_reproducible:
            lines.append(f"  ✗ {item.field}: {item.reason or 'Unknown'}")
        self._write("Reproduction Guide", "\n".join(lines))

    def _render_raw(self, r: AnalysisResult) -> None:
        data = r.model_dump(mode="json")
        self._write("Raw Data", json.dumps(data, indent=2, ensure_ascii=False, default=str))

    def clear(self) -> None:
        for panel in self._panels.values():
            panel.clear()
