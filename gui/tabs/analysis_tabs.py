"""All analysis tab views."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Optional

import customtkinter as ctk

from backend.config_generator import generate_client_config_json
from backend.config_optimizer import apply_optimization_to_config
from backend.architecture_diagnostics import format_architecture_diagnostics_text
from backend.result_summary import _format_edge_route, _get_exit_intel, build_result_summary
from backend.stealth_assessment import format_risk_factors, format_score, score_bar
from backend.e2e_validity import evaluate_xray_test_result
from backend.models import AnalysisResult
from gui.components.copyable_text import CopyableTextbox
from gui.components.two_row_tabs import TwoRowTabBar
from utils.country import format_country
from utils.helpers import mask_sensitive
from utils.settings import get_settings
from utils.ui_theme import BG_DARK, monospace_font_family

_COPY_ALL_EXCLUDED_TABS = frozenset({"Raw Data"})


class AnalysisTabs(ctk.CTkFrame):
    """Tabbed view for all analysis sections (two-row tab bar)."""

    def __init__(
        self,
        master,
        on_copy_all_done: Callable[[bool], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._result: Optional[AnalysisResult] = None
        self._on_copy_all_done = on_copy_all_done

        self._tab_names = [
            "Dashboard", "Result", "Overview", "Best Config", "Protocol Details", "DNS Analysis", "Network Analysis",
            "TLS Analysis", "Intelligence", "Xray Test", "Architecture Diagnostics",
            "Connection Architecture", "Security Report",
            "Setup Guide", "How to Run", "Reproduction Guide", "Raw Data",
        ]
        self._panels: dict[str, CopyableTextbox] = {}

        self._tab_bar = TwoRowTabBar(self, self._tab_names, on_copy_all=self._handle_copy_all_tabs)
        self._tab_bar.pack(fill="both", expand=True)

        for name in self._tab_names:
            panel = CopyableTextbox(
                self._tab_bar.frame(name),
                show_toolbar=True,
                read_only=True,
                font=ctk.CTkFont(family=monospace_font_family(), size=12),
                wrap="word",
                fg_color=BG_DARK,
            )
            panel.pack(fill="both", expand=True, padx=8, pady=(0, 8))
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

    def get_all_tabs_text(self) -> str:
        """Concatenate non-empty tab contents with section headers (excludes Raw Data)."""
        sections: list[str] = []
        divider = "═" * 62
        for name in self._tab_names:
            if name in _COPY_ALL_EXCLUDED_TABS:
                continue
            text = self._panels[name].get_text().strip()
            if not text:
                continue
            sections.append(f"{divider}\n  {name}\n{divider}\n\n{text}")
        return "\n\n".join(sections)

    def copy_all_tabs(self) -> bool:
        """Copy every tab's text to the system clipboard."""
        content = self.get_all_tabs_text()
        if not content:
            return False
        self.clipboard_clear()
        self.clipboard_append(content)
        self.update_idletasks()
        return True

    def _handle_copy_all_tabs(self) -> None:
        ok = self.copy_all_tabs()
        if self._on_copy_all_done:
            self._on_copy_all_done(ok)

    def update_result(self, result: AnalysisResult) -> None:
        self._result = result
        self._render_dashboard(result)
        self._render_result(result)
        self._render_overview(result)
        self._render_best_config(result)
        self._render_protocol(result)
        self._render_dns(result)
        self._render_network(result)
        self._render_tls(result)
        self._render_intelligence(result)
        self._render_xray(result)
        self._render_architecture_diagnostics(result)
        self._render_connection_architecture(result)
        self._render_security(result)
        self._render_setup_guide(result)
        self._render_how_to_run(result)
        self._render_reproduction(result)
        self._render_raw(result)

    def _format_route_display(self, r: AnalysisResult) -> str:
        """Edge route + origin egress (exit IP intelligence when available)."""
        parts = [_format_edge_route(r)]
        exit_intel = _get_exit_intel(r)
        if exit_intel:
            org = f" ({exit_intel.organization})" if exit_intel.organization else ""
            cc = exit_intel.country_code or exit_intel.country or "?"
            parts.append(f"Origin egress: {exit_intel.ip} ({cc}){org}")
        else:
            parts.append("Origin egress: N/A (run Xray live test)")
        return " | ".join(parts)

    def _render_dashboard(self, r: AnalysisResult) -> None:
        c = r.config
        t = r.tunnel
        score = r.security.score
        bar_filled = "█" * (score // 10)
        bar_empty = "░" * (10 - score // 10)
        tls_badge = "✓ TLS" if c.tls else "✗ No TLS"
        reality_badge = "✓ REALITY" if c.reality else "○ No Reality"
        cdn_badge = f"CDN: {r.deployment.cdn_type}" if r.deployment.cdn_type else "No CDN"
        e2e = evaluate_xray_test_result(r.xray_test)
        proxy = r.xray_test.proxy_test.value
        e2e_line = "✓ Internet E2E verified (this run)" if e2e.internet_verified else f"○ E2E not verified ({e2e.stage})"

        dpi, cam, origin = r.dpi, r.camouflage, r.origin_exposure
        lines = [
            "╔══════════════════════════════════════════════════╗",
            "║              ANALYSIS DASHBOARD                    ║",
            "╚══════════════════════════════════════════════════╝",
            "",
            f"  Security Score  [{bar_filled}{bar_empty}]  {score}/100",
            f"  Potential Score : {r.security.potential_score}/100",
            f"  Iran Score      : {r.optimization.iran_score}/100  (Grade {r.optimization.grade})",
            f"  Sell Readiness  : {r.optimization.sell_readiness}%",
            "",
            "── Stealth & Exposure (observed signals only) ──",
            f"  DPI Resistance    [{score_bar(dpi.score)}]  {format_score(dpi.score)}  ({dpi.detection_risk} risk)",
            f"  Traffic Camouflage[{score_bar(cam.score)}]  {format_score(cam.score)}  ({cam.naturalness})",
            f"  Origin Exposure   [{score_bar(origin.risk_score)}]  {format_score(origin.risk_score)}  ({origin.exposure_level})",
            f"  Confidence        : {r.confidence_calibration.summary or 'N/A'}",
            "",
            "── Status Badges ──",
            f"  {tls_badge}  |  {reality_badge}  |  {cdn_badge}",
            f"  Validation    : {'✓ Valid' if r.validation.valid else '✗ Issues found'}",
            f"  Proxy Probe   : {proxy}",
            f"  Internet E2E  : {e2e_line}",
            "",
            "── Tunnel Route ──",
            f"  {self._format_route_display(r)}",
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

        lines.extend(["", "── Iran Optimizer (P1 first) ──", f"  {r.optimization.verdict}"])
        for act in r.optimization.actions[:3]:
            lines.append(f"  [P{act.priority_rank}] {act.title}")

        self._write("Dashboard", "\n".join(lines))

    def _render_result(self, r: AnalysisResult) -> None:
        self._write("Result", build_result_summary(r))

    def _render_best_config(self, r: AnalysisResult) -> None:
        o = r.optimization
        lines = [
            "Best Config Blueprint — Iran market (filtering / DPI context)",
            "=" * 55,
            "",
            f"  DPI resistance           : {format_score(r.dpi.score)}  ({r.dpi.detection_risk} detection risk)",
            f"  Traffic camouflage       : {format_score(r.camouflage.score)}  ({r.camouflage.naturalness})",
            f"  Origin exposure          : {format_score(r.origin_exposure.risk_score)}  ({r.origin_exposure.exposure_level})",
            "",
            f"  Iran score (anti-filter) : {o.iran_score}/100  |  Grade: {o.grade}",
            f"  Sell readiness         : {o.sell_readiness}%",
            f"  Verdict                : {o.verdict}",
            "",
            "── Ideal stack ──",
            f"  {o.ideal_stack_summary}",
            "",
            "── Actions by priority (P1 = critical) ──",
        ]
        for act in o.actions:
            lines.append(f"  [P{act.priority_rank}|{act.priority.value}] {act.title} (+{act.score_gain})")
            lines.append(f"      {act.description}")
            if act.current_value or act.suggested_value:
                lines.append(f"      Current: {act.current_value or '—'}  →  Suggested: {act.suggested_value or '—'}")
            lines.append("")

        if o.ip_rankings:
            lines.extend(["── IP ranking (best first) ──"])
            for i, node in enumerate(o.ip_rankings, 1):
                bl = f" ⚠{','.join(node.blocklist_hits)}" if node.blocklist_hits else ""
                lines.append(
                    f"  {i}. {node.ip}  score={node.score}  rep={node.reputation}"
                    f"  {node.country or ''}{bl}"
                )
                for n in node.notes[:2]:
                    lines.append(f"      • {n}")
            if o.best_ip:
                lines.append(f"  → Use {o.best_ip} in DNS/Origin")
            lines.append("")

        bp = o.blueprint
        lines.extend([
            "── Client blueprint ──",
            f"  Protocol   : {bp.protocol}",
            f"  Address    : {bp.address}",
            f"  Port       : {bp.port}",
            f"  Transport  : {bp.transport}",
            f"  Security   : {bp.security}",
            f"  Flow       : {bp.flow or '—'}",
            f"  SNI        : {bp.sni or '—'}",
            f"  Host       : {bp.host or '—'}",
            f"  Path       : {bp.path or '—'}",
            f"  Fingerprint: {bp.fingerprint or '—'}",
            f"  ALPN       : {bp.alpn or '—'}",
        ])
        for note in bp.notes:
            lines.append(f"  ⚠ {note}")

        if o.suggested_share_link:
            lines.extend(["", "── Suggested VLESS link ──", o.suggested_share_link])

        lines.extend(["", "── Server setup recipe ──"])
        for step in o.server_recipe:
            lines.append(f"  {step}")

        lines.extend(["", "── Delivery checklist ──"])
        for item in o.delivery_checklist:
            lines.append(f"  {item}")

        lines.extend([
            "",
            "── Support message (copy-paste) ──",
            o.support_message,
            "",
            "── Optimized client JSON ──",
            generate_client_config_json(apply_optimization_to_config(r.config)),
        ])
        self._write("Best Config", "\n".join(lines))

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
            "── Stealth Snapshot ──",
            f"  DPI Resistance     : {format_score(r.dpi.score)}  ({r.dpi.detection_risk} detection risk)",
            f"  Traffic Camouflage : {format_score(r.camouflage.score)}  ({r.camouflage.naturalness})",
            f"  Origin Exposure    : {format_score(r.origin_exposure.risk_score)}  ({r.origin_exposure.exposure_level})",
            f"  Inferred Origin IP : {r.origin_exposure.inferred_origin_ip or 'N/A'}",
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
        lines.extend(["", "  NS Records:"])
        for rec in d.ns_records or ["  (none)"]:
            lines.append(f"    • {rec}")
        if d.dns_provider:
            lines.append(f"  DNS Provider : {d.dns_provider} ({d.dns_provider_confidence:.0%} heuristic)")
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
            f"  Route         : {self._format_route_display(r)}",
            f"  Hop Count     : {r.deployment.hop_count or r.traceroute.hop_count or 'N/A'}",
            f"  Origin risk   : {format_score(r.origin_exposure.risk_score)} ({r.origin_exposure.exposure_level})"
            f"  — {r.origin_exposure.inferred_origin_ip or 'N/A'}",
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
        lines = [
            "Threat Intelligence & Stealth Analysis", "=" * 50, "",
            "── DPI Resistance Score ──",
            f"  {format_score(r.dpi.score)}  Grade {r.dpi.grade}  |  {r.dpi.detection_risk} detection risk",
            f"  {r.dpi.summary}",
            "",
        ]
        lines.extend(format_risk_factors(r.dpi.factors, limit=8))
        lines.extend([
            "",
            "── Traffic Camouflage Score ──",
            f"  {format_score(r.camouflage.score)}  Grade {r.camouflage.grade}  |  {r.camouflage.naturalness}",
            f"  {r.camouflage.summary}",
            "",
        ])
        lines.extend(format_risk_factors(r.camouflage.layers, limit=8))
        lines.extend([
            "",
            "── Origin Exposure Risk ──",
            f"  {format_score(r.origin_exposure.risk_score)}  Level: {r.origin_exposure.exposure_level}",
            f"  Inferred origin: {r.origin_exposure.inferred_origin_ip or 'N/A'}",
            f"  {r.origin_exposure.summary}",
            "",
        ])
        lines.extend(format_risk_factors(r.origin_exposure.factors, limit=8))
        lines.extend([
            "",
            "── Confidence Calibration ──",
            f"  {r.confidence_calibration.summary}",
            "",
        ])
        for ins in r.confidence_calibration.insights[:10]:
            lines.append(f"  [{ins.confidence.value}] {ins.category}: {ins.title}")
            if ins.evidence:
                lines.append(f"      Evidence: {'; '.join(ins.evidence[:2])}")
        lines.extend(["", "── Threat Intel ──"])
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
        plvl = ta.primary_confidence_level.value if ta.primary_confidence_level else "Weak Evidence"
        lines.extend([
            "",
            "── Tunnel Type Detection ──",
            f"  Primary: {ta.primary_type} [{plvl}] ({int(ta.primary_confidence * 100)}%)",
        ])
        lines.append(f"  Traffic: {ta.traffic_flow}")
        for t in ta.detected_types:
            lvl = t.confidence_level.value if t.confidence_level else "Weak Evidence"
            cal = t.calibrated_confidence or t.confidence
            lines.append(f"  • [{lvl}] {t.name} [{int(cal * 100)}%] — {', '.join(t.evidence[:3])}")

        lines.extend(["", "── Generated Client Config ──", generate_client_config_json(r.config)])
        self._write("Intelligence", "\n".join(lines))

    def _render_xray(self, r: AnalysisResult) -> None:
        x = r.xray_test
        lines = [
            "Xray Core Test & Proxy Diagnostics", "=" * 50, "",
            f"  Xray Installed: {'Yes ✓' if r.xray_installed else 'No ✗'}",
            f"  Status        : {x.status.value}",
            f"  Run ID        : {x.run_id or 'N/A'}",
            f"  Proxy Probe   : {x.proxy_test.value} ({x.proxy_latency_ms or '-'} ms)",
            f"  Internet E2E  : {'Verified' if x.internet_e2e_verified else 'Not verified'}",
            f"  SOCKS         : {x.socks_host}:{x.socks_port} (per-run auth)",
            f"  Config -test  : {x.config_validation.value}",
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
            f"  IP Leak       : {('Unknown' if lk.ip_leak is None else ('YES ⚠' if lk.ip_leak else 'No ✓'))}",
            f"  Baseline      : {lk.baseline_status} ({len(lk.baseline_samples)} samples)",
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

    def _render_architecture_diagnostics(self, r: AnalysisResult) -> None:
        self._write("Architecture Diagnostics", format_architecture_diagnostics_text(r))

    def _render_connection_architecture(self, r: AnalysisResult) -> None:
        impl = r.implementation_analysis or {}
        lines = [
            impl.get("title", "معماری سازگار با مشاهدات"),
            "=" * 50,
            "",
            "── Effective client (Xray builder rules) ──",
        ]
        for row in impl.get("client_effective_settings", []):
            lines.append(f"  • {row}")
        lines.extend([
            "",
            f"  Entry           : {impl.get('entry_point', '')}",
            f"  Peer observed   : {impl.get('entry_peer_observed', '')}",
            f"  E2E             : {impl.get('xray_e2e', '')}",
            f"  External WS     : {impl.get('external_ws_probe', '')}",
            f"  Baseline vs exit: {impl.get('baseline_vs_exit', '')}",
            f"  Entry vs exit   : {impl.get('entry_vs_exit', '')}",
            "",
            "── Scenarios (compatible architecture, not proven server config) ──",
        ])
        for sc in impl.get("scenarios", []):
            lines.append(f"  ▶ {sc.get('name', '?')} [{sc.get('confidence_note', '')}]")
            for e in sc.get("supporting_evidence", [])[:4]:
                lines.append(f"      + {e}")
            for e in sc.get("contradicting_evidence", [])[:3]:
                lines.append(f"      − {e}")
            for u in sc.get("unknowns", [])[:3]:
                lines.append(f"      ? {u}")
            for f in sc.get("suggested_followup_checks", [])[:2]:
                lines.append(f"      → {f}")
            lines.append("")
        lines.append("── Reconstruction (similar stack, not copied server) ──")
        for step in impl.get("reconstruction_steps", []):
            lines.append(f"  {step}")
        for lim in impl.get("client_side_limitations", []):
            lines.append(f"  ‣ {lim}")
        self._write("Connection Architecture", "\n".join(lines))

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

        dpi, cam, origin = r.dpi, r.camouflage, r.origin_exposure
        lines.extend([
            "",
            "── DPI Resistance Score ──",
            f"  [{score_bar(dpi.score)}]  {format_score(dpi.score)}  Grade {dpi.grade}  ({dpi.detection_risk} risk)",
            f"  {dpi.summary}",
        ])
        lines.extend(format_risk_factors(dpi.factors, limit=6))
        if dpi.recommendations:
            lines.extend(["", "  DPI recommendations:"])
            for rec in dpi.recommendations:
                lines.append(f"    • {rec}")

        lines.extend([
            "",
            "── Traffic Camouflage Score ──",
            f"  [{score_bar(cam.score)}]  {format_score(cam.score)}  Grade {cam.grade}  ({cam.naturalness})",
            f"  {cam.summary}",
        ])
        lines.extend(format_risk_factors(cam.layers, limit=6))
        if cam.recommendations:
            lines.extend(["", "  Camouflage recommendations:"])
            for rec in cam.recommendations:
                lines.append(f"    • {rec}")

        lines.extend([
            "",
            "── Origin Exposure Risk ──",
            f"  [{score_bar(origin.risk_score)}]  {origin.risk_score}/100  ({origin.exposure_level})",
            f"  Inferred origin IP: {origin.inferred_origin_ip or 'N/A'}",
            f"  {origin.summary}",
        ])
        lines.extend(format_risk_factors(origin.factors, limit=6))
        if origin.recommendations:
            lines.extend(["", "  Origin recommendations:"])
            for rec in origin.recommendations:
                lines.append(f"    • {rec}")

        lines.extend([
            "",
            "── Confidence Calibration ──",
            f"  {r.confidence_calibration.summary}",
        ])
        for ins in r.confidence_calibration.insights[:8]:
            lines.append(
                f"  [{ins.confidence.value}] {ins.title}"
                f"  (raw {ins.raw_confidence * 100:.0f}% → cal {ins.calibrated_confidence * 100:.0f}%)"
            )

        lines.extend(["", "── Deployment Detection ──"])
        for g in r.deployment.guesses:
            conf = g.calibrated_confidence or g.confidence
            bar = "█" * int(conf * 10) + "░" * (10 - int(conf * 10))
            level = g.confidence_level.value if hasattr(g.confidence_level, "value") else str(g.confidence_level)
            lines.append(f"  [{level}] {g.name:<20} {conf * 100:5.0f}% [{bar}]")

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

    def _render_how_to_run(self, r: AnalysisResult) -> None:
        g = r.setup_guide
        if g.how_to_run_text:
            self._write("How to Run", g.how_to_run_text)
            return
        lines = [
            "How to Run — Implementation Guide",
            "=" * 50,
            "",
            "Step-by-step guide is not available for this config.",
            "Run a full analysis first or paste a valid share link.",
        ]
        self._write("How to Run", "\n".join(lines))

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
