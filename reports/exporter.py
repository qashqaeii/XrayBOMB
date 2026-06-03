"""Report export module."""

from __future__ import annotations

import csv
import html
import json
import re
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional

from backend.models import AnalysisResult, BatchAnalysisResult
from utils.branding import developer_credit
from utils.helpers import mask_sensitive
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)


def _redact_result(result: AnalysisResult) -> AnalysisResult:
    if not get_settings().redact_secrets_export:
        return result
    data = result.model_dump()
    c = data.get("config", {})
    for key in ("uuid", "password", "public_key", "short_id"):
        if c.get(key):
            c[key] = mask_sensitive(c[key])
    return AnalysisResult.model_validate(data)


class ReportExporter:
    """Export analysis results to various formats."""

    def __init__(self, result: AnalysisResult) -> None:
        self.result = _redact_result(result)

    def to_json(self, indent: int = 2) -> str:
        return self.result.model_dump_json(indent=indent)

    def to_csv(self) -> str:
        r = self.result
        c = r.config
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["Field", "Value"])
        rows = [
            ("Protocol", c.protocol.value), ("Address", c.address), ("Port", c.port),
            ("Transport", c.transport_type.value), ("TLS", c.tls), ("Reality", c.reality),
            ("Security Score", r.security.score), ("Potential Score", r.security.potential_score),
            ("DNS A", ", ".join(r.dns.a_records)), ("Resolved IPs", ", ".join(r.dns.all_resolved_ips)),
            ("TCP", r.connectivity.tcp_connect.value), ("TLS Handshake", r.connectivity.tls_handshake.value),
            ("Proxy Test", r.xray_test.proxy_test.value), ("Xray Test", r.xray_test.status.value),
            ("CDN", r.deployment.cdn_type or ""), ("Hop Count", r.deployment.hop_count or ""),
            ("Route", r.tunnel.route_display), ("Analyzed At", r.analyzed_at.isoformat()),
        ]
        lb = r.connectivity.latency_benchmark
        if lb.samples:
            rows.extend([
                ("Latency Min", lb.min_ms), ("Latency Avg", lb.avg_ms),
                ("Latency P95", lb.p95_ms), ("Latency Max", lb.max_ms),
            ])
        writer.writerows(rows)
        return output.getvalue()

    def to_markdown(self) -> str:
        r = self.result
        c = r.config
        lines = [
            "# Xray Config Analysis Report",
            "",
            f"**Generated:** {r.analyzed_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"## Security Score: **{r.security.score}/100** (potential: {r.security.potential_score})",
            "",
            "## Tunnel Route",
            f"- {r.tunnel.route_display}",
            "",
            "## Overview",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Protocol | {c.protocol.value} |",
            f"| Address | {c.address}:{c.port} |",
            f"| Transport | {c.transport_type.value} |",
            f"| TLS | {'Yes' if c.tls else 'No'} |",
            f"| Reality | {'Yes' if c.reality else 'No'} |",
            "",
            "## Validation",
            "",
        ]
        for issue in r.validation.issues:
            lines.append(f"- [{issue.severity.upper()}] {issue.message}")

        lines.extend(["", "## DNS Analysis", ""])
        lines.extend([
            f"- A: {', '.join(r.dns.a_records) or 'N/A'}",
            f"- AAAA: {', '.join(r.dns.aaaa_records) or 'N/A'}",
            f"- CNAME: {', '.join(r.dns.cname_records) or 'N/A'}",
            f"- MX: {', '.join(r.dns.mx_records) or 'N/A'}",
            f"- TXT: {', '.join(r.dns.txt_records) or 'N/A'}",
            f"- DNSSEC: {r.dns.dnssec if r.dns.dnssec is not None else 'N/A'}",
        ])

        lines.extend(["", "## Connectivity", ""])
        conn = r.connectivity
        lines.extend([
            f"- DNS: {conn.dns_resolve.value} ({conn.dns_latency_ms or '-'} ms)",
            f"- TCP: {conn.tcp_connect.value} ({conn.tcp_latency_ms or '-'} ms)",
            f"- TLS: {conn.tls_handshake.value}",
            f"- gRPC: {conn.grpc_test.value}",
            f"- QUIC: {conn.quic_test.value}",
            f"- REALITY: {conn.reality_test.value}",
        ])
        lb = conn.latency_benchmark
        if lb.samples:
            lines.append(f"- Latency Benchmark: min={lb.min_ms} avg={lb.avg_ms} p95={lb.p95_ms} max={lb.max_ms} ms")

        lines.extend(["", "## Traceroute", ""])
        if r.traceroute.hops:
            for hop in r.traceroute.hops[:15]:
                lines.append(f"- Hop {hop.hop}: {hop.ip or '*'} {hop.latency_ms or '-'} ms")
        else:
            lines.append("- N/A")

        lines.extend(["", "## Threat Intelligence", ""])
        for t in r.threat_intel:
            lines.append(f"- {t.ip}: reputation={t.reputation_score}/100, DC={t.is_datacenter}")
            for note in t.notes:
                lines.append(f"  - {note}")

        lines.extend(["", "## Cert Transparency", ""])
        ct = r.cert_transparency
        lines.append(f"- Domain: {ct.domain}, entries: {ct.total_count}")
        for entry in ct.entries[:10]:
            lines.append(f"  - {entry.subdomain}")

        lines.extend(["", "## Security Findings", ""])
        for f in r.security.findings:
            icon = "PASS" if f.passed else "FAIL"
            lines.append(f"- [{icon}] [{f.severity}] {f.title}: {f.description}")

        lines.extend(["", "## Recommendations", ""])
        for rec in r.security.recommendations:
            lines.append(f"- **{rec.title}** (+{rec.score_impact}): {rec.description}")

        lines.extend(["", "## Deployment", ""])
        for g in r.deployment.guesses[:5]:
            lines.append(f"- {g.name}: {g.confidence * 100:.0f}%")

        lines.extend(["", "## Xray Test", ""])
        lines.append(f"- Status: {r.xray_test.status.value}")
        lines.append(f"- Proxy Test: {r.xray_test.proxy_test.value} ({r.xray_test.proxy_latency_ms or '-'} ms)")

        lines.extend(["", "---", "", f"*{developer_credit()} — Xray Config Analyzer Pro*"])
        return "\n".join(lines)

    def to_html(self) -> str:
        r = self.result
        c = r.config
        score_color = "#00ff88" if r.security.score >= 80 else "#ffaa00" if r.security.score >= 50 else "#ff4444"
        md = self.to_markdown()
        body_parts = []
        for line in md.split("\n"):
            if line.startswith("# "):
                body_parts.append(f"<h1>{html.escape(line[2:])}</h1>")
            elif line.startswith("## "):
                body_parts.append(f"<h2>{html.escape(line[3:])}</h2>")
            elif line.startswith("- "):
                body_parts.append(f"<li>{html.escape(line[2:])}</li>")
            elif line.startswith("|") and "---" not in line:
                cells = [html.escape(c.strip()) for c in line.split("|")[1:-1]]
                body_parts.append("<tr>" + "".join(f"<td>{c}</td>" for c in cells) + "</tr>")
            elif line.strip():
                body_parts.append(f"<p>{html.escape(line)}</p>")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Xray Analysis — {html.escape(c.address)}</title>
<style>
body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; padding: 2rem; max-width: 960px; margin: auto; }}
h1 {{ color: #00d4ff; }} h2 {{ color: #7b68ee; border-bottom: 1px solid #333; padding-bottom: 0.3rem; }}
.score {{ font-size: 2.5rem; color: {score_color}; font-weight: bold; margin: 1rem 0; }}
li {{ margin: 0.3rem 0; }} td, th {{ border: 1px solid #444; padding: 6px 10px; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
.badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; background: #333; margin: 2px; }}
</style>
</head>
<body>
<div class="score">Security Score: {r.security.score}/100</div>
<div class="badge">Protocol: {html.escape(c.protocol.value)}</div>
<div class="badge">Route: {html.escape(r.tunnel.route_display)}</div>
{"".join(body_parts)}
<hr><p><small>Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} — Xray Config Analyzer Pro<br>{html.escape(developer_credit())}</small></p>
</body>
</html>"""

    def to_pdf(self, output_path: Path) -> bool:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

            r = self.result
            c = r.config
            doc = SimpleDocTemplate(str(output_path), pagesize=A4, topMargin=1.5 * cm)
            styles = getSampleStyleSheet()
            title_style = ParagraphStyle("Title2", parent=styles["Title"], textColor=colors.HexColor("#0066cc"))
            story = []

            story.append(Paragraph("Xray Config Analysis Report", title_style))
            story.append(Paragraph(f"Score: {r.security.score}/100 (potential {r.security.potential_score})", styles["Heading2"]))
            story.append(Paragraph(f"{c.protocol.value} — {c.address}:{c.port}", styles["Normal"]))
            story.append(Paragraph(f"Route: {r.tunnel.route_display}", styles["Normal"]))
            story.append(Spacer(1, 12))

            overview = [
                ["Field", "Value"],
                ["Transport", c.transport_type.value],
                ["TLS", "Yes" if c.tls else "No"],
                ["CDN", r.deployment.cdn_type or "N/A"],
                ["TCP", r.connectivity.tcp_connect.value],
                ["Proxy Test", r.xray_test.proxy_test.value],
            ]
            t = Table(overview, colWidths=[120, 300])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333366")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

            story.append(Paragraph("Security Findings", styles["Heading2"]))
            for f in r.security.findings:
                status = "PASS" if f.passed else "FAIL"
                story.append(Paragraph(f"[{status}] {f.title}: {f.description}", styles["Normal"]))

            story.append(Spacer(1, 12))
            story.append(Paragraph("Recommendations", styles["Heading2"]))
            for rec in r.security.recommendations:
                story.append(Paragraph(f"+{rec.score_impact} {rec.title}: {rec.description}", styles["Normal"]))

            story.append(Spacer(1, 24))
            story.append(Paragraph(developer_credit(), styles["Normal"]))

            doc.build(story)
            return True
        except ImportError:
            output_path.with_suffix(".html").write_text(self.to_html(), encoding="utf-8")
            return False

    def save(self, path: Path, fmt: str) -> Path:
        fmt = fmt.lower()
        if fmt == "json":
            path.write_text(self.to_json(), encoding="utf-8")
        elif fmt == "csv":
            path.write_text(self.to_csv(), encoding="utf-8")
        elif fmt in ("md", "markdown"):
            path.write_text(self.to_markdown(), encoding="utf-8")
        elif fmt == "html":
            path.write_text(self.to_html(), encoding="utf-8")
        elif fmt == "pdf":
            self.to_pdf(path)
        else:
            raise ValueError(f"Unsupported format: {fmt}")
        return path


class BatchReportExporter:
    """Export batch analysis results."""

    def __init__(self, batch: BatchAnalysisResult) -> None:
        self.batch = batch

    def to_csv(self) -> str:
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(["#", "Protocol", "Address", "Port", "Score", "TLS", "CDN", "TCP", "Proxy"])
        for i, r in enumerate(self.batch.results, 1):
            c = r.config
            writer.writerow([
                i, c.protocol.value, c.address, c.port, r.security.score,
                c.tls, r.deployment.cdn_type or "", r.connectivity.tcp_connect.value,
                r.xray_test.proxy_test.value,
            ])
        return output.getvalue()

    def save(self, path: Path, fmt: str) -> Path:
        if fmt == "csv":
            path.write_text(self.to_csv(), encoding="utf-8")
        elif fmt == "json":
            path.write_text(self.batch.model_dump_json(indent=2), encoding="utf-8")
        elif len(self.batch.results) == 1:
            ReportExporter(self.batch.results[0]).save(path, fmt)
        else:
            path.write_text(self.to_csv(), encoding="utf-8")
        return path
