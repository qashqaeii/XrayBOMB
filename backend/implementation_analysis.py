"""Architecture-compatible reconstruction guide (not server config discovery)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from backend.models import AnalysisResult, TestStatus


class ArchitectureScenario(BaseModel):
    name: str
    confidence_note: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    unknowns: list[str] = Field(default_factory=list)
    suggested_followup_tests: list[str] = Field(default_factory=list)


class ImplementationAnalysisReport(BaseModel):
    title: str = "معماری سازگار با مشاهدات"
    client_effective_settings: list[str] = Field(default_factory=list)
    entry_point: str = ""
    entry_network_owner: str = ""
    cdn_edge_evidence: list[str] = Field(default_factory=list)
    transport_handshake: str = ""
    config_verified_e2e: str = ""
    observed_egress_ip: str = ""
    egress_vs_entry: str = ""
    scenarios: list[ArchitectureScenario] = Field(default_factory=list)
    server_side_questions: list[str] = Field(default_factory=list)
    client_side_limitations: list[str] = Field(default_factory=list)
    reconstruction_steps: list[str] = Field(default_factory=list)


def build_implementation_analysis(result: AnalysisResult) -> ImplementationAnalysisReport:
    c = result.config
    report = ImplementationAnalysisReport()

    report.client_effective_settings = [
        f"protocol={c.protocol.value} transport={c.transport_type.value}",
        f"security={'REALITY' if c.reality else ('TLS' if c.tls else 'none')}",
        f"address={c.address}:{c.port}",
        f"sni={c.sni or '(default/address)'} host={c.host or '(none)'} path={c.path or '/'}",
        f"flow={c.flow or '(none)'} fingerprint={c.fingerprint or '(default)'}",
    ]
    if c.remark:
        report.client_effective_settings.append(f"remark (untrusted metadata)={c.remark[:80]}")

    if result.network:
        n0 = result.network[0]
        report.entry_point = f"{c.address}:{c.port} → {n0.ip}"
        report.entry_network_owner = f"{n0.organization or n0.isp or '?'} ({n0.asn or '?'})"
        if n0.cdn_detected:
            report.cdn_edge_evidence.append(f"CDN hint on resolved IP: {n0.cdn_detected} ({n0.cdn_confidence:.0%})")
    else:
        report.entry_point = f"{c.address}:{c.port}"
        report.entry_network_owner = "Unknown (no resolved IP intelligence)"

    if result.connectivity.http_cdn_detected:
        report.cdn_edge_evidence.append(f"HTTP probe CDN hint: {result.connectivity.http_cdn_detected}")

    ws = result.connectivity.websocket_upgrade
    tls = result.connectivity.tls_handshake
    report.transport_handshake = (
        f"TCP={result.connectivity.tcp_connect.value} TLS={tls.value} WS={ws.value}"
    )
    if result.connectivity.websocket_upgrade_note:
        report.transport_handshake += f" — {result.connectivity.websocket_upgrade_note}"

    xt = result.xray_test
    if xt.status == TestStatus.VALID:
        report.config_verified_e2e = "این کانفیگ با xray-core محلی و SOCKS اختصاصی به اینترنت رسید."
    elif xt.status == TestStatus.SKIPPED:
        report.config_verified_e2e = "تست end-to-end اجرا نشد (xray-core نصب نیست یا غیرفعال)."
    else:
        report.config_verified_e2e = f"تست end-to-end ناموفق/نامطمئن: {xt.summary or xt.status.value}"

    exit_ip = xt.exit_ip or (xt.leak_check.proxy_exit_ip if xt.leak_check else None)
    report.observed_egress_ip = exit_ip or "Not observed"
    lc = xt.leak_check
    if lc and lc.exit_ip_same_observed is True:
        report.egress_vs_entry = (
            "IP خروجی با IP پایهٔ مشاهده‌شده یکسان است — علت قطعی نشت نیست "
            "(VPN فعال، مسیر مشترک، یا آلودگی آزمایش)."
        )
    elif lc and lc.exit_ip_same_observed is False:
        report.egress_vs_entry = "IP خروجی با IP پایهٔ مشاهده‌شده متفاوت است."
    else:
        report.egress_vs_entry = "مقایسهٔ IP پایه/خروجی انجام نشد یا نامطمئن است."

    primary = result.tunnel_analysis.primary_type or "Unknown"
    top_evidence: list[str] = []
    if result.tunnel_analysis.detected_types:
        top_evidence = list(result.tunnel_analysis.detected_types[0].evidence[:4])
    report.scenarios.append(ArchitectureScenario(
        name=primary,
        confidence_note=result.tunnel_analysis.primary_confidence_level.value,
        supporting_evidence=top_evidence,
        unknowns=list(result.deployment.uncertain_fields[:6]),
        suggested_followup_tests=[
            "تست با VPN خاموش برای baseline تمیز",
            "تست end-to-end پس از نصب xray-core",
            "در صورت مالکیت سرور: جمع‌آوری read-only از SSH",
        ],
    ))

    report.server_side_questions = [
        "Inbound واقعی روی سرور (پورت/پروتکل) چیست؟",
        "آیا Nginx/Caddy/HAProxy جلوی Xray است؟",
        "آیا CDN فقط edge است یا origin جدا دارد؟",
        "تنظیمات REALITY (dest/serverNames) چیست؟",
    ]
    report.client_side_limitations = [
        "از لینک کلاینت نمی‌توان قطعی فهمید چند لایه relay، FRP، یا WireGuard پشت CDN وجود دارد.",
        "هدر HTTP و Server قابل جعل‌اند؛ غیاب reverse proxy را ثابت نمی‌کند.",
        "Probe بیرونی ≠ handshake دقیق Xray-core (پارامترهای متفاوت).",
    ]
    report.reconstruction_steps = [
        "۱) کلاینت با همان transport/security به address:port وصل شود.",
        "۲) SNI/Host/path مطابق کانفیگ تنظیم شود.",
        "۳) در صورت CDN، origin جدا از edge در نظر گرفته شود مگر SSH/management تأیید کند.",
    ]
    if result.reproduction.reproducible:
        for item in result.reproduction.reproducible[:5]:
            report.reconstruction_steps.append(f"• {item.field}: {item.value or '—'}")

    return report
