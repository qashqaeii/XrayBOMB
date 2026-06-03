"""Right status panel."""

from __future__ import annotations

from typing import Optional

import customtkinter as ctk

from backend.models import AnalysisResult, TestStatus
from utils.country import emoji_font_family, format_country
from utils.ui_theme import ACCENT, PANEL_BG, PANEL_BORDER, PANEL_PAD, PANEL_RADIUS, SECTION_DIVIDER, STATUS_WIDTH


class StatusPanel(ctk.CTkFrame):
    """Connection/DNS/TLS/Xray status indicators."""

    STATUS_COLORS = {
        TestStatus.VALID: "#00cc66",
        TestStatus.INVALID: "#ff4444",
        TestStatus.WARNING: "#ffaa00",
        TestStatus.PENDING: "#888888",
        TestStatus.SKIPPED: "#666666",
    }

    def __init__(self, master, **kwargs) -> None:
        width = kwargs.pop("width", STATUS_WIDTH)
        super().__init__(
            master,
            fg_color=PANEL_BG,
            corner_radius=PANEL_RADIUS,
            border_width=1,
            border_color=PANEL_BORDER,
            **kwargs,
        )

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=PANEL_PAD, pady=PANEL_PAD)
        inner = scroll

        self._wrap = max(180, width - PANEL_PAD * 2 - 16)

        ctk.CTkLabel(
            inner, text="Status", font=ctk.CTkFont(size=15, weight="bold"), anchor="w",
        ).pack(fill="x", pady=(0, 6))

        self.indicators: dict[str, ctk.CTkLabel] = {}
        for name in ("Connection", "DNS", "TLS", "Xray Test"):
            frame = ctk.CTkFrame(inner, fg_color="transparent")
            frame.pack(fill="x", pady=2)
            ctk.CTkLabel(frame, text=name, anchor="w").pack(side="left", fill="x", expand=True)
            lbl = ctk.CTkLabel(frame, text="—", width=72, anchor="e")
            lbl.pack(side="right")
            self.indicators[name] = lbl

        self._divider(inner)

        ctk.CTkLabel(
            inner, text="Tunnel Route", font=ctk.CTkFont(size=13, weight="bold"), anchor="w",
        ).pack(fill="x", pady=(4, 4))

        self._emoji_font = ctk.CTkFont(family=emoji_font_family(), size=13)
        self._emoji_font_sm = ctk.CTkFont(family=emoji_font_family(), size=11)

        self.tunnel_label = ctk.CTkLabel(
            inner, text="—", font=self._emoji_font, wraplength=self._wrap, justify="left", anchor="w",
        )
        self.tunnel_label.pack(fill="x")

        self.client_country_label = ctk.CTkLabel(
            inner, text="Client: —", font=self._emoji_font_sm, anchor="w",
        )
        self.client_country_label.pack(fill="x", pady=(4, 0))
        self.server_country_label = ctk.CTkLabel(
            inner, text="Server: —", font=self._emoji_font_sm, anchor="w",
        )
        self.server_country_label.pack(fill="x", pady=(2, 0))

        self.xray_warning = ctk.CTkLabel(
            inner,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#ffaa00",
            wraplength=self._wrap,
            justify="left",
            anchor="w",
        )

        self._divider(inner)

        score_box = ctk.CTkFrame(inner, fg_color="#12122a", corner_radius=8)
        score_box.pack(fill="x", pady=(4, 0))
        self._score_box = score_box

        ctk.CTkLabel(
            score_box, text="Security Score", font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(pady=(8, 0))
        self.score_label = ctk.CTkLabel(
            score_box, text="—/100", font=ctk.CTkFont(size=30, weight="bold"), text_color=ACCENT,
        )
        self.score_label.pack(pady=(2, 10))

        self._divider(inner)

        details = ctk.CTkFrame(inner, fg_color="transparent")
        details.pack(fill="x", pady=(4, 0))

        ctk.CTkLabel(details, text="Protocol", font=ctk.CTkFont(size=11), text_color="#8888aa").pack(anchor="w")
        self.protocol_label = ctk.CTkLabel(
            details, text="—", font=ctk.CTkFont(size=13, weight="bold"), anchor="w",
        )
        self.protocol_label.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(details, text="Transport", font=ctk.CTkFont(size=11), text_color="#8888aa").pack(anchor="w")
        self.transport_label = ctk.CTkLabel(details, text="—", anchor="w")
        self.transport_label.pack(fill="x")

    def _divider(self, parent) -> None:
        ctk.CTkFrame(parent, height=1, fg_color=SECTION_DIVIDER).pack(fill="x", pady=6)

    def _set_status(self, key: str, status: TestStatus) -> None:
        color = self.STATUS_COLORS.get(status, "#888888")
        display = status.value
        if key == "Xray Test" and status == TestStatus.SKIPPED:
            display = "Not Installed"
            color = "#ffaa00"
        self.indicators[key].configure(text=display, text_color=color)

    def update_result(self, result: Optional[AnalysisResult]) -> None:
        if not result:
            for lbl in self.indicators.values():
                lbl.configure(text="—", text_color="#888888")
            self.score_label.configure(text="—/100", text_color=ACCENT)
            self.protocol_label.configure(text="—")
            self.transport_label.configure(text="—")
            self.tunnel_label.configure(text="—")
            self.client_country_label.configure(text="Client: —")
            self.server_country_label.configure(text="Server: —")
            self.xray_warning.pack_forget()
            return

        c = result.config
        t = result.tunnel
        self._set_status("Connection", result.connectivity.tcp_connect)
        self._set_status("DNS", result.connectivity.dns_resolve)
        self._set_status("TLS", result.connectivity.tls_handshake)
        self._set_status("Xray Test", result.xray_test.status)

        self.tunnel_label.configure(text=t.route_display or "—")
        self.client_country_label.configure(
            text=f"Client: {format_country(t.client_country_code, t.client_country)}"
        )
        self.server_country_label.configure(
            text=f"Server: {format_country(t.server_country_code, t.server_country)}"
        )

        if not result.xray_installed:
            self.xray_warning.configure(text="⚠ Xray not installed\nClick Download Xray")
            self.xray_warning.pack(fill="x", pady=(6, 0), before=self._score_box)
        else:
            self.xray_warning.pack_forget()

        score = result.security.score
        color = "#00cc66" if score >= 80 else "#ffaa00" if score >= 50 else "#ff4444"
        self.score_label.configure(text=f"{score}/100", text_color=color)
        self.protocol_label.configure(text=c.protocol.value)
        self.transport_label.configure(text=c.transport_type.value)

    def reset(self) -> None:
        self.update_result(None)

    def set_xray_installed(self, installed: bool) -> None:
        if not installed:
            self.xray_warning.configure(text="⚠ Xray not installed\nClick Download Xray")
            self.xray_warning.pack(fill="x", pady=(6, 0), before=self._score_box)
        else:
            self.xray_warning.pack_forget()
