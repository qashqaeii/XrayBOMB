"""Live log panel with copy support."""

from __future__ import annotations

from datetime import datetime

import customtkinter as ctk

from gui.components.copyable_text import CopyableTextbox
from utils.ui_theme import BG_DARK, PANEL_BG, PANEL_BORDER, PANEL_PAD, PANEL_RADIUS


class LogPanel(ctk.CTkFrame):
    """Bottom live operation log — expands with window height."""

    def __init__(self, master, **kwargs) -> None:
        kwargs.pop("height", None)
        super().__init__(
            master,
            fg_color=PANEL_BG,
            corner_radius=PANEL_RADIUS,
            border_width=1,
            border_color=PANEL_BORDER,
            **kwargs,
        )

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=PANEL_PAD, pady=PANEL_PAD)

        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill="x", pady=(0, 6))
        ctk.CTkLabel(
            header, text="Live Log", font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(side="left")
        ctk.CTkButton(header, text="Clear", width=64, height=26, command=self.clear).pack(side="right")

        self._panel = CopyableTextbox(
            inner,
            show_toolbar=False,
            read_only=True,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_DARK,
            corner_radius=8,
        )
        self._panel.pack(fill="both", expand=True)

    def log(self, message: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self._panel.textbox.insert("end", f"[{ts}] {message}\n")
        self._panel.textbox.see("end")

    def clear(self) -> None:
        self._panel.clear()
