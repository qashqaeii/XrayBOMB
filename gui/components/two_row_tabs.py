"""Compact tab bar — equal-width tabs that fit the panel width."""

from __future__ import annotations

from collections.abc import Callable

import customtkinter as ctk

from utils.ui_theme import ACCENT, ACCENT_BTN, ACCENT_BTN_HOVER, PANEL_BG, PANEL_BORDER, PANEL_RADIUS, TEXT_MUTED

_TAB_ROWS: tuple[list[str], ...] = (
    [
        "Dashboard", "Result", "Overview", "Best Config",
        "Protocol Details", "DNS Analysis", "Network Analysis",
    ],
    [
        "TLS Analysis", "Intelligence", "Xray Test", "Security Report",
        "Setup Guide", "How to Run", "Reproduction Guide", "Raw Data",
    ],
)

_TAB_LABELS: dict[str, str] = {
    "Dashboard": "Dash",
    "Result": "Result",
    "Overview": "Overview",
    "Best Config": "Best",
    "Protocol Details": "Protocol",
    "DNS Analysis": "DNS",
    "Network Analysis": "Network",
    "TLS Analysis": "TLS",
    "Intelligence": "Intel",
    "Xray Test": "Xray",
    "Security Report": "Security",
    "Setup Guide": "Setup",
    "How to Run": "Run",
    "Reproduction Guide": "Repro",
    "Raw Data": "Raw",
}


class TwoRowTabBar(ctk.CTkFrame):
    """Two-row tab selector with equal-width buttons and a content area below."""

    def __init__(
        self,
        master,
        tab_names: list[str],
        on_copy_all: Callable[[], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._buttons: dict[str, ctk.CTkButton] = {}
        self._content_frames: dict[str, ctk.CTkFrame] = {}
        self._active: str | None = None

        bar = ctk.CTkFrame(
            self,
            fg_color=PANEL_BG,
            corner_radius=PANEL_RADIUS,
            border_width=1,
            border_color=PANEL_BORDER,
        )
        bar.pack(fill="x", pady=(0, 6))

        inner_bar = ctk.CTkFrame(bar, fg_color="transparent")
        inner_bar.pack(fill="x", padx=4, pady=4)

        if on_copy_all is not None:
            actions = ctk.CTkFrame(inner_bar, fg_color="transparent")
            actions.pack(fill="x", pady=(0, 4))
            ctk.CTkButton(
                actions,
                text="Copy All Tabs",
                width=110,
                height=24,
                font=ctk.CTkFont(size=11),
                fg_color=ACCENT_BTN,
                hover_color=ACCENT_BTN_HOVER,
                command=on_copy_all,
            ).pack(side="right")

        for row_idx, row_names in enumerate(_TAB_ROWS):
            row = ctk.CTkFrame(inner_bar, fg_color="transparent")
            row.pack(fill="x", pady=(0, 2) if row_idx == 0 else 0)
            uniform = f"tabs_r{row_idx}"
            for col_idx in range(len(row_names)):
                row.grid_columnconfigure(col_idx, weight=1, uniform=uniform)
            for col_idx, name in enumerate(row_names):
                if name not in tab_names:
                    continue
                label = _TAB_LABELS.get(name, name)
                btn = ctk.CTkButton(
                    row,
                    text=label,
                    height=24,
                    corner_radius=5,
                    fg_color="transparent",
                    hover_color="#252545",
                    text_color=TEXT_MUTED,
                    font=ctk.CTkFont(size=11),
                    command=lambda n=name: self.select(n),
                )
                btn.grid(row=0, column=col_idx, sticky="ew", padx=1)
                self._buttons[name] = btn

        self._body = ctk.CTkFrame(
            self,
            fg_color=PANEL_BG,
            corner_radius=PANEL_RADIUS,
            border_width=1,
            border_color=PANEL_BORDER,
        )
        self._body.pack(fill="both", expand=True)

        for name in tab_names:
            frame = ctk.CTkFrame(self._body, fg_color="transparent")
            self._content_frames[name] = frame

        if tab_names:
            self.select(tab_names[0])

    def frame(self, name: str) -> ctk.CTkFrame:
        return self._content_frames[name]

    def select(self, name: str) -> None:
        if name not in self._content_frames:
            return
        self._active = name
        for tab_name, frame in self._content_frames.items():
            if tab_name == name:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()
        for tab_name, btn in self._buttons.items():
            if tab_name == name:
                btn.configure(fg_color="#1e2a44", text_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_MUTED)

    @property
    def active(self) -> str | None:
        return self._active
