"""Tab bar with two rows of buttons — saves horizontal space."""

from __future__ import annotations

import customtkinter as ctk

from utils.ui_theme import ACCENT, PANEL_BORDER


class TwoRowTabBar(ctk.CTkFrame):
    """Two-row tab selector with a single content area below."""

    def __init__(self, master, tab_names: list[str], **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self._buttons: dict[str, ctk.CTkButton] = {}
        self._content_frames: dict[str, ctk.CTkFrame] = {}
        self._active: str | None = None

        mid = (len(tab_names) + 1) // 2
        row1, row2 = tab_names[:mid], tab_names[mid:]

        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", pady=(0, 4))

        for row_names in (row1, row2):
            row = ctk.CTkFrame(bar, fg_color="transparent")
            row.pack(fill="x", pady=1)
            for name in row_names:
                btn = ctk.CTkButton(
                    row,
                    text=name,
                    height=28,
                    fg_color="transparent",
                    hover_color="#2a2a4e",
                    border_width=1,
                    border_color=PANEL_BORDER,
                    text_color="#aaaaaa",
                    font=ctk.CTkFont(size=11),
                    command=lambda n=name: self.select(n),
                )
                btn.pack(side="left", padx=2, pady=1)
                self._buttons[name] = btn

        self._body = ctk.CTkFrame(self, fg_color="transparent")
        self._body.pack(fill="both", expand=True)

        for name in tab_names:
            self._content_frames[name] = ctk.CTkFrame(self._body, fg_color="transparent")

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
                btn.configure(fg_color="#1a2744", text_color=ACCENT, border_color=ACCENT)
            else:
                btn.configure(fg_color="transparent", text_color="#aaaaaa", border_color=PANEL_BORDER)

    @property
    def active(self) -> str | None:
        return self._active
