"""History panel for past analyses."""

from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from database.db import AnalysisDatabase
from gui.components.clipboard_bindings import bind_entry_clipboard
from utils.ui_theme import PANEL_BG, PANEL_BORDER, PANEL_PAD, PANEL_RADIUS


class HistoryPanel(ctk.CTkFrame):
    """Browse, search, load, and delete analysis history."""

    def __init__(self, master, on_load: Callable[[int], None], **kwargs) -> None:
        super().__init__(
            master,
            fg_color=PANEL_BG,
            corner_radius=PANEL_RADIUS,
            border_width=1,
            border_color=PANEL_BORDER,
            **kwargs,
        )
        self.on_load = on_load
        self.db = AnalysisDatabase()

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=PANEL_PAD, pady=PANEL_PAD)
        inner.grid_columnconfigure(0, weight=1)
        inner.grid_rowconfigure(2, weight=1)

        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        ctk.CTkLabel(header, text="History", font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")

        search_frame = ctk.CTkFrame(inner, fg_color="transparent")
        search_frame.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search...", height=30)
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        bind_entry_clipboard(self.search_entry)
        ctk.CTkButton(search_frame, text="Go", width=44, height=30, command=self.refresh).pack(side="right")

        self.list_frame = ctk.CTkScrollableFrame(inner, fg_color="#12122a", corner_radius=8)
        self.list_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 4))
        inner.grid_rowconfigure(2, weight=1)

        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.grid(row=3, column=0, sticky="ew")
        ctk.CTkButton(btn_row, text="Refresh", width=80, height=28, command=self.refresh).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            btn_row, text="Delete Selected", width=110, height=28, fg_color="#883333", command=self._delete_selected,
        ).pack(side="right")

        self._selected_id: Optional[int] = None
        self.refresh()

    def refresh(self) -> None:
        for w in self.list_frame.winfo_children():
            w.destroy()
        query = self.search_entry.get().strip()
        rows = self.db.search(query) if query else self.db.list_recent(30)
        if not rows:
            ctk.CTkLabel(self.list_frame, text="No history yet.", text_color="#666").pack(pady=10)
            return
        for row in rows:
            score = row.get("security_score", 0)
            color = "#00cc66" if score >= 80 else "#ffaa00" if score >= 50 else "#ff4444"
            health = row.get("health_status") or ""
            label = f"#{row['id']} {row['protocol']} {row['address']}:{row['port']} — {score}/100"
            if health and health != "unknown":
                label += f" [{health}]"
            btn = ctk.CTkButton(
                self.list_frame, text=label, anchor="w", height=28,
                fg_color="#1a1a2e", hover_color="#2a2a4e", text_color=color,
                command=lambda rid=row["id"]: self._select(rid),
            )
            btn.pack(fill="x", pady=1)

    def _select(self, analysis_id: int) -> None:
        self._selected_id = analysis_id
        self.on_load(analysis_id)

    def _delete_selected(self) -> None:
        if self._selected_id:
            self.db.delete(self._selected_id)
            self._selected_id = None
            self.refresh()
