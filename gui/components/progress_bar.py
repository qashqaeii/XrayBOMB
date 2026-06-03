"""Analysis progress bar with stage labels."""

from __future__ import annotations

import customtkinter as ctk


class AnalysisProgressBar(ctk.CTkFrame):
    """Visual progress for multi-stage analysis."""

    def __init__(self, master, **kwargs) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.stage_label = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=11), text_color="#888")
        self.stage_label.pack(fill="x", padx=4)
        self.bar = ctk.CTkProgressBar(self, height=8)
        self.bar.pack(fill="x", padx=4, pady=(2, 4))
        self.bar.set(0)
        self.pack_forget()

    def start(self) -> None:
        self.bar.set(0)
        self.stage_label.configure(text="Starting analysis...")
        self.pack(fill="x", padx=8, pady=(0, 4))

    def update_stage(self, current: int, total: int, name: str) -> None:
        progress = current / total if total else 0
        self.bar.set(progress)
        self.stage_label.configure(text=f"[{current}/{total}] {name}")

    def complete(self) -> None:
        self.bar.set(1.0)
        self.stage_label.configure(text="Analysis complete ✓")
        self.after(2000, self.pack_forget)

    def reset(self) -> None:
        self.bar.set(0)
        self.stage_label.configure(text="")
        self.pack_forget()
