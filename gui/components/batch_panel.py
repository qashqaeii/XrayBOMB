"""Batch analysis results table."""

from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from backend.models import AnalysisResult, BatchAnalysisResult


class BatchResultsPanel(ctk.CTkFrame):
    """Table of multiple config analysis results."""

    def __init__(self, master, on_select: Callable[[AnalysisResult], None], **kwargs) -> None:
        height = kwargs.pop("height", 72)
        super().__init__(
            master,
            fg_color="#1a1a2e",
            corner_radius=10,
            border_width=1,
            border_color="#2a2a4e",
            height=height,
            **kwargs,
        )
        self.pack_propagate(False)
        self.on_select = on_select
        self._batch: Optional[BatchAnalysisResult] = None

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=8, pady=6)

        header = ctk.CTkFrame(inner, fg_color="transparent")
        header.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(header, text="Batch Results", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left")
        self.info_label = ctk.CTkLabel(header, text="—", font=ctk.CTkFont(size=10), text_color="#8888aa")
        self.info_label.pack(side="right")

        self.scroll = ctk.CTkScrollableFrame(inner, height=40, fg_color="#12122a", corner_radius=8)
        self.scroll.pack(fill="x")

    def update_batch(self, batch: BatchAnalysisResult) -> None:
        self._batch = batch
        for w in self.scroll.winfo_children():
            w.destroy()

        ok = len(batch.results)
        err = len(batch.errors)
        self.info_label.configure(text=f"{ok} analyzed, {err} errors (of {batch.total} configs)")

        for i, result in enumerate(batch.results):
            c = result.config
            score = result.security.score
            color = "#00cc66" if score >= 80 else "#ffaa00" if score >= 50 else "#ff4444"
            tls = "TLS" if c.tls else "noTLS"
            cdn = result.deployment.cdn_type or "—"
            text = f"{i + 1}. {c.protocol.value} {c.address}:{c.port} | {score}/100 | {tls} | CDN:{cdn}"
            ctk.CTkButton(
                self.scroll, text=text, anchor="w", height=24,
                fg_color="#1a1a2e", hover_color="#2a2a4e", text_color=color,
                command=lambda r=result: self.on_select(r),
            ).pack(fill="x", pady=1)

        for err in batch.errors:
            ctk.CTkLabel(self.scroll, text=f"⚠ {err}", text_color="#ff4444", anchor="w").pack(fill="x")

    def clear(self) -> None:
        self._batch = None
        self.info_label.configure(text="—")
        for w in self.scroll.winfo_children():
            w.destroy()
