"""Reusable modal shell for network tools."""

from __future__ import annotations

import threading
from typing import Callable, Optional

import customtkinter as ctk
from tkinter import messagebox

from gui.components.copyable_text import CopyableTextbox
from gui.components.modal_utils import configure_modal
from utils.ui_theme import ACCENT_BTN, ACCENT_BTN_HOVER, BG_DARK, PANEL_BG, PANEL_BORDER


LogFn = Callable[[str], None]
TaskFn = Callable[[], str]


class AsyncToolWindow:
    """Standard tool modal: header, options, live status, results, async runner."""

    def __init__(
        self,
        parent: ctk.CTk,
        title: str,
        subtitle: str,
        *,
        badge: str = "Iran-optimized",
        size: tuple[int, int] = (840, 640),
        on_log: Optional[LogFn] = None,
    ) -> None:
        self.parent = parent
        self.on_log = on_log or (lambda _m: None)
        self._running = False
        self._closed = False

        self.win = ctk.CTkToplevel(parent)
        self.win.title(title)
        self.win.geometry(f"{size[0]}x{size[1]}")
        self.win.minsize(680, 480)
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 4))

        title_row = ctk.CTkFrame(header, fg_color="transparent")
        title_row.pack(fill="x")
        ctk.CTkLabel(
            title_row, text=title,
            font=ctk.CTkFont(size=17, weight="bold"), text_color="#00d4ff",
        ).pack(side="left")
        ctk.CTkLabel(
            title_row, text=badge,
            font=ctk.CTkFont(size=10, weight="bold"),
            fg_color="#1a3a5c", corner_radius=6, text_color="#7dd3fc",
        ).pack(side="left", padx=(10, 0), ipady=2, ipadx=8)

        ctk.CTkLabel(
            header, text=subtitle,
            font=ctk.CTkFont(size=11), text_color="#8888aa",
            wraplength=780, justify="left",
        ).pack(anchor="w", pady=(4, 0))

        self.options = ctk.CTkFrame(self.win, fg_color=PANEL_BG, corner_radius=10, border_width=1, border_color=PANEL_BORDER)
        self.options.pack(fill="x", padx=16, pady=8)

        self.status = ctk.CTkLabel(
            self.win, text="Ready.",
            font=ctk.CTkFont(size=11), text_color="#66cc99", anchor="w",
        )
        self.status.pack(fill="x", padx=18, pady=(0, 2))

        ctk.CTkLabel(
            self.win,
            text="Output: drag to select · Ctrl+C · right-click · toolbar Copy",
            font=ctk.CTkFont(size=9), text_color="#555577", anchor="w",
        ).pack(fill="x", padx=18, pady=(0, 4))

        self.output = CopyableTextbox(
            self.win, show_toolbar=True, read_only=True,
            font=ctk.CTkFont(family="Consolas", size=12), wrap="word", fg_color=BG_DARK,
        )
        self.output.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        btn_row = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 14))

        self._run_label = "Run"
        self._busy_label = "Running..."
        self.run_btn = ctk.CTkButton(
            btn_row, text="Run", width=130, height=36,
            fg_color=ACCENT_BTN, hover_color=ACCENT_BTN_HOVER,
        )
        self.run_btn.pack(side="left")
        ctk.CTkButton(btn_row, text="Close", width=90, command=self._on_close).pack(side="right")

        configure_modal(self.win, parent, on_close=self._on_close, modal=False)

    def _on_close(self) -> None:
        self._closed = True
        self._running = False
        try:
            self.win.destroy()
        except Exception:
            pass

    def _alive(self) -> bool:
        if self._closed:
            return False
        try:
            return bool(self.win.winfo_exists())
        except Exception:
            return False

    def _safe_after(self, fn: Callable[[], None]) -> None:
        if not self._alive():
            return
        try:
            self.win.after(0, fn)
        except Exception:
            pass

    def set_placeholder(self, text: str) -> None:
        self.output.set_text(text)

    def set_status(self, text: str, *, color: str = "#66cc99") -> None:
        if not self._alive():
            return
        self.status.configure(text=text, text_color=color)

    def bind_run(self, label: str, task: TaskFn, *, busy_label: str = "Running...") -> None:
        self._run_label = label
        self._busy_label = busy_label
        self.run_btn.configure(text=label, command=lambda: self._start(task, busy_label))

    def bind_run_with_progress(
        self,
        label: str,
        task: Callable[[Callable[[str], None]], str],
        *,
        busy_label: str = "Running...",
    ) -> None:
        self._run_label = label
        self._busy_label = busy_label

        def wrapped() -> str:
            def progress(msg: str) -> None:
                self._safe_after(lambda m=msg: self.set_status(m, color="#88aaff"))
                self.on_log(msg)
            return task(progress)

        self.run_btn.configure(text=label, command=lambda: self._start(wrapped, busy_label))

    def _start(self, task: TaskFn, busy_label: str) -> None:
        if self._running:
            messagebox.showwarning("Busy", "Tool is already running.", parent=self.win)
            return
        self._running = True
        self.run_btn.configure(state="disabled", text=busy_label)
        self.set_status("Working...", color="#ffaa44")

        def worker() -> None:
            try:
                text = task()
                self._safe_after(lambda t=text: self._apply_success(t))
            except Exception as exc:
                err = str(exc)
                self._safe_after(lambda e=err: self._apply_error(e))
            finally:
                self._safe_after(self._finish)

        threading.Thread(target=worker, daemon=True).start()

    def _apply_success(self, text: str) -> None:
        if not self._alive():
            return
        self.output.set_text(text)
        self.set_status("Done.", color="#66cc99")

    def _apply_error(self, err: str) -> None:
        if not self._alive():
            return
        messagebox.showerror("Tool Error", err, parent=self.win)
        self.set_status(f"Error: {err}", color="#ff6666")

    def _finish(self) -> None:
        self._running = False
        if not self._alive():
            return
        self.run_btn.configure(state="normal", text=self._run_label)
