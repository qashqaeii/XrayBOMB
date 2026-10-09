"""Left sidebar — config input."""

from __future__ import annotations

from typing import Callable

import customtkinter as ctk
from tkinter import Menu, filedialog

from gui.components.clipboard_bindings import bind_entry_clipboard, bind_textbox_clipboard
from utils.ui_theme import (
    ACCENT_BTN,
    ACCENT_BTN_HOVER,
    PANEL_BG,
    PANEL_BORDER,
    PANEL_PAD,
    PANEL_RADIUS,
    TEXT_DIM,
)

_CONFIG_PLACEHOLDER = "Paste VLESS / VMess / Trojan / SS / Hysteria2 / TUIC link here…"


class Sidebar(ctk.CTkFrame):
    """Config input sidebar."""

    def __init__(
        self,
        master,
        on_analyze: Callable[[str], None],
        on_subscription: Callable[[str], None],
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            fg_color=PANEL_BG,
            corner_radius=PANEL_RADIUS,
            border_width=1,
            border_color=PANEL_BORDER,
            **kwargs,
        )
        self.on_analyze = on_analyze
        self.on_subscription = on_subscription

        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=PANEL_PAD, pady=PANEL_PAD)

        ctk.CTkButton(
            inner,
            text="Analyze Config",
            command=self._analyze,
            font=ctk.CTkFont(size=14, weight="bold"),
            height=42,
            fg_color=ACCENT_BTN,
            hover_color=ACCENT_BTN_HOVER,
            corner_radius=8,
        ).pack(side="bottom", fill="x")

        body = ctk.CTkFrame(inner, fg_color="transparent")
        body.pack(side="top", fill="both", expand=True)

        ctk.CTkLabel(
            body, text="Config Input", font=ctk.CTkFont(size=15, weight="bold"), anchor="w",
        ).pack(fill="x", pady=(0, 8))

        self._placeholder_active = False
        self.textbox = ctk.CTkTextbox(
            body,
            height=100,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#12122a",
            corner_radius=8,
            border_width=1,
            border_color=PANEL_BORDER,
        )
        self.textbox.pack(fill="both", expand=True, pady=(0, 8))
        bind_textbox_clipboard(self.textbox, editable=True)
        self._setup_config_placeholder()
        self._patch_config_clipboard_paste()
        self._setup_config_context_menu()

        btn_frame = ctk.CTkFrame(body, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(0, 8))

        ctk.CTkButton(btn_frame, text="Paste Config", command=self._paste, width=130, height=30).pack(
            side="left", padx=(0, 4), expand=True, fill="x",
        )
        ctk.CTkButton(btn_frame, text="Import File", command=self._import_file, width=130, height=30).pack(
            side="left", padx=(4, 0), expand=True, fill="x",
        )

        sub_frame = ctk.CTkFrame(body, fg_color="transparent")
        sub_frame.pack(fill="x")

        self.sub_entry = ctk.CTkEntry(sub_frame, placeholder_text="Subscription URL...", height=32)
        self.sub_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        bind_entry_clipboard(self.sub_entry)

        ctk.CTkButton(sub_frame, text="Import Sub", width=88, height=32, command=self._import_sub).pack(side="right")

    def _setup_config_placeholder(self) -> None:
        inner = self.textbox._textbox
        inner.tag_configure("placeholder", foreground=TEXT_DIM)
        inner.bind("<FocusIn>", self._on_config_focus_in)
        inner.bind("<FocusOut>", self._on_config_focus_out)
        inner.bind("<Button-1>", self._on_config_click, add="+")
        self._show_config_placeholder()

    def _show_config_placeholder(self) -> None:
        self._placeholder_active = True
        self.textbox.delete("1.0", "end")
        self.textbox.insert("1.0", _CONFIG_PLACEHOLDER)
        self.textbox._textbox.tag_add("placeholder", "1.0", "end")

    def _clear_config_placeholder(self) -> None:
        if not self._placeholder_active:
            return
        self._placeholder_active = False
        self.textbox.delete("1.0", "end")

    def _on_config_focus_in(self, _event=None) -> None:
        if self._placeholder_active:
            self._clear_config_placeholder()

    def _on_config_click(self, _event=None) -> None:
        if self._placeholder_active:
            self._clear_config_placeholder()

    def _on_config_focus_out(self, _event=None) -> None:
        if not self.textbox.get("1.0", "end").strip():
            self._show_config_placeholder()

    def _set_config_text(self, text: str) -> None:
        self._clear_config_placeholder()
        self.textbox.delete("1.0", "end")
        if text:
            self.textbox.insert("1.0", text)

    def _patch_config_clipboard_paste(self) -> None:
        inner = self.textbox._textbox

        def _paste(_event=None):
            if self._placeholder_active:
                self._clear_config_placeholder()
            try:
                text = self.textbox.clipboard_get()
                if inner.tag_ranges("sel"):
                    inner.delete("sel.first", "sel.last")
                inner.insert("insert", text)
            except Exception:
                pass
            return "break"

        for seq in ("<Control-v>", "<Control-V>", "<Shift-Insert>"):
            inner.bind(seq, _paste)

    def _setup_config_context_menu(self) -> None:
        inner = self.textbox._textbox
        menu = Menu(self, tearoff=0)
        menu.add_command(label="Cut", command=lambda: inner.event_generate("<<Cut>>"))
        menu.add_command(label="Copy", command=lambda: inner.event_generate("<<Copy>>"))
        menu.add_command(label="Paste", command=self._paste_from_menu)
        menu.add_command(label="Select All", command=lambda: inner.tag_add("sel", "1.0", "end-1c"))

        def show_menu(event):
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        inner.bind("<Button-3>", show_menu)

    def _paste_from_menu(self) -> None:
        if self._placeholder_active:
            self._clear_config_placeholder()
        self.textbox._textbox.event_generate("<<Paste>>")

    def _paste(self) -> None:
        try:
            text = self.clipboard_get()
            self._set_config_text(text)
        except Exception:
            pass

    def _import_file(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("All Supported", "*.txt *.json *.conf"), ("All Files", "*.*")]
        )
        if path:
            with open(path, encoding="utf-8", errors="replace") as f:
                self._set_config_text(f.read())

    def _import_sub(self) -> None:
        url = self.sub_entry.get().strip()
        if url:
            self.on_subscription(url)

    def _analyze(self) -> None:
        text = self.get_text()
        if text:
            self.on_analyze(text)

    def get_text(self) -> str:
        if self._placeholder_active:
            return ""
        return self.textbox.get("1.0", "end").strip()

    def set_text(self, text: str) -> None:
        if text.strip():
            self._set_config_text(text)
        else:
            self._show_config_placeholder()
