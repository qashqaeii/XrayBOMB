"""Copyable text widget with clipboard support."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_textbox_clipboard
from utils.country import apply_flag_emoji_tags


class CopyableTextbox(ctk.CTkFrame):
    """Textbox with copy toolbar, Ctrl+C, and right-click menu."""

    def __init__(
        self,
        master,
        show_toolbar: bool = True,
        read_only: bool = True,
        rtl: bool = False,
        **kwargs,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self._read_only = read_only
        self._rtl = rtl

        if show_toolbar:
            toolbar = ctk.CTkFrame(self, fg_color="transparent", height=28)
            toolbar.pack(fill="x", padx=2, pady=(0, 2))
            ctk.CTkButton(toolbar, text="📋 Copy", width=72, height=24, command=self.copy_selection).pack(side="left", padx=2)
            ctk.CTkButton(toolbar, text="Copy All", width=72, height=24, command=self.copy_all).pack(side="left", padx=2)
            ctk.CTkButton(toolbar, text="Select All", width=72, height=24, command=self.select_all).pack(side="left", padx=2)

        self._font_size = 12
        font_kw = kwargs.get("font")
        if isinstance(font_kw, ctk.CTkFont):
            self._font_size = font_kw.cget("size") or 12

        self.textbox = ctk.CTkTextbox(self, **kwargs)
        self.textbox.pack(fill="both", expand=True)
        bind_textbox_clipboard(self.textbox, editable=not read_only)

        if read_only:
            self._make_read_only()

        self._ctx_menu = tk.Menu(self, tearoff=0)
        self._ctx_menu.add_command(label="Copy", command=self.copy_selection)
        self._ctx_menu.add_command(label="Copy All", command=self.copy_all)
        self._ctx_menu.add_command(label="Select All", command=self.select_all)
        self.textbox.bind("<Button-3>", self._show_context_menu)

    def _make_read_only(self) -> None:
        inner = self.textbox._textbox

        def _block_edit(event) -> str | None:
            if event.state & 0x4 and event.keysym.lower() in ("c", "a", "insert"):
                return None
            if event.keysym in ("Left", "Right", "Up", "Down", "Home", "End", "Prior", "Next",
                                "Shift_L", "Shift_R", "Control_L", "Control_R"):
                return None
            return "break"

        inner.bind("<Key>", _block_edit)

    def _show_context_menu(self, event) -> None:
        try:
            self._ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx_menu.grab_release()

    def get_text(self) -> str:
        return self.textbox.get("1.0", "end-1c")

    def _prepare_rtl_content(self, content: str) -> str:
        """Prefix lines with RLM so Persian renders right-to-left in Tk."""
        rlm = "\u200f"
        return "\n".join(f"{rlm}{line}" if line.strip() else line for line in content.split("\n"))

    def set_text(self, content: str) -> None:
        self.textbox.delete("1.0", "end")
        inner = self.textbox._textbox
        if self._rtl:
            inner.tag_configure("rtl", justify="right")
            inner.insert("1.0", self._prepare_rtl_content(content), "rtl")
        else:
            self.textbox.insert("1.0", content)
        apply_flag_emoji_tags(inner, size=self._font_size)

    def copy_selection(self) -> None:
        try:
            selected = self.textbox.get("sel.first", "sel.last")
            if selected:
                self.clipboard_clear()
                self.clipboard_append(selected)
                return
        except Exception:
            pass
        self.copy_all()

    def copy_all(self) -> None:
        text = self.get_text()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)

    def select_all(self) -> None:
        self.textbox.tag_add("sel", "1.0", "end")

    def clear(self) -> None:
        self.textbox.delete("1.0", "end")
