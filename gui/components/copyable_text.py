"""Copyable text widget with clipboard support."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_textbox_clipboard
from utils.country import apply_flag_emoji_tags
from utils.persian_text import split_persian_lines
from utils.ui_theme import monospace_font_family, persian_font_family


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
            toolbar = ctk.CTkFrame(self, fg_color="transparent", height=24)
            toolbar.pack(fill="x", padx=4, pady=(4, 2))
            btn_kw = dict(height=22, font=ctk.CTkFont(size=11), fg_color="transparent", hover_color="#252545")
            ctk.CTkButton(toolbar, text="Copy", width=56, command=self.copy_selection, **btn_kw).pack(side="left", padx=(0, 2))
            ctk.CTkButton(toolbar, text="All", width=40, command=self.copy_all, **btn_kw).pack(side="left", padx=2)
            ctk.CTkButton(toolbar, text="Select", width=52, command=self.select_all, **btn_kw).pack(side="left", padx=2)

        self._font_size = 12
        self._font_family = "Consolas"
        font_kw = kwargs.get("font")
        if isinstance(font_kw, ctk.CTkFont):
            self._font_size = font_kw.cget("size") or 12
            family = font_kw.cget("family")
            if family:
                self._font_family = family

        self.textbox = ctk.CTkTextbox(self, **kwargs)
        self.textbox.pack(fill="both", expand=True)
        bind_textbox_clipboard(self.textbox, editable=not read_only)

        if read_only:
            self._make_read_only()

        self._ctx_menu = tk.Menu(self, tearoff=0)
        self._ctx_menu.add_command(label="Copy", command=self.copy_selection)
        self._ctx_menu.add_command(label="Copy All", command=self.copy_all)
        self._ctx_menu.add_command(label="Select All", command=self.select_all)
        if not read_only:
            self._ctx_menu.add_separator()
            self._ctx_menu.add_command(label="Paste", command=self.paste_clipboard)
        self.textbox.bind("<Button-3>", self._show_context_menu)
        self.textbox.bind("<Control-a>", lambda _e: (self.select_all(), "break"))

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

    def set_text(self, content: str) -> None:
        self.textbox.delete("1.0", "end")
        inner = self.textbox._textbox
        if self._rtl:
            persian = self._font_family or persian_font_family()
            mono = monospace_font_family()
            inner.tag_configure(
                "rtl",
                justify="right",
                font=(persian, self._font_size),
                lmargin1=8,
                lmargin2=8,
                rmargin=8,
            )
            inner.tag_configure(
                "ltr",
                justify="left",
                font=(mono, self._font_size),
                lmargin1=8,
                lmargin2=8,
                rmargin=8,
            )
            for display, tag in split_persian_lines(content):
                inner.insert("end", display + "\n", tag)
        else:
            self.textbox.insert("1.0", content)
        apply_flag_emoji_tags(inner, size=self._font_size)

    def append_text(self, content: str, *, max_chars: int = 500_000, tag_flags: bool = True) -> None:
        """Append without rebuilding the whole buffer (terminal streaming)."""
        if not content:
            return
        inner = self.textbox._textbox
        inner.insert("end", content)
        if tag_flags:
            apply_flag_emoji_tags(inner, size=self._font_size)
        if max_chars > 0:
            total = int(inner.index("end-1c").split(".")[0])
            if total > max_chars:
                trim = total - int(max_chars * 0.85)
                inner.delete("1.0", f"{trim}.0")
                inner.insert("1.0", "… earlier output trimmed …\n\n")
        inner.see("end")

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

    def paste_clipboard(self) -> None:
        if self._read_only:
            return
        try:
            text = self.clipboard_get()
            inner = self.textbox._textbox
            if inner.tag_ranges("sel"):
                inner.delete("sel.first", "sel.last")
            inner.insert("insert", text)
        except Exception:
            pass

    def select_all(self) -> None:
        self.textbox.tag_add("sel", "1.0", "end")

    def clear(self) -> None:
        self.textbox.delete("1.0", "end")
