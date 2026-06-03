"""Standard Ctrl+C / Ctrl+V / Ctrl+A bindings for CTk widgets."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk


def bind_textbox_clipboard(textbox: ctk.CTkTextbox, editable: bool = True) -> None:
    """Bind clipboard shortcuts on the inner tk Text widget."""
    inner = textbox._textbox

    def _copy(_event=None):
        try:
            if inner.tag_ranges("sel"):
                text = inner.get("sel.first", "sel.last")
                textbox.clipboard_clear()
                textbox.clipboard_append(text)
        except tk.TclError:
            pass
        return "break"

    def _paste(_event=None):
        if not editable:
            return "break"
        try:
            text = textbox.clipboard_get()
            if inner.tag_ranges("sel"):
                inner.delete("sel.first", "sel.last")
            inner.insert("insert", text)
        except tk.TclError:
            pass
        return "break"

    def _cut(_event=None):
        if not editable:
            return "break"
        _copy()
        try:
            if inner.tag_ranges("sel"):
                inner.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        return "break"

    def _select_all(_event=None):
        inner.tag_add("sel", "1.0", "end-1c")
        return "break"

    for seq in ("<Control-c>", "<Control-C>", "<Control-Insert>"):
        inner.bind(seq, _copy)
    for seq in ("<Control-a>", "<Control-A>"):
        inner.bind(seq, _select_all)
    if editable:
        for seq in ("<Control-v>", "<Control-V>", "<Shift-Insert>"):
            inner.bind(seq, _paste)
        for seq in ("<Control-x>", "<Control-X>"):
            inner.bind(seq, _cut)


def bind_entry_clipboard(entry: ctk.CTkEntry) -> None:
    """Bind clipboard shortcuts on CTkEntry."""
    inner = entry._entry

    def _copy(_event=None):
        try:
            if inner.selection_present():
                text = inner.selection_get()
            else:
                text = entry.get()
            entry.clipboard_clear()
            entry.clipboard_append(text)
        except tk.TclError:
            pass
        return "break"

    def _paste(_event=None):
        try:
            text = entry.clipboard_get()
            if inner.selection_present():
                inner.delete(tk.SEL_FIRST, tk.SEL_LAST)
            inner.insert(tk.INSERT, text)
        except tk.TclError:
            pass
        return "break"

    def _cut(_event=None):
        _copy()
        try:
            if inner.selection_present():
                inner.delete(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            pass
        return "break"

    def _select_all(_event=None):
        inner.select_range(0, tk.END)
        inner.icursor(tk.END)
        return "break"

    for seq in ("<Control-c>", "<Control-C>"):
        inner.bind(seq, _copy)
    for seq in ("<Control-v>", "<Control-V>", "<Shift-Insert>"):
        inner.bind(seq, _paste)
    for seq in ("<Control-x>", "<Control-X>"):
        inner.bind(seq, _cut)
    for seq in ("<Control-a>", "<Control-A>"):
        inner.bind(seq, _select_all)
