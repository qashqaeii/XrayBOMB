"""Raise CTkToplevel modals above the main window (Windows z-order fix)."""

from __future__ import annotations

import platform

import customtkinter as ctk


def configure_modal(window: ctk.CTkToplevel, parent: ctk.CTk) -> None:
    """Show *window* on top of *parent* and capture input until closed."""
    window.transient(parent)

    def _raise() -> None:
        window.lift(parent)
        window.focus_force()
        if platform.system() == "Windows":
            try:
                window.attributes("-topmost", True)
                window.after(80, lambda: window.attributes("-topmost", False))
            except Exception:
                pass

    def _close() -> None:
        try:
            window.grab_release()
        except Exception:
            pass
        window.destroy()

    window.protocol("WM_DELETE_WINDOW", _close)
    window.bind("<Map>", lambda _e: _raise(), add="+")

    window.update_idletasks()
    window.after(10, _raise)

    try:
        window.grab_set()
    except Exception:
        pass
