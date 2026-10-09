"""CTkToplevel helpers — z-order, optional modal grab, minimizable tool windows."""

from __future__ import annotations

import platform
from typing import Callable, Optional

import customtkinter as ctk

OnCloseFn = Callable[[], None]


def configure_modal(
    window: ctk.CTkToplevel,
    parent: ctk.CTk,
    *,
    modal: bool = False,
    on_close: Optional[OnCloseFn] = None,
) -> None:
    """Attach a child window to *parent*.

    modal=False (default for tools): no input grab — user can minimize and use the main app.
    modal=True: blocks parent until closed (settings, short dialogs).
    """
    # transient on Windows often hides the minimize button; use it only for true modals
    if modal:
        window.transient(parent)

    def _close() -> None:
        try:
            window.grab_release()
        except Exception:
            pass
        if on_close is not None:
            on_close()
        elif window.winfo_exists():
            window.destroy()

    def _raise() -> None:
        try:
            if str(window.state()) == "iconic":
                return
        except Exception:
            pass
        window.lift(parent)
        window.focus_force()
        if platform.system() == "Windows":
            try:
                window.attributes("-topmost", True)
                window.after(80, lambda: window.attributes("-topmost", False))
            except Exception:
                pass

    def _on_unmap(event) -> None:
        if event.widget is window:
            try:
                if str(window.state()) == "iconic":
                    window.grab_release()
            except Exception:
                pass

    def _on_map(event) -> None:
        if event.widget is window:
            _raise()
            if modal:
                try:
                    window.grab_set()
                except Exception:
                    pass

    window.protocol("WM_DELETE_WINDOW", _close)
    window.bind("<Unmap>", _on_unmap, add="+")
    window.bind("<Map>", _on_map, add="+")

    window.update_idletasks()
    window.after(10, _raise)

    if modal:
        try:
            window.grab_set()
        except Exception:
            pass


def configure_tool_window(
    window: ctk.CTkToplevel,
    parent: ctk.CTk,
    *,
    on_close: Optional[OnCloseFn] = None,
) -> None:
    """Minimizable tool window (alias for configure_modal with modal=False)."""
    configure_modal(window, parent, modal=False, on_close=on_close)
