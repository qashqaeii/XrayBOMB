"""Toast notification overlay."""

from __future__ import annotations

import customtkinter as ctk


class ToastNotification:
    """Simple toast popup that auto-dismisses."""

    def __init__(self, master) -> None:
        self.master = master
        self._label: ctk.CTkLabel | None = None

    def show(self, message: str, duration_ms: int = 3000, color: str = "#006633") -> None:
        if self._label:
            self._label.destroy()
        self._label = ctk.CTkLabel(
            self.master, text=message, fg_color=color, corner_radius=8,
            font=ctk.CTkFont(size=12), padx=16, pady=8,
        )
        self._label.place(relx=0.5, rely=0.02, anchor="n")
        self.master.after(duration_ms, self._dismiss)

    def _dismiss(self) -> None:
        if self._label:
            self._label.destroy()
            self._label = None
