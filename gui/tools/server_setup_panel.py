"""Server Setup tab — grouped provisioning actions with clear layout."""

from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_entry_clipboard
from gui.components.copyable_text import CopyableTextbox
from tools.server_provisioning import ACTION_BY_ID, SETUP_UI_SECTIONS
from utils.ui_theme import BG_DARK, PANEL_BG, PANEL_BORDER, PANEL_PAD, TEXT_DIM, TEXT_MUTED

SECTION_COLORS = {
    "System & packages": ("#1a2a3a", "#243447"),
    "Proxy panels": ("#1a2f24", "#243828"),
    "SSL / domain": ("#2a2438", "#352d48"),
    "Firewall & network": ("#2a2820", "#38352a"),
}


class ServerSetupPanel(ctk.CTkFrame):
    """Server provisioning: SSL bar on top, actions (left) + output log (right)."""

    def __init__(
        self,
        master,
        *,
        on_run: Callable[[str], None],
        get_domain: Optional[Callable[[], str]] = None,
        get_email: Optional[Callable[[], str]] = None,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self.on_run = on_run
        self._get_domain = get_domain
        self._get_email = get_email

        self.columnconfigure(0, weight=3, minsize=420)
        self.columnconfigure(1, weight=2, minsize=280)
        self.rowconfigure(1, weight=1)

        self._build_ssl_card()
        self._build_actions_scroll()
        self._build_output()

    def _entry(self, parent, **kwargs) -> ctk.CTkEntry:
        e = ctk.CTkEntry(parent, **kwargs)
        bind_entry_clipboard(e)
        return e

    def _build_ssl_card(self) -> None:
        card = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=PANEL_PAD, border_width=1, border_color=PANEL_BORDER)
        card.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        card.columnconfigure(1, weight=1)
        card.columnconfigure(3, weight=1)

        ctk.CTkLabel(
            card, text="SSL & domain",
            font=ctk.CTkFont(size=13, weight="bold"), text_color="#7ee787",
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=PANEL_PAD, pady=(PANEL_PAD, 6))

        ctk.CTkLabel(card, text="Domain", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).grid(
            row=1, column=0, sticky="w", padx=(PANEL_PAD, 4), pady=4,
        )
        self.domain_e = self._entry(card, placeholder_text="sub.example.com", height=34)
        self.domain_e.grid(row=1, column=1, sticky="ew", padx=4, pady=4)

        ctk.CTkLabel(card, text="Email", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED).grid(
            row=1, column=2, sticky="w", padx=(16, 4), pady=4,
        )
        self.email_e = self._entry(card, placeholder_text="optional — Let's Encrypt", height=34)
        self.email_e.grid(row=1, column=3, sticky="ew", padx=(4, PANEL_PAD), pady=4)

        ctk.CTkLabel(
            card,
            text="Required for Certbot / acme.sh · port 80 must be free during issue",
            font=ctk.CTkFont(size=10), text_color=TEXT_DIM, anchor="w",
        ).grid(row=2, column=0, columnspan=4, sticky="w", padx=PANEL_PAD, pady=(0, PANEL_PAD))

    def domain(self) -> str:
        if self._get_domain:
            return self._get_domain()
        return self.domain_e.get().strip()

    def email(self) -> str:
        if self._get_email:
            return self._get_email()
        return self.email_e.get().strip()

    def _build_actions_scroll(self) -> None:
        wrap = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=PANEL_PAD, border_width=1, border_color=PANEL_BORDER)
        wrap.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(1, weight=1)

        ctk.CTkLabel(
            wrap, text="Actions", font=ctk.CTkFont(size=12, weight="bold"), text_color="#e6edf3", anchor="w",
        ).grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 6))

        self.scroll = ctk.CTkScrollableFrame(wrap, fg_color="#12141c", corner_radius=6, border_width=0)
        self.scroll.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.scroll.columnconfigure(0, weight=1)

        for row_idx, (title, action_ids) in enumerate(SETUP_UI_SECTIONS):
            bg, hover = SECTION_COLORS.get(title, ("#1e1e2a", "#2a2a3a"))
            section = ctk.CTkFrame(self.scroll, fg_color=bg, corner_radius=8, border_width=1, border_color=PANEL_BORDER)
            section.grid(row=row_idx, column=0, sticky="ew", padx=4, pady=6)
            section.columnconfigure(0, weight=1)
            section.columnconfigure(1, weight=1)

            ctk.CTkLabel(
                section, text=title, font=ctk.CTkFont(size=12, weight="bold"), text_color="#e6edf3", anchor="w",
            ).grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 10))

            idx = 0
            for aid in action_ids:
                action = ACTION_BY_ID.get(aid)
                if not action:
                    continue
                label_text = action.label
                r = idx // 2 + 1
                c = idx % 2
                ctk.CTkButton(
                    section,
                    text=label_text,
                    height=40,
                    font=ctk.CTkFont(size=11),
                    fg_color="#21262d",
                    hover_color=hover,
                    anchor="center",
                    command=lambda a=aid: self.on_run(a),
                ).grid(row=r, column=c, sticky="ew", padx=10, pady=6)
                idx += 1

            # Minimum height so section is never collapsed
            last_row = max(1, (idx + 1) // 2)
            section.grid_rowconfigure(last_row, minsize=8)

        # Force scroll region to include all sections after layout
        self.after(100, self._refresh_scroll)

    def _refresh_scroll(self) -> None:
        try:
            self.scroll.update_idletasks()
            canvas = self.scroll._parent_canvas
            canvas.configure(scrollregion=canvas.bbox("all"))
        except Exception:
            pass

    def _build_output(self) -> None:
        out_card = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=PANEL_PAD, border_width=1, border_color=PANEL_BORDER)
        out_card.grid(row=1, column=1, sticky="nsew")
        out_card.columnconfigure(0, weight=1)
        out_card.rowconfigure(1, weight=1)

        head = ctk.CTkFrame(out_card, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=PANEL_PAD, pady=(10, 6))
        head.columnconfigure(0, weight=1)
        ctk.CTkLabel(head, text="Output log", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00d4ff").grid(
            row=0, column=0, sticky="w",
        )
        self.status_lbl = ctk.CTkLabel(head, text="Ready", font=ctk.CTkFont(size=11), text_color=TEXT_DIM)
        self.status_lbl.grid(row=0, column=1, sticky="e")

        self.output = CopyableTextbox(
            out_card, show_toolbar=True, read_only=True, height=280,
            font=ctk.CTkFont(family="Consolas", size=11), wrap="word", fg_color=BG_DARK,
        )
        self.output.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.output.set_text(
            "Pick an action on the left.\n"
            "Long installs (5–15 min) — output streams here.\n"
            "Interactive steps: SSH Console tab.\n",
        )

    def set_status(self, text: str, *, color: str = "#88aaff") -> None:
        self.status_lbl.configure(text=text, text_color=color)

    def set_output(self, text: str) -> None:
        self.output.set_text(text)
