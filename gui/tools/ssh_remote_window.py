"""Remote Server Manager — vault, quick actions, live SSH console."""

from __future__ import annotations

import threading
from tkinter import messagebox
from typing import Callable, Optional

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_entry_clipboard
from gui.components.copyable_text import CopyableTextbox
from gui.components.modal_utils import configure_modal
from gui.tools.ssh_console_panel import SSHConsolePanel
from gui.tools.server_setup_panel import ServerSetupPanel
from gui.tools.tool_framework import LogFn
from tools.remote_server_ssh import (
    run_server_diagnostics_sync,
    test_bidirectional_connectivity_sync,
    test_ssh_connection_sync,
)
from tools.server_provisioning import ACTION_BY_ID, run_provisioning_action_sync
from tools.ssh_interactive import SSHInteractiveSession
from tools.ssh_vault import DB_FILE, SSHServerProfile, get_ssh_vault
from utils.ui_theme import ACCENT_BTN, ACCENT_BTN_HOVER, BG_DARK, PANEL_BG, PANEL_BORDER


def open_remote_server_window(parent: ctk.CTk, on_log: Optional[LogFn] = None) -> None:
    RemoteServerWindow(parent, on_log=on_log)


class RemoteServerWindow:
    """Professional SSH hub: saved servers + actions + interactive console."""

    def __init__(self, parent: ctk.CTk, *, on_log: Optional[LogFn] = None) -> None:
        self.parent = parent
        self.on_log = on_log or (lambda _m: None)
        self.vault = get_ssh_vault()
        self.session = SSHInteractiveSession()
        self._profiles: list[SSHServerProfile] = []
        self._selected_id: Optional[int] = None
        self._closed = False

        self.win = ctk.CTkToplevel(parent)
        self.win.title("Remote Server Manager")
        self.win.geometry("1120x860")
        self.win.minsize(980, 720)
        configure_modal(self.win, parent, on_close=self._on_close, modal=False)

        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(
            header, text="Remote Server Manager",
            font=ctk.CTkFont(size=20, weight="bold"), text_color="#00d4ff",
        ).pack(side="left")
        ctk.CTkLabel(
            header,
            text="Encrypted vault · Quick ops · Live console",
            font=ctk.CTkFont(size=11), text_color="#8888aa",
        ).pack(side="left", padx=(12, 0))

        self._build_profile_bar()
        self._build_tabs()
        self._refresh_profiles()

    # ── Profile selector (top bar) ──

    def _entry(self, parent, **kwargs) -> ctk.CTkEntry:
        e = ctk.CTkEntry(parent, **kwargs)
        bind_entry_clipboard(e)
        return e

    def _build_profile_bar(self) -> None:
        bar = ctk.CTkFrame(self.win, fg_color=PANEL_BG, corner_radius=10, border_width=1, border_color=PANEL_BORDER)
        bar.pack(fill="x", padx=16, pady=6)
        bar.columnconfigure(1, weight=1)

        row0 = ctk.CTkFrame(bar, fg_color="transparent")
        row0.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(10, 6))
        row0.columnconfigure(1, weight=1)

        ctk.CTkLabel(row0, text="Saved server", font=ctk.CTkFont(size=11, weight="bold"), text_color="#00d4ff").grid(
            row=0, column=0, sticky="w", padx=(0, 8),
        )
        self.profile_menu = ctk.CTkOptionMenu(row0, values=["— manual —"], width=320, command=self._on_profile_pick)
        self.profile_menu.set("— manual —")
        self.profile_menu.grid(row=0, column=1, sticky="ew", padx=4)

        actions = ctk.CTkFrame(row0, fg_color="transparent")
        actions.grid(row=0, column=2, sticky="e", padx=(8, 0))
        ctk.CTkButton(actions, text="Reload", width=72, height=30, command=self._refresh_profiles).pack(side="left", padx=2)
        ctk.CTkButton(
            actions, text="Save", width=72, height=30,
            fg_color=ACCENT_BTN, hover_color=ACCENT_BTN_HOVER, command=self._save_profile,
        ).pack(side="left", padx=2)
        ctk.CTkButton(
            actions, text="Delete", width=72, height=30,
            fg_color="#5a2233", hover_color="#7a3344", command=self._delete_profile,
        ).pack(side="left", padx=2)
        ctk.CTkButton(
            actions, text="Connect SSH", width=100, height=30,
            fg_color="#238636", hover_color="#2ea043", command=self._quick_connect,
        ).pack(side="left", padx=(6, 0))

        cred = ctk.CTkFrame(bar, fg_color="transparent")
        cred.grid(row=1, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 10))
        for col, (label, attr, width, extra) in enumerate((
            ("Host", "host_e", 180, {"placeholder_text": "IP or domain"}),
            ("Port", "port_e", 56, {}),
            ("User", "user_e", 100, {"placeholder_text": "root"}),
            ("Password", "pass_e", 120, {"show": "*"}),
            ("Label", "label_e", 110, {"placeholder_text": "Germany VPS"}),
            ("Region", "region_m", 90, None),
        )):
            ctk.CTkLabel(cred, text=label, font=ctk.CTkFont(size=10), text_color="#8888aa").grid(
                row=0, column=col, sticky="w", padx=(0 if col == 0 else 10, 4), pady=(0, 2),
            )
            if attr == "region_m":
                self.region_m = ctk.CTkOptionMenu(cred, values=["—", "Iran", "Foreign", "Relay"], width=width)
                self.region_m.set("—")
                self.region_m.grid(row=1, column=col, sticky="w", padx=(0 if col == 0 else 10, 4))
            else:
                kw = {"width": width, "height": 32, **(extra or {})}
                entry = self._entry(cred, **kw)
                setattr(self, attr, entry)
                entry.grid(row=1, column=col, sticky="w", padx=(0 if col == 0 else 10, 4))
        self.port_e.insert(0, "22")

        ctk.CTkLabel(
            bar,
            text="Credentials encrypted locally · ~/.xray_analyzer/ssh_vault",
            font=ctk.CTkFont(size=9), text_color="#666688",
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=12, pady=(0, 8))

    def _credentials(self) -> tuple[str, str, str, int] | None:
        h = self.host_e.get().strip()
        u = self.user_e.get().strip()
        p = self.pass_e.get()
        try:
            port = int(self.port_e.get().strip() or "22")
        except ValueError:
            port = 22
        if not h or not u:
            return None
        return h, u, p, port

    def _refresh_profiles(self) -> None:
        self._profiles = self.vault.list_profiles()
        names = ["— manual —"] + [p.display for p in self._profiles]
        self.profile_menu.configure(values=names)
        if self._selected_id:
            for p in self._profiles:
                if p.id == self._selected_id:
                    self.profile_menu.set(p.display)
                    return
        self.profile_menu.set("— manual —")

    def _on_profile_pick(self, choice: str) -> None:
        if choice == "— manual —":
            self._selected_id = None
            return
        for p in self._profiles:
            if p.display == choice:
                self._load_profile(p)
                return

    def _load_profile(self, p: SSHServerProfile) -> None:
        self._selected_id = p.id
        self.host_e.delete(0, "end")
        self.host_e.insert(0, p.host)
        self.port_e.delete(0, "end")
        self.port_e.insert(0, str(p.port))
        self.user_e.delete(0, "end")
        self.user_e.insert(0, p.username)
        self.pass_e.delete(0, "end")
        self.pass_e.insert(0, p.password)
        self.label_e.delete(0, "end")
        self.label_e.insert(0, p.label)
        self.region_m.set(p.region or "—")
        self.vault.touch(p.id)

    def _save_profile(self) -> None:
        creds = self._credentials()
        if not creds:
            messagebox.showwarning("Save", "Enter host and username.", parent=self.win)
            return
        h, u, p, port = creds
        try:
            pid = self.vault.save(
                label=self.label_e.get().strip() or h,
                host=h, username=u, password=p,
                port=port, region="" if self.region_m.get() == "—" else self.region_m.get(),
                profile_id=self._selected_id,
            )
            self._selected_id = pid
            self._refresh_profiles()
            self.on_log(f"Saved SSH profile: {h}")
            messagebox.showinfo("Saved", "Server profile saved to encrypted vault.", parent=self.win)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc), parent=self.win)

    def _quick_connect(self) -> None:
        if hasattr(self, "console"):
            self.console.connect()

    def _delete_profile(self) -> None:
        if not self._selected_id:
            messagebox.showinfo("Delete", "Select a saved server first.", parent=self.win)
            return
        if not messagebox.askyesno("Delete", "Remove this server from vault?", parent=self.win):
            return
        self.vault.delete(self._selected_id)
        self._selected_id = None
        self._refresh_profiles()
        self.profile_menu.set("— manual —")

    # ── Tabs ──

    def _build_tabs(self) -> None:
        tabs = ctk.CTkTabview(self.win, fg_color="#1a1a2e")
        tabs.pack(fill="both", expand=True, padx=16, pady=8)
        tabs.add("SSH Console")
        tabs.add("Server Setup")
        tabs.add("Diagnostics")
        tabs.add("Vault")
        self._build_console_tab(tabs.tab("SSH Console"))
        self._build_setup_tab(tabs.tab("Server Setup"))
        self._build_diagnostics_tab(tabs.tab("Diagnostics"))
        self._build_vault_tab(tabs.tab("Vault"))
        tabs.set("SSH Console")

    def _build_setup_tab(self, parent) -> None:
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        inner = ctk.CTkFrame(parent, fg_color="transparent")
        inner.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(0, weight=1)

        self.setup_panel = ServerSetupPanel(inner, on_run=self._run_setup_by_id)
        self.setup_panel.grid(row=0, column=0, sticky="nsew")

    def _run_setup_by_id(self, action_id: str) -> None:
        action = ACTION_BY_ID.get(action_id)
        if not action:
            return
        creds = self._credentials()
        if not creds:
            messagebox.showwarning("Setup", "Enter host and username in the connection bar.", parent=self.win)
            return
        domain = self.setup_panel.domain()
        email = self.setup_panel.email()
        if action.needs_domain and not domain:
            messagebox.showwarning("Domain", "Enter domain in the SSL section.", parent=self.win)
            return
        if action.confirm:
            msg = f"Run on server?\n\n{action.label}\n\n{action.description}"
            if not messagebox.askyesno("Confirm", msg, parent=self.win):
                return

        h, u, p, port = creds
        self.setup_panel.set_status(f"Running: {action.label}…", color="#ffaa44")
        self.setup_panel.set_output(f"Running: {action.label}\n(may take several minutes)\n\n")
        self.on_log(f"Provision: {action.id} → {h}")

        def worker() -> None:
            try:
                text = run_provisioning_action_sync(
                    host=h, username=u, password=p, port=port,
                    action_id=action.id, domain=domain, email=email,
                )
                if self._selected_id:
                    self.vault.touch(self._selected_id)
                color = "#66cc99"
            except Exception as exc:
                text = f"Error: {exc}"
                color = "#ff6666"
            self.win.after(0, lambda t=text, c=color: (self.setup_panel.set_output(t), self.setup_panel.set_status("Done", color=c)))

        threading.Thread(target=worker, daemon=True).start()

    def _build_diagnostics_tab(self, parent) -> None:
        inner = ctk.CTkFrame(parent, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=10, pady=10)
        inner.columnconfigure(0, weight=1)
        inner.rowconfigure(1, weight=1)

        card = ctk.CTkFrame(inner, fg_color=PANEL_BG, corner_radius=10, border_width=1, border_color=PANEL_BORDER)
        card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        card.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            card, text="Network diagnostics",
            font=ctk.CTkFont(size=13, weight="bold"), text_color="#00d4ff",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        ctk.CTkLabel(row, text="Your IP (optional)", font=ctk.CTkFont(size=11), text_color="#8888aa").pack(side="left")
        self.client_ip_e = self._entry(row, width=160, height=32, placeholder_text="auto-detect")
        self.client_ip_e.pack(side="left", padx=(10, 16))
        for label, cmd, color in (
            ("IR ↔ World route", self._run_route_test, ACCENT_BTN),
            ("SSH test", self._run_ssh_test, "#2a4a6e"),
            ("Full diagnostics", self._run_full_diag, "#2a4a6e"),
        ):
            ctk.CTkButton(
                row, text=label, width=130, height=34,
                fg_color=color, hover_color=ACCENT_BTN_HOVER if color == ACCENT_BTN else "#3a5a7e",
                command=cmd,
            ).pack(side="left", padx=4)

        self.diag_out = CopyableTextbox(
            inner, show_toolbar=True, read_only=True, height=400,
            font=ctk.CTkFont(family="Consolas", size=12), wrap="word", fg_color=BG_DARK,
        )
        self.diag_out.grid(row=1, column=0, sticky="nsew")
        self.diag_out.set_text("Run a diagnostic test — results appear here.\n")

    def _run_ssh_task(self, label: str, fn, *, output: str = "diag") -> None:
        creds = self._credentials()
        if not creds:
            messagebox.showwarning("Run", "Enter host and username.", parent=self.win)
            return
        h, u, p, port = creds
        box = self.diag_out if output == "diag" else getattr(self, "action_out", self.diag_out)
        box.set_text(f"Working: {label}...\n")
        self.on_log(f"SSH: {label} → {h}")

        def worker() -> None:
            try:
                text = fn(h, u, p, port)
                if self._selected_id:
                    self.vault.touch(self._selected_id)
            except Exception as exc:
                text = f"Error: {exc}"
            self.win.after(0, lambda t=text, b=box: b.set_text(t))

        threading.Thread(target=worker, daemon=True).start()

    def _run_route_test(self) -> None:
        cip = self.client_ip_e.get().strip() or None
        self._run_ssh_task(
            "route test",
            lambda h, u, p, port: test_bidirectional_connectivity_sync(
                host=h, username=u, password=p, port=port, client_ip=cip,
            ),
        )

    def _run_ssh_test(self) -> None:
        self._run_ssh_task(
            "SSH test",
            lambda h, u, p, port: test_ssh_connection_sync(host=h, username=u, password=p, port=port),
        )

    def _run_full_diag(self) -> None:
        self._run_ssh_task(
            "diagnostics",
            lambda h, u, p, port: run_server_diagnostics_sync(host=h, username=u, password=p, port=port),
        )

    def _build_console_tab(self, parent) -> None:
        def on_connected() -> None:
            if self._selected_id:
                self.vault.touch(self._selected_id)

        self.console = SSHConsolePanel(
            parent,
            self.session,
            get_credentials=self._credentials,
            on_connected=on_connected,
            parent_window=self.win,
        )
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        self.console.grid(row=0, column=0, sticky="nsew", padx=6, pady=6)

    def _build_vault_tab(self, parent) -> None:
        inner = ctk.CTkFrame(parent, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=8, pady=8)
        self.vault_list = CopyableTextbox(
            inner, show_toolbar=True, read_only=True, height=400,
            font=ctk.CTkFont(family="Consolas", size=11), fg_color=BG_DARK,
        )
        self.vault_list.pack(fill="both", expand=True)
        ctk.CTkButton(inner, text="Refresh list", command=self._render_vault_list).pack(pady=6)
        self._render_vault_list()

    def _render_vault_list(self) -> None:
        profiles = self.vault.list_profiles()
        if not profiles:
            self.vault_list.set_text("No saved servers.\nUse Save on the profile bar after entering credentials.\n")
            return
        lines = ["Saved SSH Servers (encrypted at rest)", "═" * 52, ""]
        for p in profiles:
            lines.append(f"  [{p.id}] {p.label}")
            lines.append(f"      {p.username}@{p.host}:{p.port}  region={p.region or '—'}")
            if p.notes:
                lines.append(f"      notes: {p.notes}")
            lines.append(f"      last used: {p.last_used or 'never'}")
            lines.append("")
        lines.append(f"  Storage: {DB_FILE}")
        self.vault_list.set_text("\n".join(lines))

    def _on_close(self) -> None:
        self._closed = True
        if hasattr(self, "console"):
            self.console.mark_closed()
        self.session.disconnect()
        try:
            self.win.destroy()
        except Exception:
            pass
