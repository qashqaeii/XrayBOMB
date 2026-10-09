"""Professional SSH terminal panel for Remote Server Manager."""

from __future__ import annotations

import threading
from tkinter import messagebox
from typing import Callable, Optional

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_entry_clipboard
from gui.components.copyable_text import CopyableTextbox
from tools.ssh_interactive import SSHInteractiveSession
from utils.ui_theme import ACCENT_BTN, ACCENT_BTN_HOVER, PANEL_BG, PANEL_BORDER, PANEL_PAD, TEXT_DIM, TEXT_MUTED

TERM_BG = "#0a0e14"
TERM_BORDER = "#30363d"
TERM_HEADER = "#161b22"
PROMPT_COLOR = "#3fb950"
STATUS_OFF = "#6e7681"
STATUS_ON = "#3fb950"
STATUS_BUSY = "#d29922"
STATUS_ERR = "#f85149"

QUICK_COMMANDS: tuple[tuple[str, str], ...] = (
    ("uname", "uname -a"),
    ("disk", "df -h"),
    ("memory", "free -h"),
    ("uptime", "uptime"),
    ("IPs", "ip -4 addr show"),
    ("listening", "ss -tlnp"),
    ("updates", "apt list --upgradable 2>/dev/null | head -15"),
    ("xray status", "systemctl status xray 2>/dev/null || systemctl status x-ui 2>/dev/null || echo 'no xray'"),
    ("clear", "clear"),
)

WELCOME = (
    "SSH Terminal — connect above, then type commands.\n"
    "Shortcuts: Enter send · ↑↓ history · Ctrl+C interrupt · Ctrl+L clear\n"
    "Panel install & SSL: use the «Server Setup» tab.\n\n"
)


class SSHConsolePanel(ctk.CTkFrame):
    """Live SSH shell — terminal expands; quick commands in a tidy row."""

    def __init__(
        self,
        master,
        session: SSHInteractiveSession,
        *,
        get_credentials: Callable[[], tuple[str, str, str, int] | None],
        on_connected: Optional[Callable[[], None]] = None,
        parent_window: Optional[ctk.CTkToplevel] = None,
    ) -> None:
        super().__init__(master, fg_color="transparent")
        self.session = session
        self.get_credentials = get_credentials
        self.on_connected = on_connected
        self._parent_win = parent_window
        self._history: list[str] = []
        self._hist_idx = -1
        self._hist_draft = ""
        self._closed = False
        self._font_size = 13
        self._connecting = False

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_chrome()
        self._build_terminal()
        self._build_command_bar()
        self._build_quick_bar()
        self._build_footer()

    def _entry(self, parent, **kwargs) -> ctk.CTkEntry:
        e = ctk.CTkEntry(parent, **kwargs)
        bind_entry_clipboard(e)
        return e

    def _build_chrome(self) -> None:
        chrome = ctk.CTkFrame(self, fg_color=TERM_HEADER, corner_radius=PANEL_PAD, border_width=1, border_color=TERM_BORDER)
        chrome.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        chrome.columnconfigure(0, weight=1)

        top = ctk.CTkFrame(chrome, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 6))
        top.columnconfigure(1, weight=1)

        self.status_dot = ctk.CTkLabel(top, text="●", font=ctk.CTkFont(size=16), text_color=STATUS_OFF, width=22)
        self.status_dot.grid(row=0, column=0, rowspan=2, sticky="nw")
        ctk.CTkLabel(
            top, text="SSH Terminal", font=ctk.CTkFont(size=15, weight="bold"), text_color="#e6edf3",
        ).grid(row=0, column=1, sticky="w", padx=(4, 0))
        self.endpoint_lbl = ctk.CTkLabel(
            top, text="Not connected", font=ctk.CTkFont(family="Consolas", size=11), text_color=TEXT_MUTED, anchor="w",
        )
        self.endpoint_lbl.grid(row=1, column=1, sticky="w", padx=(4, 0))

        tools = ctk.CTkFrame(top, fg_color="transparent")
        tools.grid(row=0, column=2, rowspan=2, sticky="e")
        for text, cmd, color, hover in (
            ("Connect", self.connect, "#238636", "#2ea043"),
            ("Disconnect", self.disconnect, "#6e3630", "#8b4640"),
            ("Clear", self.clear, "#21262d", "#30363d"),
        ):
            ctk.CTkButton(tools, text=text, width=96, height=32, fg_color=color, hover_color=hover, command=cmd).pack(
                side="left", padx=3,
            )
        ctk.CTkButton(
            tools, text="Copy All", width=80, height=32, fg_color="#21262d", hover_color="#30363d",
            command=lambda: self.term_out.copy_all(),
        ).pack(side="left", padx=3)
        ctk.CTkButton(
            tools, text="A−", width=40, height=32, fg_color="#21262d", hover_color="#30363d",
            command=lambda: self._font_delta(-1),
        ).pack(side="left", padx=2)
        ctk.CTkButton(
            tools, text="A+", width=40, height=32, fg_color="#21262d", hover_color="#30363d",
            command=lambda: self._font_delta(1),
        ).pack(side="left", padx=2)

        self.conn_status = ctk.CTkLabel(
            chrome, text="Disconnected", font=ctk.CTkFont(size=11), text_color=TEXT_DIM, anchor="w",
        )
        self.conn_status.grid(row=1, column=0, sticky="w", padx=14, pady=(0, 10))

    def _build_terminal(self) -> None:
        frame = ctk.CTkFrame(self, fg_color=TERM_BG, corner_radius=8, border_width=1, border_color=TERM_BORDER)
        frame.grid(row=1, column=0, sticky="nsew", pady=(0, 8))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.term_out = CopyableTextbox(
            frame,
            show_toolbar=False,
            read_only=True,
            height=200,
            font=ctk.CTkFont(family="Consolas", size=self._font_size),
            wrap="none",
            fg_color=TERM_BG,
            text_color="#c9d1d9",
            corner_radius=0,
            border_width=0,
        )
        self.term_out.grid(row=0, column=0, sticky="nsew", padx=3, pady=3)
        self.term_out.set_text(WELCOME)

    def _build_command_bar(self) -> None:
        bar = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=PANEL_PAD, border_width=1, border_color=PANEL_BORDER)
        bar.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        bar.columnconfigure(1, weight=1)

        self.prompt_lbl = ctk.CTkLabel(
            bar, text="$", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=PROMPT_COLOR, anchor="w",
        )
        self.prompt_lbl.grid(row=0, column=0, sticky="w", padx=(12, 8), pady=12)

        self.cmd_e = self._entry(
            bar, placeholder_text="Type command and press Enter…",
            font=ctk.CTkFont(family="Consolas", size=13), height=38, border_color=TERM_BORDER,
        )
        self.cmd_e.grid(row=0, column=1, sticky="ew", padx=4, pady=10)
        self.cmd_e.bind("<Return>", self.send_command)
        self.cmd_e.bind("<Up>", self._history_up)
        self.cmd_e.bind("<Down>", self._history_down)
        self.cmd_e.bind("<Control-c>", self._on_ctrl_c)
        self.cmd_e.bind("<Control-l>", lambda _e: (self.clear(), "break"))
        self.cmd_e.bind("<Control-d>", lambda _e: (self._send_eof(), "break"))

        btns = ctk.CTkFrame(bar, fg_color="transparent")
        btns.grid(row=0, column=2, sticky="e", padx=(4, 12), pady=10)
        ctk.CTkButton(
            btns, text="Interrupt", width=88, height=36,
            fg_color="#6e3630", hover_color="#8b4640", command=self.send_interrupt,
        ).pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            btns, text="Send", width=80, height=36,
            fg_color=ACCENT_BTN, hover_color=ACCENT_BTN_HOVER, command=self.send_command,
        ).pack(side="right")

    def _build_quick_bar(self) -> None:
        box = ctk.CTkFrame(self, fg_color=PANEL_BG, corner_radius=PANEL_PAD, border_width=1, border_color=PANEL_BORDER)
        box.grid(row=3, column=0, sticky="ew")
        box.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            box, text="Shell shortcuts", font=ctk.CTkFont(size=11, weight="bold"), text_color=TEXT_MUTED,
        ).grid(row=0, column=0, sticky="w", padx=12, pady=(10, 6))

        grid = ctk.CTkFrame(box, fg_color="transparent")
        grid.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 12))
        cols = 5
        for i, (label, cmd) in enumerate(QUICK_COMMANDS):
            r, c = divmod(i, cols)
            ctk.CTkButton(
                grid, text=label, height=30, font=ctk.CTkFont(size=11),
                fg_color="#21262d", hover_color="#30363d",
                command=lambda c=cmd: self.run_quick(c),
            ).grid(row=r, column=c, sticky="ew", padx=4, pady=4)
            grid.columnconfigure(c, weight=1)

    def _build_footer(self) -> None:
        ctk.CTkLabel(
            self, text="Server setup (panels, SSL, apt) → open the «Server Setup» tab",
            font=ctk.CTkFont(size=10), text_color=TEXT_DIM,
        ).grid(row=4, column=0, sticky="w", padx=4, pady=(8, 0))

    def _font_delta(self, delta: int) -> None:
        self._font_size = max(9, min(20, self._font_size + delta))
        self.term_out.textbox.configure(font=ctk.CTkFont(family="Consolas", size=self._font_size))

    def _set_status(self, state: str, message: str) -> None:
        colors = {"off": STATUS_OFF, "on": STATUS_ON, "busy": STATUS_BUSY, "err": STATUS_ERR}
        self.status_dot.configure(text_color=colors.get(state, STATUS_OFF))
        self.conn_status.configure(text=message)

    def _update_prompt(self) -> None:
        if self.session.connected:
            ep = self.session.endpoint
            self.prompt_lbl.configure(text=f"{ep} $")
            self.endpoint_lbl.configure(text=f"Connected · {ep}")
        else:
            self.prompt_lbl.configure(text="$")
            self.endpoint_lbl.configure(text="Not connected")

    def _append(self, text: str) -> None:
        if self._closed or not text:
            return
        self.term_out.append_text(text, tag_flags=False)

    def clear(self) -> None:
        self.term_out.set_text("")

    def connect(self) -> None:
        if self._connecting or self.session.connected:
            if self.session.connected:
                messagebox.showinfo("SSH", "Already connected.", parent=self._parent_win)
            return
        creds = self.get_credentials()
        if not creds:
            messagebox.showwarning("Connect", "Enter host and username.", parent=self._parent_win)
            return
        h, u, p, port = creds
        self._connecting = True
        self._set_status("busy", f"Connecting to {u}@{h}:{port}…")
        self._append(f"\n── connecting to {u}@{h}:{port} ──\n")

        def on_output(chunk: str) -> None:
            if not self._closed:
                self.after(0, lambda c=chunk: self._append(c))

        def on_state(msg: str) -> None:
            if self._closed:
                return
            self.after(0, lambda: self._set_status("on", msg))
            self.after(0, self._update_prompt)

        def worker() -> None:
            try:
                self.session.connect(h, u, p, port, on_output=on_output, on_state=on_state)
                if not self._closed:
                    self.after(0, lambda: self.cmd_e.focus())
                    if self.on_connected:
                        self.after(0, self.on_connected)
            except Exception as exc:
                if not self._closed:
                    self.after(0, lambda: self._set_status("err", f"Failed: {exc}"))
                    self.after(0, lambda: self._append(f"\n[connect failed: {exc}]\n"))
            finally:
                self._connecting = False

        threading.Thread(target=worker, daemon=True).start()

    def disconnect(self) -> None:
        self.session.disconnect()
        self._set_status("off", "Disconnected")
        self._update_prompt()
        self._append("\n── disconnected ──\n")

    def send_command(self, _event=None) -> None:
        if not self.session.connected:
            messagebox.showinfo("Console", "Connect first.", parent=self._parent_win)
            return
        line = self.cmd_e.get()
        if line in self._history[-1:] if self._history else False:
            pass
        elif line.strip():
            self._history.append(line)
        self._hist_idx = len(self._history)
        self._hist_draft = ""
        self.cmd_e.delete(0, "end")
        try:
            self.session.send_line(line)
        except Exception as exc:
            self._append(f"\n[send error: {exc}]\n")

    def send_interrupt(self) -> None:
        if self.session.connected:
            try:
                self.session.send_interrupt()
            except Exception as exc:
                self._append(f"\n[interrupt error: {exc}]\n")

    def _send_eof(self) -> None:
        if self.session.connected:
            try:
                self.session.send_eof()
            except Exception as exc:
                self._append(f"\n[eof error: {exc}]\n")

    def _on_ctrl_c(self, _event=None) -> str:
        if self.session.connected:
            self.send_interrupt()
            return "break"
        return None

    def run_quick(self, cmd: str) -> None:
        self.cmd_e.delete(0, "end")
        self.cmd_e.insert(0, cmd)
        if self.session.connected:
            self.send_command()
        else:
            self.cmd_e.focus()

    def _history_up(self, _event=None) -> str:
        if not self._history:
            return "break"
        if self._hist_idx >= len(self._history):
            self._hist_draft = self.cmd_e.get()
        if self._hist_idx > 0:
            self._hist_idx -= 1
        elif self._hist_idx < 0:
            self._hist_idx = 0
        self.cmd_e.delete(0, "end")
        self.cmd_e.insert(0, self._history[self._hist_idx])
        return "break"

    def _history_down(self, _event=None) -> str:
        if not self._history:
            return "break"
        if self._hist_idx < len(self._history) - 1:
            self._hist_idx += 1
            self.cmd_e.delete(0, "end")
            self.cmd_e.insert(0, self._history[self._hist_idx])
        else:
            self._hist_idx = len(self._history)
            self.cmd_e.delete(0, "end")
            self.cmd_e.insert(0, self._hist_draft)
        return "break"

    def mark_closed(self) -> None:
        self._closed = True
