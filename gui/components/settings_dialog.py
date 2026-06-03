"""Settings dialog."""

from __future__ import annotations

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_entry_clipboard
from gui.components.modal_utils import configure_modal
from utils.branding import TELEGRAM_HANDLE, TELEGRAM_URL, developer_credit
from utils.settings import AppSettings, get_settings, save_settings


class SettingsDialog(ctk.CTkToplevel):
    """Application settings window."""

    def __init__(self, master, on_save=None) -> None:
        super().__init__(master)
        self.title("Settings")
        self.geometry("420x580")
        self.resizable(False, False)
        self.on_save = on_save
        self.settings = get_settings()

        scroll = ctk.CTkScrollableFrame(self)
        scroll.pack(fill="both", expand=True, padx=12, pady=12)

        self._fields: dict = {}

        self._add_option(scroll, "Appearance", "appearance_mode", ["dark", "light", "system"])
        self._add_switch(scroll, "Run Xray Test", "run_xray_test")
        self._add_switch(scroll, "Real Proxy Test (SOCKS)", "real_proxy_test")
        self._add_switch(scroll, "Mask Secrets in UI", "mask_secrets_ui")
        self._add_switch(scroll, "Redact Secrets on Export", "redact_secrets_export")
        self._add_switch(scroll, "Enable Traceroute", "enable_traceroute")
        self._add_switch(scroll, "Enable Threat Intel", "enable_threat_intel")
        self._add_switch(scroll, "Enable Cert Transparency", "enable_cert_transparency")
        self._add_switch(scroll, "Enable Health Monitor", "enable_health_monitor")

        self._add_entry(scroll, "Health Check Interval (min)", "health_check_interval_min")
        self._add_entry(scroll, "Latency Samples", "latency_samples")
        self._add_entry(scroll, "Cloud Sync URL", "cloud_sync_url")
        self._add_entry(scroll, "Cloud Sync Token", "cloud_sync_token")
        self._add_entry(scroll, "IP-API Key (optional)", "ip_api_key")

        about = ctk.CTkFrame(scroll, fg_color="#1a2744", corner_radius=8)
        about.pack(fill="x", pady=(16, 8))
        ctk.CTkLabel(
            about,
            text="About",
            font=ctk.CTkFont(weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))
        ctk.CTkLabel(
            about,
            text=developer_credit(),
            justify="left",
            wraplength=360,
        ).pack(anchor="w", padx=12, pady=(0, 2))
        ctk.CTkLabel(
            about,
            text=f"Telegram: {TELEGRAM_HANDLE}\n{TELEGRAM_URL}",
            justify="left",
            text_color="#8888aa",
            wraplength=360,
        ).pack(anchor="w", padx=12, pady=(0, 10))

        ctk.CTkButton(self, text="Save", command=self._save, fg_color="#0066cc").pack(pady=10)
        configure_modal(self, master)

    def _add_switch(self, parent, label: str, key: str) -> None:
        var = ctk.BooleanVar(value=getattr(self.settings, key))
        sw = ctk.CTkSwitch(parent, text=label, variable=var)
        sw.pack(anchor="w", pady=4)
        self._fields[key] = var

    def _add_option(self, parent, label: str, key: str, values: list[str]) -> None:
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(weight="bold")).pack(anchor="w", pady=(8, 2))
        var = ctk.StringVar(value=getattr(self.settings, key))
        menu = ctk.CTkOptionMenu(parent, values=values, variable=var)
        menu.pack(fill="x", pady=2)
        self._fields[key] = var

    def _add_entry(self, parent, label: str, key: str) -> None:
        ctk.CTkLabel(parent, text=label).pack(anchor="w", pady=(6, 0))
        val = getattr(self.settings, key) or ""
        entry = ctk.CTkEntry(parent)
        entry.insert(0, str(val))
        entry.pack(fill="x", pady=2)
        bind_entry_clipboard(entry)
        self._fields[key] = entry

    def _save(self) -> None:
        data = self.settings.model_dump()
        for key, widget in self._fields.items():
            if isinstance(widget, ctk.BooleanVar):
                data[key] = widget.get()
            elif isinstance(widget, ctk.StringVar):
                data[key] = widget.get()
            else:
                val = widget.get()
                if key in ("health_check_interval_min", "latency_samples"):
                    try:
                        data[key] = int(val)
                    except ValueError:
                        pass
                else:
                    data[key] = val or None
        new_settings = AppSettings.model_validate(data)
        save_settings(new_settings)
        ctk.set_appearance_mode(new_settings.appearance_mode)
        if self.on_save:
            self.on_save(new_settings)
        try:
            self.grab_release()
        except Exception:
            pass
        self.destroy()
