"""Main application window."""

from __future__ import annotations

import asyncio
import threading
import tkinter.messagebox as messagebox
from pathlib import Path
from tkinter import filedialog
from typing import Optional

import customtkinter as ctk

from backend.analyzer import ConfigAnalyzer
from backend.cloud_sync import sync_download
from backend.config_generator import generate_client_config_json
from backend.config_parser import fetch_subscription
from backend.diff_tool import diff_configs, format_diff_text
from backend.health_monitor import HealthMonitor
from backend.models import AnalysisResult, BatchAnalysisResult
from database.db import AnalysisDatabase
from gui.components.batch_panel import BatchResultsPanel
from gui.components.history_panel import HistoryPanel
from gui.components.log_panel import LogPanel
from gui.components.modal_utils import configure_modal
from gui.components.progress_bar import AnalysisProgressBar
from gui.components.settings_dialog import SettingsDialog
from gui.components.clipboard_bindings import bind_textbox_clipboard
from gui.components.sidebar import Sidebar
from gui.components.status_panel import StatusPanel
from gui.components.toast import ToastNotification
from gui.tabs.analysis_tabs import AnalysisTabs
from reports.exporter import BatchReportExporter, ReportExporter
from utils.branding import developer_credit
from utils.logger import setup_logging, get_logger
from utils.qrcode_gen import generate_qr_for_config, save_qr_png
from utils.settings import get_settings, load_settings
from utils.ui_theme import (
    CONTENT_LOG_RATIO,
    HISTORY_MIN_HEIGHT,
    LEFT_CONFIG_HISTORY_RATIO,
    LOG_MIN_HEIGHT,
    SIDEBAR_WIDTH,
    STATUS_WIDTH,
    TOOLBAR_BG,
)
from xray.manager import XrayManager

logger = get_logger(__name__)


class XrayAnalyzerApp(ctk.CTk):
    """Xray Config Analyzer Pro — main window."""

    APP_TITLE = "Xray Config Analyzer Pro"
    APP_VERSION = "2.0.0"

    def __init__(self) -> None:
        super().__init__()
        settings = load_settings()
        setup_logging()
        ctk.set_appearance_mode(settings.appearance_mode)
        ctk.set_default_color_theme(settings.color_theme)

        self.title(f"{self.APP_TITLE} v{self.APP_VERSION}")
        self.minsize(1200, 760)

        self.analyzer = ConfigAnalyzer()
        self.database = AnalysisDatabase()
        self.xray_manager = XrayManager()
        self._result: Optional[AnalysisResult] = None
        self._batch: Optional[BatchAnalysisResult] = None
        self._analyzing = False
        self._compare_result: Optional[AnalysisResult] = None

        self._build_ui()
        self.update_idletasks()
        self._maximize_window()
        self._health_monitor = HealthMonitor(on_result=self._on_health_check)
        if settings.enable_health_monitor:
            self._health_monitor.start()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        toolbar = ctk.CTkFrame(self, height=44, fg_color=TOOLBAR_BG, corner_radius=0)
        toolbar.pack(fill="x")
        toolbar.pack_propagate(False)

        ctk.CTkLabel(
            toolbar, text=f"⚡ {self.APP_TITLE}",
            font=ctk.CTkFont(size=18, weight="bold"), text_color="#00d4ff",
        ).pack(side="left", padx=15)

        ctk.CTkLabel(
            toolbar,
            text=developer_credit(),
            font=ctk.CTkFont(size=11),
            text_color="#8888aa",
        ).pack(side="left")

        ctk.CTkButton(toolbar, text="⚙ Settings", width=90, command=self._open_settings).pack(side="right", padx=5, pady=5)

        export_menu = ctk.CTkOptionMenu(
            toolbar,
            values=["Export JSON", "Export CSV", "Export Markdown", "Export HTML", "Export PDF", "Export Batch CSV"],
            command=self._export, width=160,
        )
        export_menu.set("Export...")
        export_menu.pack(side="right", padx=10, pady=5)

        ctk.CTkButton(toolbar, text="📱 QR Code", width=100, command=self._show_qr).pack(side="right", padx=5, pady=5)
        ctk.CTkButton(toolbar, text="📋 Copy JSON", width=110, command=self._copy_json).pack(side="right", padx=5, pady=5)
        ctk.CTkButton(toolbar, text="Generate Config", width=120, command=self._generate_config).pack(side="right", padx=5, pady=5)
        ctk.CTkButton(toolbar, text="Diff", width=70, command=self._diff_configs).pack(side="right", padx=5, pady=5)
        ctk.CTkButton(toolbar, text="Cloud Sync", width=100, command=self._cloud_sync).pack(side="right", padx=5, pady=5)

        self.xray_btn = ctk.CTkButton(toolbar, text="Download Xray", width=120, command=self._download_xray)
        self.xray_btn.pack(side="right", padx=5, pady=5)

        self.progress = AnalysisProgressBar(self)
        self.progress.pack(fill="x", padx=8, pady=(5, 0))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=10, pady=(6, 10))
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=CONTENT_LOG_RATIO[0], minsize=420)
        body.grid_rowconfigure(1, weight=CONTENT_LOG_RATIO[1], minsize=LOG_MIN_HEIGHT)

        content = ctk.CTkFrame(body, fg_color="transparent")
        content.grid(row=0, column=0, sticky="nsew")
        content.grid_columnconfigure(0, weight=0, minsize=SIDEBAR_WIDTH)
        content.grid_columnconfigure(1, weight=1)
        content.grid_columnconfigure(2, weight=0, minsize=STATUS_WIDTH)
        content.grid_rowconfigure(0, weight=1)

        left_col = ctk.CTkFrame(content, fg_color="transparent")
        left_col.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left_col.grid_columnconfigure(0, weight=1)
        left_col.grid_rowconfigure(0, weight=LEFT_CONFIG_HISTORY_RATIO[0], minsize=240)
        left_col.grid_rowconfigure(1, weight=LEFT_CONFIG_HISTORY_RATIO[1], minsize=HISTORY_MIN_HEIGHT)

        self.sidebar = Sidebar(
            left_col, on_analyze=self._start_analysis, on_subscription=self._start_subscription,
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.history_panel = HistoryPanel(left_col, on_load=self._load_history)
        self.history_panel.grid(row=1, column=0, sticky="nsew", pady=(8, 0))

        center = ctk.CTkFrame(content, fg_color="transparent")
        center.grid(row=0, column=1, sticky="nsew", padx=(0, 8))
        center.grid_columnconfigure(0, weight=1)
        center.grid_rowconfigure(1, weight=1)

        self.batch_panel = BatchResultsPanel(center, on_select=self._select_batch_result, height=72)
        self.batch_panel.grid(row=0, column=0, sticky="ew", pady=(0, 4))

        self.tabs = AnalysisTabs(center)
        self.tabs.grid(row=1, column=0, sticky="nsew")

        self.status_panel = StatusPanel(content, width=STATUS_WIDTH)
        self.status_panel.grid(row=0, column=2, sticky="nsew")

        self.log_panel = LogPanel(body)
        self.log_panel.grid(row=1, column=0, sticky="nsew")

        self.toast = ToastNotification(self)

        self.log_panel.log(f"{self.APP_TITLE} v{self.APP_VERSION} started.")
        self.log_panel.log(developer_credit())
        if self.xray_manager.is_installed():
            ver = self.xray_manager.get_version()
            self.log_panel.log(f"Xray-core detected: {ver}")
            self.xray_btn.configure(text="Xray ✓", fg_color="#006633")
        else:
            self.log_panel.log("⚠ Xray-core not installed — click Download Xray.")
            self.status_panel.set_xray_installed(False)

    def _maximize_window(self) -> None:
        """Open maximized on Windows/Linux; full screen on macOS."""
        try:
            self.state("zoomed")
        except Exception:
            try:
                self.attributes("-zoomed", True)
            except Exception:
                sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
                self.geometry(f"{sw}x{sh}+0+0")

    def _log(self, msg: str) -> None:
        self.after(0, lambda: self.log_panel.log(msg))

    def _update_stage(self, cur: int, total: int, name: str) -> None:
        self.after(0, lambda: self.progress.update_stage(cur, total, name))

    def _start_analysis(self, text: str) -> None:
        if self._analyzing:
            messagebox.showwarning("Busy", "Analysis already in progress.")
            return
        self._analyzing = True
        self.status_panel.reset()
        self.tabs.clear()
        self.batch_panel.clear()
        self.progress.start()
        self.log_panel.log("Starting analysis...")
        threading.Thread(target=self._run_analysis, args=(text,), daemon=True).start()

    def _run_analysis(self, text: str) -> None:
        try:
            batch = self.analyzer.analyze_sync(
                text,
                progress_callback=self._log,
                stage_callback=self._update_stage,
            )
            self._batch = batch
            if batch.results:
                self._result = batch.results[0]
                self.after(0, lambda: self._on_analysis_complete(batch))
            else:
                err = "\n".join(batch.errors) or "No valid config found."
                self.after(0, lambda: messagebox.showerror("Parse Error", err))
        except ValueError as exc:
            self.after(0, lambda: messagebox.showerror("Parse Error", str(exc)))
        except Exception as exc:
            logger.exception("Analysis failed")
            self.after(0, lambda: messagebox.showerror("Error", str(exc)))
        finally:
            self._analyzing = False
            self.after(0, self.progress.complete)

    def _on_analysis_complete(self, batch: BatchAnalysisResult) -> None:
        result = batch.results[0]
        self.tabs.update_result(result)
        self.status_panel.update_result(result)
        self.batch_panel.update_batch(batch)
        self.database.save_batch(batch)
        self.history_panel.refresh()
        self.toast.show(f"Analysis complete — Score: {result.security.score}/100")
        self.log_panel.log(
            f"Done — {len(batch.results)} config(s) | "
            f"{result.config.protocol.value} {result.config.address}:{result.config.port} | "
            f"Score: {result.security.score}/100"
        )

    def _select_batch_result(self, result: AnalysisResult) -> None:
        self._result = result
        self.tabs.update_result(result)
        self.status_panel.update_result(result)

    def _load_history(self, analysis_id: int) -> None:
        result = self.database.load(analysis_id)
        if result:
            self._result = result
            self.tabs.update_result(result)
            self.status_panel.update_result(result)
            self.toast.show(f"Loaded history #{analysis_id}")

    def _start_subscription(self, url: str) -> None:
        if self._analyzing:
            messagebox.showwarning("Busy", "Analysis already in progress.")
            return
        self._analyzing = True
        self.log_panel.log(f"Fetching subscription: {url[:60]}...")
        threading.Thread(target=self._run_subscription, args=(url,), daemon=True).start()

    def _run_subscription(self, url: str) -> None:
        try:
            configs = asyncio.run(fetch_subscription(url))
            if not configs:
                self.after(0, lambda: messagebox.showerror(
                    "Subscription Error",
                    "No configs found. Check URL, network, or subscription format.",
                ))
                return
            lines = "\n".join(c.raw_url for c in configs if c.raw_url)
            if not lines:
                lines = "\n".join(f"{c.protocol.value}://..." for c in configs)
            self.after(0, lambda: self.sidebar.set_text(lines))
            self._run_analysis(lines)
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Subscription Error", str(exc)))
        finally:
            self._analyzing = False

    def _download_xray(self) -> None:
        self.log_panel.log("Downloading Xray-core...")
        threading.Thread(target=self._run_xray_download, daemon=True).start()

    def _run_xray_download(self) -> None:
        try:
            ok = asyncio.run(self.xray_manager.download_latest(self._log))
            if ok:
                ver = self.xray_manager.get_version()
                self.after(0, lambda: self.log_panel.log(f"Xray installed: {ver}"))
                self.after(0, lambda: self.xray_btn.configure(text="Xray ✓", fg_color="#006633"))
                self.after(0, lambda: self.status_panel.set_xray_installed(True))
                self.after(0, lambda: self.toast.show("Xray installed successfully"))
            else:
                self.after(0, lambda: messagebox.showerror("Error", "Failed to download Xray-core."))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Error", str(exc)))

    def _copy_json(self) -> None:
        if not self._result:
            messagebox.showinfo("Copy JSON", "Run analysis first.")
            return
        json_text = self.tabs.get_full_json()
        self.clipboard_clear()
        self.clipboard_append(json_text)
        self.toast.show("JSON copied to clipboard")

    def _show_qr(self) -> None:
        if not self._result:
            messagebox.showinfo("QR Code", "Run analysis first.")
            return
        png_bytes, link = generate_qr_for_config(self._result.config)
        if not link:
            messagebox.showwarning("QR Code", "No share link (raw_url) in this config.")
            return

        win = ctk.CTkToplevel(self)
        win.title("Config QR Code")
        win.geometry("360x480")
        win.resizable(False, False)

        import io
        from PIL import Image

        img = Image.open(io.BytesIO(png_bytes))
        ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=(280, 280))
        ctk.CTkLabel(win, image=ctk_img, text="").pack(pady=10)
        ctk.CTkLabel(win, text="Scan with v2rayNG / Streisand / Hiddify", font=ctk.CTkFont(size=12)).pack()

        link_box = ctk.CTkTextbox(win, height=60, font=ctk.CTkFont(size=10))
        link_box.pack(fill="x", padx=15, pady=8)
        link_box.insert("1.0", link)
        bind_textbox_clipboard(link_box, editable=False)

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=8)

        def copy_link() -> None:
            self.clipboard_clear()
            self.clipboard_append(link)
            self.toast.show("Link copied")

        def save_png() -> None:
            path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
            if path:
                save_qr_png(self._result.config, Path(path))
                self.toast.show(f"Saved {path}")

        ctk.CTkButton(btn_row, text="Copy Link", command=copy_link, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_row, text="Save PNG", command=save_png, width=100).pack(side="left", padx=5)
        configure_modal(win, self)

    def _generate_config(self) -> None:
        if not self._result:
            messagebox.showinfo("Generate", "Run analysis first.")
            return
        cfg_json = generate_client_config_json(self._result.config)
        win = ctk.CTkToplevel(self)
        win.title("Generated Xray Client Config")
        win.geometry("600x400")
        tb = ctk.CTkTextbox(win, font=ctk.CTkFont(family="Consolas", size=11))
        tb.pack(fill="both", expand=True, padx=10, pady=10)
        bind_textbox_clipboard(tb, editable=False)
        tb.insert("1.0", cfg_json)
        configure_modal(win, self)

    def _diff_configs(self) -> None:
        if not self._result:
            messagebox.showinfo("Diff", "Analyze a config first (A).")
            return
        if not self._compare_result:
            self._compare_result = self._result
            self.toast.show("Config A saved. Analyze another for Config B.")
            return
        text = format_diff_text(diff_configs(self._compare_result.config, self._result.config))
        win = ctk.CTkToplevel(self)
        win.title("Config Diff")
        win.geometry("500x400")
        tb = ctk.CTkTextbox(win, font=ctk.CTkFont(family="Consolas", size=11))
        tb.pack(fill="both", expand=True, padx=10, pady=10)
        bind_textbox_clipboard(tb, editable=False)
        tb.insert("1.0", text)
        self._compare_result = None
        configure_modal(win, self)

    def _cloud_sync(self) -> None:
        if not get_settings().cloud_sync_url:
            messagebox.showinfo("Cloud Sync", "Set Cloud Sync URL in Settings first.")
            return
        threading.Thread(target=self._run_cloud_sync, daemon=True).start()

    def _run_cloud_sync(self) -> None:
        try:
            items = asyncio.run(sync_download())
            self.after(0, lambda: self.toast.show(f"Synced {len(items)} items from cloud"))
        except Exception as exc:
            self.after(0, lambda: messagebox.showerror("Sync Error", str(exc)))

    def _open_settings(self) -> None:
        SettingsDialog(self, on_save=self._on_settings_saved)

    def _on_settings_saved(self, settings) -> None:
        self.analyzer = ConfigAnalyzer()
        if settings.enable_health_monitor:
            self._health_monitor.start()
        else:
            self._health_monitor.stop()
        self.toast.show("Settings saved")

    def _on_health_check(self, analysis_id: int, status: str, score: int) -> None:
        self.after(0, lambda: self.history_panel.refresh())
        if status == "DEGRADED":
            self.after(0, lambda: self.toast.show(f"Health alert: #{analysis_id} degraded ({score}/100)", color="#883333"))

    def _export(self, choice: str) -> None:
        if choice == "Export Batch CSV":
            if not self._batch or not self._batch.results:
                messagebox.showinfo("Export", "No batch results.")
                return
            path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if path:
                BatchReportExporter(self._batch).save(Path(path), "csv")
                self.toast.show(f"Exported batch to {path}")
            return

        if not self._result:
            messagebox.showinfo("Export", "No analysis result. Run analysis first.")
            return

        fmt_map = {
            "Export JSON": ("json", "JSON files", "*.json"),
            "Export CSV": ("csv", "CSV files", "*.csv"),
            "Export Markdown": ("md", "Markdown files", "*.md"),
            "Export HTML": ("html", "HTML files", "*.html"),
            "Export PDF": ("pdf", "PDF files", "*.pdf"),
        }
        fmt, desc, pattern = fmt_map.get(choice, ("json", "All", "*.*"))
        path = filedialog.asksaveasfilename(defaultextension=f".{fmt}", filetypes=[(desc, pattern)])
        if path:
            try:
                ReportExporter(self._result).save(Path(path), fmt)
                self.toast.show(f"Exported to {path}")
            except Exception as exc:
                messagebox.showerror("Export Error", str(exc))

    def _on_close(self) -> None:
        self._health_monitor.stop()
        self.destroy()

    def run(self) -> None:
        self.mainloop()


def main() -> None:
    app = XrayAnalyzerApp()
    app.run()


if __name__ == "__main__":
    main()
