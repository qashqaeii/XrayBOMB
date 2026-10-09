"""Tools launcher + professional per-tool modals."""

from __future__ import annotations

from typing import Callable, Optional

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_entry_clipboard
from gui.components.copyable_text import CopyableTextbox
from gui.components.modal_utils import configure_modal
from gui.tools.tool_framework import AsyncToolWindow, LogFn
from gui.tools.extended_modals import register_extended_openers
from tools.clean_ip_finder import find_clean_cloudflare_ips_sync
from tools.client_profile import build_client_profile_sync
from tools.cloudflare_ranges import REGION_OPTIONS, SCAN_SOURCE_MODES
from tools.asn_dc_lookup import lookup_asn_dc_sync
from tools.multi_dc_compare import COMPARE_COUNTRIES, compare_countries_sync
from tools.vps_deploy_check import validate_vps_deploy_sync
from tools.vps_ip_ranker import rank_vps_ips_sync
from tools.datacenter_finder import benchmark_datacenters_sync
from tools.dns_health import analyze_dns_health_sync
from tools.formatters import format_clean_ip, format_datacenter
from tools.host_benchmark import benchmark_host_sync
from tools.infrastructure_advisor import build_marketplace_report_sync
from tools.infrastructure_catalog import (
    CATEGORY_LABELS,
    DC_TYPES,
    MARKETPLACE_COUNTRIES,
    ROLE_LABELS,
    TIER_LABELS,
)
from tools.ip_checker import check_ip_or_host_sync
from tools.isp_iran_guide import ISPS, build_isp_guide
from tools.port_scanner import PRESETS, scan_ports_sync
from tools.provider_catalog import TARGET_COUNTRIES
from tools.registry import CATEGORIES, TOOL_SPECS, ToolSpec
from tools.subscription_health import check_subscription_sync
from tools.tunnel_route_planner import GOALS, ORIGIN_COUNTRIES, build_tunnel_plan
from utils.ui_theme import ACCENT_BTN, ACCENT_BTN_HOVER, PANEL_BG, PANEL_BORDER


def _entry(parent, **kwargs) -> ctk.CTkEntry:
    e = ctk.CTkEntry(parent, **kwargs)
    bind_entry_clipboard(e)
    return e


def _openers(parent: ctk.CTk, log: LogFn) -> dict[str, Callable[[], None]]:
    base = {
        "client_profile": lambda: _modal_client_profile(parent, log),
        "isp_guide": lambda: _modal_isp_guide(parent, log),
        "infrastructure_market": lambda: _modal_infrastructure_market(parent, log),
        "tunnel_planner": lambda: _modal_tunnel_planner(parent, log),
        "clean_ip": lambda: _modal_clean_ip(parent, log),
        "ip_checker": lambda: _modal_ip_checker(parent, log),
        "host_benchmark": lambda: _modal_host_benchmark(parent, log),
        "port_scanner": lambda: _modal_port_scanner(parent, log),
        "datacenter": lambda: _modal_datacenter(parent, log),
        "multi_dc_compare": lambda: _modal_multi_dc_compare(parent, log),
        "vps_deploy_check": lambda: _modal_vps_deploy_check(parent, log),
        "vps_ip_ranker": lambda: _modal_vps_ip_ranker(parent, log),
        "asn_dc_lookup": lambda: _modal_asn_dc_lookup(parent, log),
        "dns_health": lambda: _modal_dns_health(parent, log),
        "subscription_health": lambda: _modal_subscription_health(parent, log),
    }
    base.update(register_extended_openers(parent, log))
    return base


def open_tools_launcher(parent: ctk.CTk, on_log: Optional[LogFn] = None) -> None:
    log = on_log or (lambda _m: None)
    openers = _openers(parent, log)

    win = ctk.CTkToplevel(parent)
    win.title("Network Tools Suite")
    win.geometry("900x680")
    win.minsize(760, 560)

    ctk.CTkLabel(
        win, text="Network Tools Suite",
        font=ctk.CTkFont(size=22, weight="bold"), text_color="#00d4ff",
    ).pack(pady=(16, 2))
    ctk.CTkLabel(
        win,
        text="Professional toolkit for operators in Iran — filtering, DPI, CDN, VPS selection",
        font=ctk.CTkFont(size=11), text_color="#8888aa",
    ).pack(pady=(0, 10))

    by_cat: dict[str, list[ToolSpec]] = {c: [] for c in CATEGORIES}
    for spec in TOOL_SPECS:
        by_cat[spec.category].append(spec)

    body = ctk.CTkFrame(win, fg_color="transparent")
    body.pack(fill="both", expand=True, padx=16, pady=8)

    tab_bar = ctk.CTkFrame(body, fg_color="#1a1a2e", corner_radius=10, border_width=1, border_color=PANEL_BORDER)
    tab_bar.pack(fill="x", pady=(0, 8))

    content_host = ctk.CTkFrame(body, fg_color="#1a1a2e", corner_radius=10, border_width=1, border_color=PANEL_BORDER)
    content_host.pack(fill="both", expand=True)

    tab_buttons: dict[str, ctk.CTkButton] = {}
    category_title = ctk.CTkLabel(
        content_host,
        text="",
        font=ctk.CTkFont(size=15, weight="bold"),
        text_color="#00d4ff",
        anchor="w",
    )

    def _short_label(cat: str) -> str:
        short = {
            "Network Context": "Network",
            "Cloudflare & CDN": "CDN",
            "VPS & Remote Server": "Remote SSH",
            "VPS & Datacenter": "Datacenter",
            "DNS Intelligence": "DNS",
            "Latency & Routing": "Latency",
            "TLS Intelligence": "TLS",
            "Xray / Sing-box": "Xray",
            "Iran Tools": "Iran",
            "Infrastructure & Buying": "Market",
        }
        return short.get(cat, cat[:14])

    def _select_category(cat: str) -> None:
        for name, btn in tab_buttons.items():
            selected = name == cat
            btn.configure(
                fg_color=ACCENT_BTN if selected else "#2a2a4a",
                hover_color=ACCENT_BTN_HOVER if selected else "#3a3a6a",
                text_color="#ffffff" if selected else "#bbbbe0",
                border_width=2 if selected else 0,
                border_color="#00d4ff" if selected else "#2a2a4a",
            )
        _render_category(cat)

    def _render_category(cat: str) -> None:
        for w in content_host.winfo_children():
            if w is not category_title:
                w.destroy()
        category_title.configure(text=cat)
        category_title.pack(fill="x", padx=14, pady=(10, 4))
        scroll = ctk.CTkScrollableFrame(content_host, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        for spec in by_cat[cat]:
            _tool_card(scroll, spec, openers[spec.tool_id])

    cats = list(CATEGORIES)
    mid = (len(cats) + 1) // 2
    for row_cats in (cats[:mid], cats[mid:]):
        row = ctk.CTkFrame(tab_bar, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=5)
        for cat in row_cats:
            btn = ctk.CTkButton(
                row,
                text=_short_label(cat),
                height=38,
                font=ctk.CTkFont(size=13, weight="bold"),
                fg_color="#2a2a4a",
                hover_color="#3a3a6a",
                corner_radius=8,
                command=lambda c=cat: _select_category(c),
            )
            btn.pack(side="left", padx=4, pady=3, expand=True, fill="x")
            tab_buttons[cat] = btn

    _select_category(CATEGORIES[0])

    ctk.CTkButton(win, text="Close", width=100, command=win.destroy).pack(pady=12)
    configure_modal(win, parent, on_close=win.destroy, modal=False)


def _tool_card(parent, spec: ToolSpec, open_fn: Callable[[], None]) -> None:
    card = ctk.CTkFrame(parent, fg_color=PANEL_BG, corner_radius=10, border_width=1, border_color=PANEL_BORDER)
    card.pack(fill="x", pady=5)
    row = ctk.CTkFrame(card, fg_color="transparent")
    row.pack(fill="x", padx=12, pady=10)

    ctk.CTkLabel(row, text=spec.icon, font=ctk.CTkFont(size=26), width=36).pack(side="left")
    col = ctk.CTkFrame(row, fg_color="transparent")
    col.pack(side="left", fill="x", expand=True, padx=(8, 10))
    ctk.CTkLabel(col, text=spec.title, anchor="w", font=ctk.CTkFont(size=13, weight="bold")).pack(fill="x")
    ctk.CTkLabel(col, text=spec.subtitle, anchor="w", font=ctk.CTkFont(size=11), text_color="#8888aa").pack(fill="x")
    ctk.CTkLabel(
        col, text=spec.description, anchor="w", wraplength=420, justify="left",
        font=ctk.CTkFont(size=10), text_color="#999999",
    ).pack(fill="x", pady=(2, 0))
    tags = " · ".join(spec.tags)
    if tags:
        ctk.CTkLabel(col, text=tags, anchor="w", font=ctk.CTkFont(size=9), text_color="#555577").pack(fill="x")

    ctk.CTkButton(
        row, text="Open", width=80, height=30,
        fg_color=ACCENT_BTN, hover_color=ACCENT_BTN_HOVER, command=open_fn,
    ).pack(side="right")


# ── Tool modals ──


def _modal_client_profile(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Client Network Profile",
        "Detect your public IP, ISP, ASN, location, and timezone (via ipwho.is).",
        on_log=log,
    )
    w.set_placeholder("Click Detect Network.\n")
    w.bind_run_with_progress("Detect Network", lambda p: build_client_profile_sync(progress=p), busy_label="Detecting...")


def _modal_clean_ip(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Cloudflare Clean IP Finder",
        "Live TCP/TLS scan — official CF list, custom CIDR, or pasted IP list. All scores measured.",
        on_log=log, size=(900, 720),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)

    r0 = ctk.CTkFrame(inner, fg_color="transparent")
    r0.pack(fill="x", pady=2)
    ctk.CTkLabel(r0, text="Source:", width=70, anchor="w").pack(side="left")
    source = ctk.CTkOptionMenu(r0, values=list(SCAN_SOURCE_MODES), width=220)
    source.set(SCAN_SOURCE_MODES[0])
    source.pack(side="left", padx=4)

    region_row = ctk.CTkFrame(inner, fg_color="transparent")
    region_row.pack(fill="x", pady=2)
    ctk.CTkLabel(region_row, text="Note:", width=70, anchor="w").pack(side="left")
    region = ctk.CTkOptionMenu(region_row, values=list(REGION_OPTIONS), width=200)
    region.set("All Cloudflare")
    region.pack(side="left", padx=4)
    ctk.CTkLabel(region_row, text="(anycast — informational only)", font=ctk.CTkFont(size=10), text_color="#666688").pack(side="left", padx=6)

    r1 = ctk.CTkFrame(inner, fg_color="transparent")
    r1.pack(fill="x", pady=2)
    ctk.CTkLabel(r1, text="SNI:", width=70, anchor="w").pack(side="left")
    sni = _entry(r1, width=240)
    sni.insert(0, "www.cloudflare.com")
    sni.pack(side="left", padx=4)
    ctk.CTkLabel(r1, text="Max IPs:", width=56).pack(side="left", padx=(8, 0))
    max_ips = ctk.CTkOptionMenu(r1, values=["24", "40", "60", "80", "120"], width=60)
    max_ips.set("40")
    max_ips.pack(side="left", padx=4)
    ctk.CTkLabel(r1, text="Samples:", width=60).pack(side="left")
    samples = ctk.CTkOptionMenu(r1, values=["4", "5", "6", "8"], width=50)
    samples.set("5")
    samples.pack(side="left", padx=4)

    custom_frame = ctk.CTkFrame(inner, fg_color="transparent")
    ctk.CTkLabel(custom_frame, text="Input:", width=70, anchor="nw").pack(side="left", anchor="n")
    custom_box = CopyableTextbox(
        custom_frame, show_toolbar=True, read_only=False, height=100,
        font=ctk.CTkFont(family="Consolas", size=11), wrap="none",
    )
    custom_box.pack(side="left", fill="x", expand=True, padx=4)
    custom_box.set_text(
        "# Custom CIDR (one per line):\n# 104.16.0.0/24\n# 172.64.0.0/24\n\n"
        "# Or custom IP list:\n# 104.16.0.1\n# 172.64.0.2\n"
    )

    def _toggle_input(_choice: str = "") -> None:
        mode = source.get()
        if mode == "Cloudflare live list":
            region_row.pack(fill="x", pady=2)
            custom_frame.pack_forget()
        else:
            region_row.pack_forget()
            custom_frame.pack(fill="x", pady=4)

    source.configure(command=_toggle_input)
    _toggle_input()

    w.set_placeholder(
        "Results are live measurements only (latency, TLS, DNSBL).\n"
        "Select text with mouse → Ctrl+C or toolbar Copy.\n"
    )

    def task(progress):
        r = find_clean_cloudflare_ips_sync(
            region=region.get(),
            sni=sni.get().strip() or "www.cloudflare.com",
            max_ips=int(max_ips.get()),
            samples=int(samples.get()),
            scan_mode=source.get(),
            custom_input=custom_box.get_text(),
            progress=progress,
        )
        log(f"Clean IP: {r.reachable}/{r.scanned} reachable")
        return format_clean_ip(r)

    w.bind_run_with_progress("Start Scan", task, busy_label="Scanning...")


def _modal_datacenter(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Datacenter Finder",
        "Parallel VPS provider benchmark — ranked for operators selling configs to Iran.",
        on_log=log, size=(860, 660),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Country:", width=70, anchor="w").pack(side="left")
    country = ctk.CTkOptionMenu(row, values=list(TARGET_COUNTRIES), width=180)
    country.set("Germany")
    country.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Port:", width=40).pack(side="left", padx=(8, 0))
    port = ctk.CTkOptionMenu(row, values=["443", "8443", "2053"], width=70)
    port.set("443")
    port.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Samples:", width=60).pack(side="left")
    samples = ctk.CTkOptionMenu(row, values=["4", "6", "8", "10"], width=60)
    samples.set("6")
    samples.pack(side="left", padx=4)

    w.set_placeholder("Select country — providers tested in parallel.\n")

    def task(progress):
        r = benchmark_datacenters_sync(
            country=country.get(), port=int(port.get()), samples=int(samples.get()), progress=progress,
        )
        log(f"DC Finder: winner {r.winner} ({r.winner_score})")
        return format_datacenter(r)

    w.bind_run_with_progress("Run Benchmark", task, busy_label="Benchmarking...")


def _modal_multi_dc_compare(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Multi-Country DC Compare",
        "Benchmark 2–3 countries in parallel — all scores measured from your network.",
        on_log=log, size=(880, 680),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    opts = ["— skip —"] + list(COMPARE_COUNTRIES)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="Country 1:", width=72, anchor="w").pack(side="left")
    c1 = ctk.CTkOptionMenu(row, values=opts, width=160)
    c1.set("Germany")
    c1.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Country 2:", width=72).pack(side="left")
    c2 = ctk.CTkOptionMenu(row, values=opts, width=160)
    c2.set("Finland")
    c2.pack(side="left", padx=4)
    row2 = ctk.CTkFrame(inner, fg_color="transparent")
    row2.pack(fill="x", pady=2)
    ctk.CTkLabel(row2, text="Country 3:", width=72, anchor="w").pack(side="left")
    c3 = ctk.CTkOptionMenu(row2, values=opts, width=160)
    c3.set("Netherlands")
    c3.pack(side="left", padx=4)
    ctk.CTkLabel(row2, text="Samples:", width=60).pack(side="left", padx=(8, 0))
    samples = ctk.CTkOptionMenu(row2, values=["4", "5", "6"], width=50)
    samples.set("5")
    samples.pack(side="left", padx=4)

    def task(progress):
        countries = [c for c in (c1.get(), c2.get(), c3.get()) if c and not c.startswith("—")]
        return compare_countries_sync(
            countries=countries, samples=int(samples.get()), progress=progress,
        )

    w.bind_run_with_progress("Compare Countries", task, busy_label="Benchmarking...")


def _modal_vps_deploy_check(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "VPS Pre-Deploy Validator",
        "Go/no-go checklist after purchase — TCP, TLS, blocklist, ports (all measured).",
        on_log=log, size=(860, 680),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="VPS IP:", width=70, anchor="w").pack(side="left")
    ip = _entry(row, width=200, placeholder_text="your.server.ip")
    ip.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="SNI:", width=36).pack(side="left")
    sni = _entry(row, width=180)
    sni.insert(0, "www.cloudflare.com")
    sni.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Port:", width=40).pack(side="left")
    port = ctk.CTkOptionMenu(row, values=["443", "8443"], width=60)
    port.set("443")
    port.pack(side="left", padx=4)

    def task(progress):
        t = ip.get().strip()
        if not t:
            return "Enter VPS IP or hostname."
        return validate_vps_deploy_sync(
            target=t, port=int(port.get()), sni=sni.get().strip() or None, progress=progress,
        )

    w.bind_run_with_progress("Validate VPS", task, busy_label="Validating...")


def _modal_vps_ip_ranker(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "VPS IP Ranker",
        "Paste multiple VPS IPs — rank by live route quality from your network.",
        on_log=log, size=(900, 720),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="SNI:", width=70, anchor="w").pack(side="left")
    sni = _entry(row, width=200)
    sni.insert(0, "www.cloudflare.com")
    sni.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Samples:", width=60).pack(side="left")
    samples = ctk.CTkOptionMenu(row, values=["4", "6", "8"], width=50)
    samples.set("6")
    samples.pack(side="left", padx=4)
    ip_frame = ctk.CTkFrame(inner, fg_color="transparent")
    ip_frame.pack(fill="x", pady=4)
    ctk.CTkLabel(ip_frame, text="VPS IPs:", width=70, anchor="nw").pack(side="left", anchor="n")
    ip_box = CopyableTextbox(
        ip_frame, show_toolbar=True, read_only=False, height=90,
        font=ctk.CTkFont(family="Consolas", size=11),
    )
    ip_box.pack(side="left", fill="x", expand=True, padx=4)
    ip_box.set_text("# One IPv4 per line:\n# 95.217.x.x\n# 49.12.x.x\n")

    def task(progress):
        text = ip_box.get_text()
        return rank_vps_ips_sync(
            ip_text=text,
            sni=sni.get().strip() or "www.cloudflare.com",
            samples=int(samples.get()),
            progress=progress,
        )

    w.bind_run_with_progress("Rank IPs", task, busy_label="Probing...")


def _modal_asn_dc_lookup(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "ASN & Datacenter Identifier",
        "Live lookup: who owns this IP — ASN, ISP, DC/CDN class, catalog match.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="IP/Host:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=280, placeholder_text="IP or hostname")
    target.pack(side="left", padx=4)

    def task(progress):
        t = target.get().strip()
        if not t:
            return "Enter IP or hostname."
        return lookup_asn_dc_sync(target=t, progress=progress)

    w.bind_run_with_progress("Identify", task, busy_label="Looking up...")


def _modal_ip_checker(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "IP Reputation Scanner",
        "Full connectivity, TLS, geo, CDN, and blocklist report for one IP or domain.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Target:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=220, placeholder_text="IP or domain")
    target.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Port:", width=40).pack(side="left")
    port = _entry(row, width=60)
    port.insert(0, "443")
    port.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="SNI:", width=36).pack(side="left")
    sni = _entry(row, width=180)
    sni.insert(0, "www.cloudflare.com")
    sni.pack(side="left", padx=4)

    w.set_placeholder("Enter IP or domain to check reputation before selling.\n")

    def task(progress):
        t = target.get().strip()
        if not t:
            return "Enter a target IP or domain."
        return check_ip_or_host_sync(
            target=t, port=int(port.get() or 443),
            sni=sni.get().strip() or None, progress=progress,
        )

    w.bind_run_with_progress("Scan IP", task, busy_label="Scanning...")


def _modal_host_benchmark(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Host Latency Benchmark",
        "TCP latency benchmark to any host — compare nodes before publishing configs.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Host:", width=70, anchor="w").pack(side="left")
    host = _entry(row, width=240)
    host.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Port:", width=40).pack(side="left")
    port = _entry(row, width=60)
    port.insert(0, "443")
    port.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Samples:", width=60).pack(side="left")
    samples = ctk.CTkOptionMenu(row, values=["4", "6", "8", "12"], width=60)
    samples.set("8")
    samples.pack(side="left", padx=4)

    def task(progress):
        h = host.get().strip()
        if not h:
            return "Enter a hostname or IP."
        return benchmark_host_sync(host=h, port=int(port.get() or 443), samples=int(samples.get()), progress=progress)

    w.bind_run_with_progress("Benchmark", task, busy_label="Testing...")


def _modal_dns_health(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "DNS Health Analyzer",
        "DNS records + local vs DoH — detect ISP filtering common in Iran.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=320, placeholder_text="example.com")
    domain.pack(side="left", padx=4)

    w.set_placeholder("Enter domain — checks A/AAAA/CNAME and DoH poisoning signs.\n")

    def task(progress):
        d = domain.get().strip()
        if not d:
            return "Enter a domain name."
        return analyze_dns_health_sync(hostname=d, progress=progress)

    w.bind_run_with_progress("Analyze DNS", task, busy_label="Querying...")


def _modal_infrastructure_market(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Infrastructure Marketplace",
        "Professional buy guide: VPS, CDN, domains, and datacenters — filtered for tunnel operators in Iran.",
        badge="Buy guide",
        on_log=log, size=(920, 700),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)

    r1 = ctk.CTkFrame(inner, fg_color="transparent")
    r1.pack(fill="x", pady=2)
    ctk.CTkLabel(r1, text="Country:", width=72, anchor="w").pack(side="left")
    country = ctk.CTkOptionMenu(r1, values=list(MARKETPLACE_COUNTRIES), width=200)
    country.set("Germany")
    country.pack(side="left", padx=4)
    ctk.CTkLabel(r1, text="Category:", width=72).pack(side="left", padx=(8, 0))
    cats = ["All categories"] + list(CATEGORY_LABELS.values())
    category = ctk.CTkOptionMenu(r1, values=cats, width=200)
    category.set("All categories")
    category.pack(side="left", padx=4)

    r2 = ctk.CTkFrame(inner, fg_color="transparent")
    r2.pack(fill="x", pady=2)
    ctk.CTkLabel(r2, text="Role:", width=72, anchor="w").pack(side="left")
    roles = ["All roles"] + list(ROLE_LABELS.values())
    role = ctk.CTkOptionMenu(r2, values=roles, width=220)
    role.set(ROLE_LABELS["tunnel_origin"])
    role.pack(side="left", padx=4)
    ctk.CTkLabel(r2, text="DC type:", width=56).pack(side="left", padx=(4, 0))
    dc_type = ctk.CTkOptionMenu(r2, values=list(DC_TYPES), width=160)
    dc_type.set("All DC types")
    dc_type.pack(side="left", padx=4)

    r2b = ctk.CTkFrame(inner, fg_color="transparent")
    r2b.pack(fill="x", pady=2)
    ctk.CTkLabel(r2b, text="Budget:", width=72, anchor="w").pack(side="left")
    tiers = ["Any budget"] + list(TIER_LABELS.values())
    tier = ctk.CTkOptionMenu(r2b, values=tiers, width=120)
    tier.set("Any budget")
    tier.pack(side="left", padx=4)

    r3 = ctk.CTkFrame(inner, fg_color="transparent")
    r3.pack(fill="x", pady=4)
    live_probe = ctk.CTkCheckBox(r3, text="Live TCP probe on top providers (slower, accurate)")
    live_probe.select()
    live_probe.pack(side="left")

    w.set_placeholder(
        "Curated links to buy VPS (Hetzner, OVH…), CDN (Cloudflare, Arvan…), domains.\n"
        "Pair with Datacenter Finder before purchase.\n"
    )

    def task(progress):
        return build_marketplace_report_sync(
            country=country.get(), category=category.get(), role=role.get(), tier=tier.get(),
            dc_type=dc_type.get(), live_probe=live_probe.get(), progress=progress,
        )

    w.bind_run_with_progress("Generate Buy Guide", task, busy_label="Building guide...")


def _modal_tunnel_planner(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Tunnel Route Planner",
        "Architecture checklist: origin DC, CDN front, REALITY stack — for selling or personal use.",
        on_log=log, size=(820, 640),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="Goal:", width=70, anchor="w").pack(side="left")
    goal = ctk.CTkOptionMenu(row, values=list(GOALS), width=360)
    goal.set(GOALS[0])
    goal.pack(side="left", padx=4)
    row2 = ctk.CTkFrame(inner, fg_color="transparent")
    row2.pack(fill="x", pady=2)
    ctk.CTkLabel(row2, text="Origin:", width=70, anchor="w").pack(side="left")
    origin = ctk.CTkOptionMenu(row2, values=list(ORIGIN_COUNTRIES), width=280)
    origin.set(ORIGIN_COUNTRIES[0])
    origin.pack(side="left", padx=4)
    use_cdn = ctk.CTkCheckBox(row2, text="Use CDN front (Cloudflare)")
    use_cdn.select()
    use_cdn.pack(side="left", padx=12)

    w.set_placeholder("Click Run for step-by-step tunnel architecture.\n")

    def task(progress):
        return build_tunnel_plan(goal.get(), origin.get(), use_cdn=use_cdn.get(), progress=progress)

    w.bind_run_with_progress("Build Plan", task, busy_label="Planning...")


def _modal_isp_guide(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Iran ISP Operator Matrix",
        "Per-ISP tactics: which EU region and which app tools to run first.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="ISP:", width=70, anchor="w").pack(side="left")
    isp = ctk.CTkOptionMenu(row, values=list(ISPS), width=320)
    isp.set(ISPS[0])
    isp.pack(side="left", padx=4)
    w.set_placeholder("Select your buyers' ISP or your own connection.\n")
    w.bind_run_with_progress(
        "Show Guide", lambda p: build_isp_guide(isp.get(), progress=p), busy_label="Loading...",
    )


def _modal_port_scanner(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Port & Service Scanner",
        "TCP connectivity scan — verify 443/8443/2053 and admin ports before go-live.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="Host:", width=70, anchor="w").pack(side="left")
    host = _entry(row, width=240)
    host.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Preset:", width=50).pack(side="left", padx=(8, 0))
    preset = ctk.CTkOptionMenu(row, values=list(PRESETS.keys()), width=320)
    preset.set(list(PRESETS.keys())[0])
    preset.pack(side="left", padx=4)

    def task(progress):
        h = host.get().strip()
        if not h:
            return "Enter hostname or IP."
        ports = PRESETS.get(preset.get(), (443,))
        return scan_ports_sync(h, ports, progress=progress)

    w.bind_run_with_progress("Scan Ports", task, busy_label="Scanning...")


def _modal_subscription_health(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Subscription Link Checker",
        "Fetch subscription URL — count nodes, protocols, detect dead panel links.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Sub URL:", width=70, anchor="w").pack(side="left")
    url = _entry(row, width=480, placeholder_text="https://panel.example.com/sub/...")
    url.pack(side="left", padx=4, fill="x", expand=True)
    w.set_placeholder("Paste panel subscription link.\n")

    def task(progress):
        u = url.get().strip()
        if not u:
            return "Enter subscription URL."
        return check_subscription_sync(u, progress=progress)

    w.bind_run_with_progress("Check Subscription", task, busy_label="Fetching...")
# Backward-compatible exports
open_clean_ip_modal = lambda parent, on_log=None: _modal_clean_ip(parent, on_log or (lambda _: None))
open_datacenter_modal = lambda parent, on_log=None: _modal_datacenter(parent, on_log or (lambda _: None))
