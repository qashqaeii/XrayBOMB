"""Extended tool modals — network intelligence, SSH, Xray analyzers."""

from __future__ import annotations

from tkinter import messagebox

import customtkinter as ctk

from gui.components.clipboard_bindings import bind_entry_clipboard
from gui.components.copyable_text import CopyableTextbox
from gui.tools.tool_framework import AsyncToolWindow, LogFn
from tools.arvan_inspector import inspect_arvan_sync
from tools.anycast_detector import detect_anycast_sync
from tools.cdn_route_comparator import compare_cdn_routes_sync
from tools.cloudflare_colo_finder import find_cloudflare_colo_sync
from tools.cdn_detector_tool import detect_cdn_for_target_sync
from tools.config_topology import map_config_topology_sync
from tools.datacenter_fingerprint import fingerprint_datacenter_sync
from tools.dns_propagation import monitor_dns_propagation_sync
from tools.dnssec_validator import validate_dnssec_sync
from tools.fake_cdn_detector import detect_fake_cdn_sync
from tools.geodns_analyzer import analyze_geodns_sync
from tools.infrastructure_similarity import compare_infrastructure_sync
from tools.iran_filtering_test import run_iran_filtering_suite_sync
from tools.mtr_visualizer import build_mtr_report_sync
from tools.multi_region_ping import build_ping_matrix_sync
from tools.national_cdn_analyzer import analyze_national_cdn_sync
from tools.national_network_detector import build_national_network_report_sync
from tools.operator_comparison import build_operator_comparison_sync
from tools.packet_loss_heatmap import build_packet_loss_heatmap_sync
from tools.reality_analyzer import analyze_reality_config_sync
from gui.tools.ssh_remote_window import open_remote_server_window
from tools.subscription_analyzer import analyze_subscription_sync
from tools.tls_intelligence import scan_tls_target_sync


def _entry(parent, **kwargs) -> ctk.CTkEntry:
    e = ctk.CTkEntry(parent, **kwargs)
    bind_entry_clipboard(e)
    return e


def register_extended_openers(parent: ctk.CTk, log: LogFn) -> dict:
    return {
        "national_network": lambda: _modal_national_network(parent, log),
        "operator_comparison": lambda: _modal_operator_comparison(parent, log),
        "cdn_detector": lambda: _modal_cdn_detector(parent, log),
        "fake_cdn": lambda: _modal_fake_cdn(parent, log),
        "remote_server": lambda: _modal_remote_server(parent, log),
        "dc_fingerprint": lambda: _modal_dc_fingerprint(parent, log),
        "dns_propagation": lambda: _modal_dns_propagation(parent, log),
        "multi_region_ping": lambda: _modal_multi_region_ping(parent, log),
        "tls_scanner": lambda: _modal_tls_scanner(parent, log),
        "config_topology": lambda: _modal_config_topology(parent, log),
        "reality_analyzer": lambda: _modal_reality_analyzer(parent, log),
        "subscription_analyzer": lambda: _modal_subscription_analyzer(parent, log),
        "iran_filtering": lambda: _modal_iran_filtering(parent, log),
        "mtr_visualizer": lambda: _modal_mtr_visualizer(parent, log),
        "packet_loss_heatmap": lambda: _modal_packet_loss_heatmap(parent, log),
        "anycast_detector": lambda: _modal_anycast_detector(parent, log),
        "cf_colo_finder": lambda: _modal_cf_colo_finder(parent, log),
        "cdn_route_compare": lambda: _modal_cdn_route_compare(parent, log),
        "dnssec_validator": lambda: _modal_dnssec_validator(parent, log),
        "geodns_analyzer": lambda: _modal_geodns_analyzer(parent, log),
        "infra_similarity": lambda: _modal_infra_similarity(parent, log),
        "arvan_inspector": lambda: _modal_arvan_inspector(parent, log),
        "national_cdn": lambda: _modal_national_cdn(parent, log),
    }


def _modal_national_network(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "National Network Detector",
        "Live connectivity, DNS hijack, and filtering hints from your network.",
        on_log=log,
    )
    w.set_placeholder("Click Run Detection.\n")
    w.bind_run_with_progress(
        "Run Detection",
        lambda p: build_national_network_report_sync(progress=p),
        busy_label="Testing...",
    )


def _modal_operator_comparison(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Operator Comparison Lab",
        "ASN reference + live EU ping matrix from your current ISP.",
        on_log=log, size=(880, 680),
    )
    w.set_placeholder("Runs Multi-Region Ping automatically.\n")
    w.bind_run_with_progress(
        "Run Comparison",
        lambda p: build_operator_comparison_sync(progress=p),
        busy_label="Benchmarking...",
    )


def _modal_cdn_detector(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "CDN Detector",
        "Identify CDN provider from domain or IP.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain/IP:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=280, placeholder_text="example.com")
    target.pack(side="left", padx=4)

    def task(progress):
        return detect_cdn_for_target_sync(target=target.get().strip(), progress=progress)

    w.bind_run_with_progress("Detect CDN", task, busy_label="Analyzing...")


def _modal_fake_cdn(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Fake CDN Detector",
        "Verify if domain truly sits on CDN edge or direct VPS.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=220)
    domain.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Expected CDN:", width=90).pack(side="left")
    cdn = ctk.CTkOptionMenu(row, values=["Cloudflare", "ArvanCloud", "Akamai", "Fastly"], width=120)
    cdn.set("Cloudflare")
    cdn.pack(side="left", padx=4)

    def task(progress):
        return detect_fake_cdn_sync(domain=domain.get().strip(), claimed_cdn=cdn.get(), progress=progress)

    w.bind_run_with_progress("Analyze", task, busy_label="Checking...")


def _modal_remote_server(parent: ctk.CTk, log: LogFn) -> None:
    open_remote_server_window(parent, on_log=log)


def _modal_dc_fingerprint(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Datacenter Fingerprint",
        "Identify OVH, Hetzner, DO, AWS, Azure from IP.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="IP/Host:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=260)
    target.pack(side="left", padx=4)
    w.bind_run_with_progress(
        "Fingerprint",
        lambda p: fingerprint_datacenter_sync(target=target.get().strip(), progress=p),
        busy_label="Looking up...",
    )


def _modal_dns_propagation(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "DNS Propagation Monitor",
        "Compare A records across Cloudflare, Google, Quad9, OpenDNS.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=260)
    domain.pack(side="left", padx=4)
    w.bind_run_with_progress(
        "Check Propagation",
        lambda p: monitor_dns_propagation_sync(hostname=domain.get().strip(), progress=p),
        busy_label="Querying...",
    )


def _modal_multi_region_ping(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Multi-Region Ping Matrix",
        "Live latency to Frankfurt, Amsterdam, Paris, London, Istanbul, Dubai.",
        on_log=log, size=(880, 640),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Samples:", width=70, anchor="w").pack(side="left")
    samples = ctk.CTkOptionMenu(row, values=["3", "4", "5", "6", "8"], width=60)
    samples.set("5")
    samples.pack(side="left", padx=4)
    w.bind_run_with_progress(
        "Run Matrix",
        lambda p: build_ping_matrix_sync(samples=int(samples.get()), progress=p),
        busy_label="Probing...",
    )


def _modal_tls_scanner(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "TLS & Certificate Scanner",
        "TLS version, cipher, ALPN, CA, expiry.",
        on_log=log,
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="Host:", width=70, anchor="w").pack(side="left")
    host = _entry(row, width=200)
    host.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="Port:", width=36).pack(side="left")
    port = _entry(row, width=50)
    port.insert(0, "443")
    port.pack(side="left", padx=4)
    ctk.CTkLabel(row, text="SNI:", width=36).pack(side="left")
    sni = _entry(row, width=180)
    sni.pack(side="left", padx=4)

    def task(progress):
        try:
            p = int(port.get().strip() or "443")
        except ValueError:
            p = 443
        return scan_tls_target_sync(
            host=host.get().strip(), port=p,
            sni=sni.get().strip() or None, progress=progress,
        )

    w.bind_run_with_progress("Scan TLS", task, busy_label="Handshaking...")


def _modal_config_topology(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Infrastructure Mapper",
        "Parse config → CDN/origin topology + reproduction checklist.",
        on_log=log, size=(900, 720),
    )
    ctk.CTkLabel(w.options, text="Paste share link or JSON:", anchor="w").pack(fill="x", padx=10, pady=(8, 2))
    box = CopyableTextbox(
        w.options, show_toolbar=True, read_only=False, height=100,
        font=ctk.CTkFont(family="Consolas", size=11),
    )
    box.pack(fill="x", padx=10, pady=4)
    box.set_text("vless://...\n")

    def task(progress):
        return map_config_topology_sync(text=box.get_text(), progress=progress)

    w.bind_run_with_progress("Map Topology", task, busy_label="Analyzing...")


def _modal_reality_analyzer(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "REALITY Analyzer",
        "Parse VLESS REALITY — SNI, pbk, shortId, fingerprint.",
        on_log=log, size=(860, 640),
    )
    ctk.CTkLabel(w.options, text="Paste VLESS REALITY link:", anchor="w").pack(fill="x", padx=10, pady=(8, 2))
    box = CopyableTextbox(
        w.options, show_toolbar=True, read_only=False, height=80,
        font=ctk.CTkFont(family="Consolas", size=11),
    )
    box.pack(fill="x", padx=10, pady=4)

    w.bind_run_with_progress(
        "Analyze REALITY",
        lambda p: analyze_reality_config_sync(text=box.get_text(), progress=p),
        busy_label="Parsing...",
    )


def _modal_subscription_analyzer(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Subscription Analyzer",
        "Deep sub analysis — countries, datacenters, CDNs per node.",
        on_log=log, size=(880, 680),
    )
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Sub URL:", width=70, anchor="w").pack(side="left")
    url = _entry(row, width=480)
    url.pack(side="left", padx=4)
    w.bind_run_with_progress(
        "Analyze Subscription",
        lambda p: analyze_subscription_sync(url=url.get().strip(), progress=p),
        busy_label="Fetching...",
    )


def _modal_iran_filtering(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(
        parent, "Iran Filtering Test Suite",
        "Live TLS, HTTP, DNS probes for filtered sites.",
        on_log=log, size=(860, 640),
    )
    w.set_placeholder("Tests run from your current ISP.\n")
    w.bind_run_with_progress(
        "Run Filter Tests",
        lambda p: run_iran_filtering_suite_sync(progress=p),
        busy_label="Testing...",
    )


def _modal_mtr_visualizer(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "MTR / Traceroute Visualizer",
                        "Live hop trace with ASN, country, and latency graph.", on_log=log, size=(900, 680))
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Target:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=260, placeholder_text="host or IP")
    target.pack(side="left", padx=4)
    w.bind_run_with_progress("Run Traceroute",
        lambda p: build_mtr_report_sync(target=target.get().strip(), progress=p), busy_label="Tracing...")


def _modal_packet_loss_heatmap(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "Packet Loss Heatmap",
                        "TCP sample matrix per region — loss and jitter.", on_log=log, size=(900, 640))
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Samples:", width=70, anchor="w").pack(side="left")
    samples = ctk.CTkOptionMenu(row, values=["6", "8", "10"], width=60)
    samples.set("8")
    samples.pack(side="left", padx=4)
    w.bind_run_with_progress("Build Heatmap",
        lambda p: build_packet_loss_heatmap_sync(samples=int(samples.get()), progress=p), busy_label="Probing...")


def _modal_anycast_detector(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "Anycast Detector", "Repeated DNS — unique IP analysis.", on_log=log)
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=260)
    domain.pack(side="left", padx=4)
    w.bind_run_with_progress("Detect Anycast",
        lambda p: detect_anycast_sync(hostname=domain.get().strip(), progress=p), busy_label="Resolving...")


def _modal_cf_colo_finder(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "Cloudflare Colo Finder",
                        "Edge POP via /cdn-cgi/trace — live from Cloudflare.", on_log=log, size=(860, 640))
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x", pady=2)
    ctk.CTkLabel(row, text="CF IP/host:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=200, placeholder_text="optional — blank = 1.1.1.1")
    target.pack(side="left", padx=4)
    scan = ctk.CTkCheckBox(inner, text="Scan sample Cloudflare IPs from your route")
    scan.pack(anchor="w", padx=76, pady=4)
    w.bind_run_with_progress("Find Colo",
        lambda p: find_cloudflare_colo_sync(
            target=target.get().strip(), scan_ips=scan.get(), progress=p),
        busy_label="Tracing...")


def _modal_cdn_route_compare(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "CDN Route Comparator",
                        "Side-by-side live latency — two domains or IPs.", on_log=log, size=(880, 640))
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    for label, ph in (("CDN A:", "cloudflare-front.com"), ("CDN B:", "arvancloud.ir")):
        row = ctk.CTkFrame(inner, fg_color="transparent")
        row.pack(fill="x", pady=2)
        ctk.CTkLabel(row, text=label, width=70, anchor="w").pack(side="left")
        e = _entry(row, width=280, placeholder_text=ph)
        e.pack(side="left", padx=4)
        if label.startswith("CDN A"):
            ta = e
        else:
            tb = e
    w.bind_run_with_progress("Compare Routes",
        lambda p: compare_cdn_routes_sync(target_a=ta.get().strip(), target_b=tb.get().strip(), progress=p),
        busy_label="Probing...")


def _modal_dnssec_validator(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "DNSSEC Validator", "DS/DNSKEY and resolver validation.", on_log=log)
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=260)
    domain.pack(side="left", padx=4)
    w.bind_run_with_progress("Validate DNSSEC",
        lambda p: validate_dnssec_sync(hostname=domain.get().strip(), progress=p), busy_label="Checking...")


def _modal_geodns_analyzer(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "GeoDNS Analyzer", "Compare DNS answers across resolvers.", on_log=log)
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=260)
    domain.pack(side="left", padx=4)
    w.bind_run_with_progress("Analyze GeoDNS",
        lambda p: analyze_geodns_sync(hostname=domain.get().strip(), progress=p), busy_label="Querying...")


def _modal_infra_similarity(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "Infrastructure Similarity Engine",
                        "Computed match % from parsed fields + IP lookup.", on_log=log, size=(900, 720))
    ctk.CTkLabel(w.options, text="Config A:", anchor="w").pack(fill="x", padx=10, pady=(8, 2))
    box_a = CopyableTextbox(w.options, show_toolbar=True, read_only=False, height=70,
                            font=ctk.CTkFont(family="Consolas", size=11))
    box_a.pack(fill="x", padx=10, pady=2)
    ctk.CTkLabel(w.options, text="Config B:", anchor="w").pack(fill="x", padx=10, pady=(6, 2))
    box_b = CopyableTextbox(w.options, show_toolbar=True, read_only=False, height=70,
                            font=ctk.CTkFont(family="Consolas", size=11))
    box_b.pack(fill="x", padx=10, pady=2)
    w.bind_run_with_progress("Compare",
        lambda p: compare_infrastructure_sync(text_a=box_a.get_text(), text_b=box_b.get_text(), progress=p),
        busy_label="Analyzing...")


def _modal_arvan_inspector(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "ArvanCloud Inspector",
                        "Arvan DNS, ASN, HTTP headers, live route.", on_log=log, size=(880, 680))
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain:", width=70, anchor="w").pack(side="left")
    domain = _entry(row, width=280)
    domain.pack(side="left", padx=4)
    w.bind_run_with_progress("Inspect Arvan",
        lambda p: inspect_arvan_sync(domain=domain.get().strip(), progress=p), busy_label="Analyzing...")


def _modal_national_cdn(parent: ctk.CTk, log: LogFn) -> None:
    w = AsyncToolWindow(parent, "National CDN Analyzer",
                        "Arvan, Afranet, Asiatech, Pars Online detection.", on_log=log)
    inner = ctk.CTkFrame(w.options, fg_color="transparent")
    inner.pack(fill="x", padx=10, pady=8)
    row = ctk.CTkFrame(inner, fg_color="transparent")
    row.pack(fill="x")
    ctk.CTkLabel(row, text="Domain/IP:", width=70, anchor="w").pack(side="left")
    target = _entry(row, width=280)
    target.pack(side="left", padx=4)
    w.bind_run_with_progress("Analyze",
        lambda p: analyze_national_cdn_sync(target=target.get().strip(), progress=p), busy_label="Checking...")
