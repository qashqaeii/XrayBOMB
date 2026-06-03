#!/usr/bin/env python3
"""CLI for Xray Config Analyzer Pro — rich output."""

from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from backend.analyzer import ConfigAnalyzer
from backend.config_parser import parse_input, parse_share_link
from backend.diff_tool import diff_configs, format_diff_text
from backend.models import BatchAnalysisResult, TestStatus
from database.db import AnalysisDatabase
from reports.exporter import BatchReportExporter, ReportExporter
from utils.qrcode_gen import generate_qr_for_config, save_qr_png

console = Console()


def _load_text(args) -> str:
    if args.file:
        return Path(args.file).read_text(encoding="utf-8", errors="replace")
    if args.config:
        return args.config
    return sys.stdin.read()


def _status_style(status: str) -> str:
    if status == "Valid":
        return "[green]✓[/green]"
    if status == "Invalid":
        return "[red]✗[/red]"
    return "[yellow]⚠[/yellow]"


def _print_proxy_diagnostics(r) -> None:
    x = r.xray_test
    if x.proxy_test == TestStatus.SKIPPED:
        return

    table = Table(title="Site Reachability (via tunnel)", show_header=True)
    table.add_column("Site")
    table.add_column("Status")
    table.add_column("Latency")
    table.add_column("Details")
    for s in x.site_reachability:
        table.add_row(s.name, s.status.value, f"{s.latency_ms or '-'} ms", s.details[:50])
    if x.site_reachability:
        console.print(table)

    st = x.speed_test
    if st.status != TestStatus.PENDING:
        speed_txt = f"{st.download_mbps} Mbps" if st.download_mbps else "N/A"
        console.print(Panel(
            f"Download: [cyan]{speed_txt}[/cyan] | "
            f"Duration: {st.duration_sec}s | "
            f"Bytes: {st.bytes_downloaded}",
            title="Speed Test (1MB Cloudflare)",
            border_style="blue",
        ))

    lk = x.leak_check
    if lk.proxy_exit_ip or lk.client_ip:
        leak_color = "red" if lk.ip_leak else "green"
        console.print(Panel(
            f"Client IP: {lk.client_ip or '?'}\n"
            f"Exit IP:   {lk.proxy_exit_ip or '?'} ({lk.proxy_exit_country or '?'})\n"
            f"IP Leak:   [{leak_color}]{'YES' if lk.ip_leak else 'No'}[/]\n"
            f"DNS A:     {', '.join(lk.direct_dns_ips) or 'N/A'}",
            title="Leak Check",
            border_style="magenta",
        ))


def _print_summary(batch: BatchAnalysisResult, verbose: bool = False) -> None:
    table = Table(title=f"Analysis Results ({len(batch.results)} configs)", show_lines=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Protocol", width=10)
    table.add_column("Address")
    table.add_column("Score", justify="right")
    table.add_column("Proxy", width=8)
    table.add_column("Speed", width=10)
    table.add_column("Exit IP", width=14)
    table.add_column("Sites", width=16)

    for i, r in enumerate(batch.results, 1):
        c = r.config
        x = r.xray_test
        speed = f"{x.speed_test.download_mbps}M" if x.speed_test.download_mbps else "—"
        sites_ok = sum(1 for s in x.site_reachability if s.status == TestStatus.VALID)
        sites_total = len(x.site_reachability)
        sites_str = f"{sites_ok}/{sites_total}" if sites_total else "—"
        score_color = "green" if r.security.score >= 80 else "yellow" if r.security.score >= 50 else "red"
        table.add_row(
            str(i), c.protocol.value, f"{c.address}:{c.port}",
            f"[{score_color}]{r.security.score}/100[/]",
            x.proxy_test.value[:6], speed,
            x.exit_ip or "—", sites_str,
        )
    console.print(table)

    if verbose and batch.results:
        console.print()
        _print_proxy_diagnostics(batch.results[0])

    plugins = batch.results[0].raw_data.get("plugins", {}) if batch.results else {}
    if plugins:
        console.print(Panel(str(list(plugins.keys())), title="Plugins loaded", border_style="dim"))


def cmd_analyze(args) -> int:
    text = _load_text(args)
    analyzer = ConfigAnalyzer(run_xray_test=not args.no_xray)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        task = progress.add_task("Analyzing...", total=None)

        def on_stage(cur, total, name):
            progress.update(task, description=f"[{cur}/{total}] {name}")

        batch = analyzer.analyze_sync(text, stage_callback=on_stage)

    if not batch.results:
        console.print("[red bold]No valid configs found.[/]")
        for e in batch.errors:
            console.print(f"  [yellow]{e}[/]")
        return 1

    fmt = args.format.lower()
    if fmt == "json":
        out = batch.model_dump_json(indent=2) if len(batch.results) > 1 else batch.results[0].model_dump_json(indent=2)
        if args.pretty:
            console.print_json(out)
        else:
            print(out)
    elif fmt in ("md", "markdown", "html", "csv", "pdf"):
        if args.output:
            path = Path(args.output)
            if len(batch.results) == 1:
                ReportExporter(batch.results[0]).save(path, fmt)
            else:
                BatchReportExporter(batch).save(path, fmt)
            console.print(f"[green]Saved → {path}[/]")
        else:
            if len(batch.results) == 1:
                exp = ReportExporter(batch.results[0])
                print({"md": exp.to_markdown, "markdown": exp.to_markdown, "html": exp.to_html, "csv": exp.to_csv}[fmt]())
    else:
        _print_summary(batch, verbose=args.verbose)

    if args.save_db:
        db = AnalysisDatabase()
        db.save_batch(batch)
        console.print("[dim]Saved to history database.[/]")

    return 0


def cmd_qr(args) -> int:
    text = args.config or (Path(args.file).read_text(encoding="utf-8") if args.file else "")
    if not text.strip():
        console.print("[red]Provide --config or --file[/]")
        return 1
    configs = parse_input(text.strip()) if "\n" in text or text.startswith("{") else [parse_share_link(text.strip())]
    if not configs:
        console.print("[red]No valid config[/]")
        return 1
    cfg = configs[0]
    png, link = generate_qr_for_config(cfg)
    if not link:
        console.print("[red]No share link in config[/]")
        return 1

    console.print(Panel(link, title="Share Link", border_style="cyan"))
    out = Path(args.output) if args.output else Path(f"qr_{cfg.address}.png")
    out.write_bytes(png)
    console.print(f"[green]QR saved → {out}[/]")
    return 0


def cmd_diff(args) -> int:
    configs = parse_input(_load_text(args))
    if len(configs) < 2 and args.file2:
        configs = configs + parse_input(Path(args.file2).read_text(encoding="utf-8"))
    if len(configs) < 2:
        console.print("[red]Need at least 2 configs[/]")
        return 1
    diffs = diff_configs(configs[0], configs[1])
    console.print(Panel(format_diff_text(diffs), title="Config Diff", border_style="yellow"))
    return 0


def cmd_history(args) -> int:
    db = AnalysisDatabase()
    rows = db.search(args.query) if args.query else db.list_recent(args.limit)
    table = Table(title="Analysis History")
    table.add_column("ID")
    table.add_column("Protocol")
    table.add_column("Address")
    table.add_column("Score")
    table.add_column("Date")
    for row in rows:
        table.add_row(
            str(row["id"]), row["protocol"], f"{row['address']}:{row['port']}",
            str(row["security_score"]), (row["analyzed_at"] or "")[:19],
        )
    console.print(table)
    return 0


def cmd_plugins(args) -> int:
    from backend.plugins import get_plugin_manager
    mgr = get_plugin_manager()
    count = mgr.load_plugins()
    names = [n for n, _ in mgr._plugins]
    console.print(Panel("\n".join(names) or "(none)", title=f"Plugins loaded ({count})", border_style="green"))
    return 0


def main() -> None:
    from utils.branding import developer_credit

    parser = argparse.ArgumentParser(
        prog="xray-analyzer",
        description="[bold cyan]Xray Config Analyzer Pro[/] — CLI",
        epilog=developer_credit(),
    )
    sub = parser.add_subparsers(dest="command")

    p_analyze = sub.add_parser("analyze", help="Analyze config(s)")
    p_analyze.add_argument("config", nargs="?", help="Config string or stdin")
    p_analyze.add_argument("-f", "--file", help="Input file")
    p_analyze.add_argument("-o", "--output", help="Output file")
    p_analyze.add_argument("--format", default="summary", choices=["summary", "json", "md", "html", "csv", "pdf"])
    p_analyze.add_argument("--no-xray", action="store_true")
    p_analyze.add_argument("--save-db", action="store_true")
    p_analyze.add_argument("--pretty", action="store_true")
    p_analyze.add_argument("-v", "--verbose", action="store_true", help="Show proxy diagnostics")
    p_analyze.set_defaults(func=cmd_analyze)

    p_qr = sub.add_parser("qr", help="Generate QR PNG from config")
    p_qr.add_argument("config", nargs="?", help="Share link")
    p_qr.add_argument("-f", "--file")
    p_qr.add_argument("-o", "--output", help="Output PNG path")
    p_qr.set_defaults(func=cmd_qr)

    p_diff = sub.add_parser("diff", help="Compare two configs")
    p_diff.add_argument("-f", "--file", required=True)
    p_diff.add_argument("--file2")
    p_diff.set_defaults(func=cmd_diff)

    p_hist = sub.add_parser("history", help="List history")
    p_hist.add_argument("-q", "--query", default="")
    p_hist.add_argument("-n", "--limit", type=int, default=20)
    p_hist.set_defaults(func=cmd_history)

    p_plug = sub.add_parser("plugins", help="List loaded plugins")
    p_plug.set_defaults(func=cmd_plugins)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
