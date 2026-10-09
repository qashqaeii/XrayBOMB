"""Remote VPS toolkit — SSH diagnostics and one-click maintenance."""

from __future__ import annotations

import asyncio
import json
import re
import socket
from typing import Callable, Optional

import httpx

from network.geo import lookup_geo_ip
from tools.ip_probe import probe_host, resolve_host
from tools.output_labels import MEASURED
from utils.logger import get_logger

logger = get_logger(__name__)

SSH_TIMEOUT = 20
CMD_TIMEOUT = 45
ROUTE_CMD_TIMEOUT = 75

_HTTP = {"timeout": 10.0, "trust_env": False, "follow_redirects": True}

INTERNATIONAL_TARGETS: tuple[tuple[str, str], ...] = (
    ("Google HTTPS", "https://www.google.com"),
    ("Cloudflare", "https://1.1.1.1"),
    ("GitHub", "https://github.com"),
    ("Quad9 DNS", "https://9.9.9.9"),
)

IRAN_TARGETS: tuple[tuple[str, str], ...] = (
    ("Digikala", "https://www.digikala.com"),
    ("Aparat", "https://www.aparat.com"),
    ("Arvan Cloud", "https://www.arvancloud.ir"),
    ("IRNIC", "https://www.nic.ir"),
)


def _run_ssh(
    host: str,
    username: str,
    password: str,
    command: str,
    *,
    port: int = 22,
    timeout: int = CMD_TIMEOUT,
) -> tuple[int, str, str]:
    """Execute one command over SSH. Returns (exit_code, stdout, stderr)."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=SSH_TIMEOUT,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        client.close()


async def _ssh(
    host: str,
    user: str,
    password: str,
    cmd: str,
    port: int = 22,
    *,
    timeout: int = CMD_TIMEOUT,
) -> tuple[int, str, str]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, lambda: _run_ssh(host, user, password, cmd, port=port, timeout=timeout),
    )


def _header(title: str) -> list[str]:
    return [title, "═" * 58, ""]


def _section(name: str) -> str:
    return f"── {name} ──"


def _curl_probe_cmd(url: str) -> str:
    return (
        f"curl -4 -s -o /dev/null -w '%{{http_code}} %{{time_total}}s' "
        f"--max-time 12 {url} 2>&1"
    )


def _build_curl_test_script(title: str, targets: tuple[tuple[str, str], ...]) -> str:
    parts = [f"echo '=== {title} ==='"]
    for label, url in targets:
        parts.append(f"echo '{label}:'; {_curl_probe_cmd(url)}; echo")
    return "; ".join(parts)


def _parse_ip_api_blob(text: str) -> dict:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{") and "countryCode" in line:
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
    match = re.search(r"\{[^{}]*countryCode[^{}]*\}", text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass
    return {}


async def _fetch_client_public_ip() -> Optional[str]:
    try:
        async with httpx.AsyncClient(**_HTTP) as client:
            r = await client.get("https://api.ipify.org?format=json")
            r.raise_for_status()
            return r.json().get("ip")
    except Exception:
        return None


async def _server_geo(host: str, user: str, password: str, port: int) -> dict:
    script = (
        "IP=$(curl -4 -s --max-time 6 https://api.ipify.org 2>/dev/null); "
        "echo \"$IP\"; "
        "curl -s --max-time 8 \"http://ip-api.com/json/${IP}?fields=status,countryCode,country,isp,query,as\" 2>/dev/null"
    )
    _code, out, _err = await _ssh(host, user, password, script, port, timeout=30)
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    outbound_ip = lines[0] if lines and re.match(r"^\d+\.\d+\.\d+\.\d+$", lines[0]) else ""
    geo = _parse_ip_api_blob(out)
    if outbound_ip and not geo.get("query"):
        geo["query"] = outbound_ip
    return geo


def _count_http_ok(output: str) -> int:
    return sum(
        1 for line in output.splitlines()
        if re.match(r"^\s*(200|301|302|204)\s", line.strip())
    )


async def test_bidirectional_connectivity(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    client_ip: Optional[str] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    """
    Smart route test:
    - Iran VPS  → can it reach international internet?
    - Foreign VPS → can it reach Iran? Can you (Iran) reach the VPS?
    """
    host = host.strip()
    if not host or not username:
        return "Enter host and username."

    if progress:
        progress("Your network profile...")
    client_geo = await lookup_geo_ip()
    client_cc = (client_geo or {}).get("country_code", "?")
    client_country = (client_geo or {}).get("country", "?")
    client_isp = (client_geo or {}).get("isp", "—")
    if not client_ip:
        client_ip = (client_geo or {}).get("ip") or await _fetch_client_public_ip()

    if progress:
        progress("Probing server from YOUR network...")
    server_probe_ip = await resolve_host(host)
    probe_target = server_probe_ip or host
    local_443 = await probe_host(probe_target, port=443, samples=4)
    local_22 = await probe_host(probe_target, port=port if port != 22 else 22, samples=3)

    if progress:
        progress("Detecting server location via SSH...")
    try:
        sgeo = await _server_geo(host, username, password, port)
    except Exception as exc:
        return "\n".join(_header("IR ↔ World Route Test — FAILED") + [f"  SSH error: {exc}"])

    server_cc = (sgeo.get("countryCode") or "?").upper()
    server_country = sgeo.get("country", "?")
    server_isp = sgeo.get("isp", "—")
    server_outbound = sgeo.get("query", probe_target)

    is_server_iran = server_cc == "IR"
    is_client_iran = client_cc == "IR"

    lines = _header("IR ↔ World Route Test")
    lines.extend([
        f"  Server host   : {host}:{port}",
        f"  Server egress : {server_outbound} ({server_country} / {server_cc})",
        f"  Server ISP    : {server_isp}",
        "",
        f"  Your IP       : {client_ip or '—'} ({client_country} / {client_cc})",
        f"  Your ISP      : {client_isp}",
        "",
        _section(f"Direction A — YOU → SERVER {MEASURED}"),
        f"  Target IP     : {probe_target}",
        f"  TCP :443      : {'OK' if local_443.tcp_ok else 'FAIL'}  "
        f"avg {local_443.avg_ms or '—'} ms  loss {local_443.packet_loss_pct:.0f}%",
        f"  TCP :{port} (SSH) : {'OK' if local_22.tcp_ok else 'FAIL'}  "
        f"avg {local_22.avg_ms or '—'} ms",
        "",
    ])

    # Server-side egress tests (direction B)
    if is_server_iran:
        test_title = "Direction B — IR SERVER → INTERNATIONAL (from server)"
        targets = INTERNATIONAL_TARGETS
        lines.append(_section(test_title))
        lines.append("  Iran VPS: testing outbound access to global internet.")
    else:
        test_title = "Direction B — FOREIGN SERVER → IRAN (from server)"
        targets = IRAN_TARGETS
        lines.append(_section(test_title))
        lines.append("  Foreign VPS: testing reachability to Iranian endpoints.")

    if progress:
        progress("Running server-side curl tests...")
    script = _build_curl_test_script(test_title, targets)

    if client_ip and re.match(r"^\d+\.\d+\.\d+\.\d+$", client_ip):
        script += (
            f"; echo '=== SERVER → YOUR IP ({client_ip}) ==='; "
            f"echo -n 'TCP 443: '; (timeout 5 bash -c 'echo >/dev/tcp/{client_ip}/443' 2>/dev/null && echo OK || echo FAIL); "
            f"echo -n 'TCP 22: '; (timeout 5 bash -c 'echo >/dev/tcp/{client_ip}/22' 2>/dev/null && echo OK || echo FAIL); "
            f"echo 'ICMP ping:'; (ping -c 2 -W 3 {client_ip} 2>/dev/null || ping -n 2 {client_ip} 2>/dev/null || echo unavailable)"
        )

    try:
        code, out, err = await _ssh(
            host, username, password, script, port, timeout=ROUTE_CMD_TIMEOUT,
        )
    except Exception as exc:
        lines.append(f"  SSH test failed: {exc}")
        out, err, code = "", "", 1

    lines.append("")
    for line in (out or err).splitlines():
        lines.append(f"  {line}")

    ok_server = _count_http_ok(out or "")
    lines.extend(["", _section("Verdict")])

    if is_server_iran:
        lines.append(f"  IR → World (server curl): {ok_server}/{len(targets)} endpoints OK")
        if ok_server >= 3:
            lines.append("  ✓ Iran server has working international egress — suitable as IR relay/origin with global exit")
        elif ok_server >= 1:
            lines.append("  ⚠ Partial international access — verify before using as exit node")
        else:
            lines.append("  ✗ No international egress — national network or firewall on server")
    else:
        lines.append(f"  World → IR (server curl): {ok_server}/{len(targets)} Iranian sites OK")
        if ok_server >= 2:
            lines.append("  ✓ Foreign server can reach Iranian endpoints — route to IR buyers likely OK")
        elif ok_server >= 1:
            lines.append("  ⚠ Limited IR reachability from server — benchmark from real Irancell/MCI")
        else:
            lines.append("  ✗ Server cannot reach Iranian sites — poor choice for IR-focused configs")

    if is_client_iran and not is_server_iran:
        if local_443.tcp_ok and local_443.avg_ms:
            lines.append(
                f"  YOU → SERVER: OK — avg {local_443.avg_ms:.0f} ms from your ISP "
                f"(score {local_443.score})"
            )
            if local_443.p95_ms and local_443.p95_ms > 350:
                lines.append(f"  ⚠ High P95 ({local_443.p95_ms:.0f} ms) from Iran — consider closer region")
        else:
            lines.append("  YOU → SERVER: FAIL — your ISP may block or route poorly to this VPS IP")
    elif is_client_iran and is_server_iran:
        lines.append("  Both you and server are in Iran — use international test for server exit quality")
    elif not is_client_iran and not is_server_iran:
        lines.append("  Client and server both outside IR — IR route test is informational only")

    if client_ip and not is_server_iran:
        lines.append("")
        lines.append("  Server → YOUR IP: see TCP/ping section above (often blocked on residential IR)")

    lines.extend(["", f"  Exit code: {code}"])
    return "\n".join(lines)


async def test_ssh_connection(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host or not username:
        return "Enter host and username."

    if progress:
        progress(f"Connecting to {host}:{port}...")
    try:
        code, out, err = await _ssh(host, username, password, "echo OK && uname -a", port)
    except socket.timeout:
        return "\n".join(_header("SSH Connection — FAILED") + ["  Timeout connecting to SSH port."])
    except Exception as exc:
        return "\n".join(_header("SSH Connection — FAILED") + [f"  Error: {exc}"])

    lines = _header("SSH Connection Test")
    lines.append(f"  Host     : {host}:{port}")
    lines.append(f"  User     : {username}")
    lines.append(f"  Status   : {'OK' if code == 0 else 'FAILED'}")
    if out:
        lines.extend(["", _section("System"), f"  {out}"])
    if err and code != 0:
        lines.extend(["", _section("Error"), f"  {err}"])
    return "\n".join(lines)


async def run_server_diagnostics(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host or not username:
        return "Enter host and username."

    script = (
        "echo '=== OUTBOUND IP ==='; "
        "(curl -4 -s --max-time 8 https://api.ipify.org 2>/dev/null || wget -qO- --timeout=8 https://api.ipify.org 2>/dev/null || echo N/A); "
        "echo; echo '=== GEO (country/ISP) ==='; "
        "IP=$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null); "
        "curl -s --max-time 8 \"http://ip-api.com/line/${IP}?fields=status,country,countryCode,isp,as,query\" 2>/dev/null | head -8 || echo geo-unavailable; "
        "echo; echo '=== PING 8.8.8.8 ==='; "
        "ping -c 3 -W 3 8.8.8.8 2>/dev/null || ping -n 3 8.8.8.8 2>/dev/null || echo ping-unavailable; "
        "echo; echo '=== CURL GOOGLE ==='; "
        "curl -4 -sI --max-time 10 https://www.google.com 2>&1 | head -5; "
        "echo; echo '=== CURL CLOUDFLARE ==='; "
        "curl -4 -sI --max-time 10 https://1.1.1.1 2>&1 | head -5; "
        "echo; echo '=== DNS GOOGLE ==='; "
        "(dig +short google.com A 2>/dev/null || nslookup google.com 2>/dev/null | tail -3); "
        "echo; echo '=== DISK/MEM ==='; "
        "df -h / 2>/dev/null | tail -1; free -h 2>/dev/null | head -2 || echo mem-unavailable; "
        "echo; echo '=== UPTIME ==='; uptime 2>/dev/null || echo uptime-unavailable"
    )

    if progress:
        progress("Running full diagnostics on server...")
    try:
        code, out, err = await _ssh(host, username, password, script, port)
    except Exception as exc:
        return "\n".join(_header("Server Diagnostics — FAILED") + [f"  {exc}"])

    lines = _header("Remote Server Diagnostics")
    lines.append(f"  Host : {host}:{port}")
    lines.append(f"  User : {username}")
    lines.append("")
    lines.append(_section("Live results from server"))
    lines.append("")
    for line in (out or err or "(no output)").splitlines():
        lines.append(f"  {line}")

    lines.extend([
        "",
        _section("Next step"),
        "  Run «IR ↔ World route test» for auto IR/foreign direction checks.",
        "",
        f"  Exit code: {code}",
    ])
    return "\n".join(lines)


async def test_international_access(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    """Legacy wrapper — use test_bidirectional_connectivity."""
    return await test_bidirectional_connectivity(
        host, username, password, port, progress=progress,
    )


async def run_system_update(
    host: str,
    username: str,
    password: str,
    port: int = 22,
    *,
    upgrade: bool = False,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host or not username:
        return "Enter host and username."

    if upgrade:
        cmd = "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get upgrade -y -qq 2>&1 | tail -30"
        label = "System Update (apt update + upgrade)"
    else:
        cmd = "export DEBIAN_FRONTEND=noninteractive; apt-get update -qq 2>&1 && apt list --upgradable 2>/dev/null | head -25"
        label = "Package List Update (apt update)"

    if progress:
        progress(f"Running {label}...")
    try:
        code, out, err = await _ssh(host, username, password, cmd, port)
    except Exception as exc:
        return "\n".join(_header(f"{label} — FAILED") + [f"  {exc}"])

    lines = _header(label)
    lines.append(f"  Server: {host}")
    lines.append("")
    for line in (out or err or "(no output)").splitlines():
        lines.append(f"  {line}")
    lines.extend(["", f"  Exit code: {code}"])
    if code != 0:
        lines.append("  Note: non-Debian/Ubuntu systems may need manual package manager.")
    return "\n".join(lines)


def test_ssh_connection_sync(**kwargs) -> str:
    return asyncio.run(test_ssh_connection(**kwargs))


def run_server_diagnostics_sync(**kwargs) -> str:
    return asyncio.run(run_server_diagnostics(**kwargs))


def test_bidirectional_connectivity_sync(**kwargs) -> str:
    return asyncio.run(test_bidirectional_connectivity(**kwargs))


def test_international_access_sync(**kwargs) -> str:
    return asyncio.run(test_international_access(**kwargs))


def run_system_update_sync(**kwargs) -> str:
    return asyncio.run(run_system_update(**kwargs))
