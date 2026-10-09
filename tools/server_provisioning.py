"""SSH server setup — panels, SSL, apt, dependencies (upstream install scripts)."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Callable, Optional

from tools.remote_server_ssh import _header, _run_ssh, _section

PANEL_TIMEOUT = 900
APT_TIMEOUT = 600
SSL_TIMEOUT = 300
DEFAULT_TIMEOUT = 120


@dataclass(frozen=True)
class ProvisionAction:
    id: str
    label: str
    group: str
    description: str
    timeout: int = DEFAULT_TIMEOUT
    confirm: bool = True
    needs_domain: bool = False
    needs_email: bool = False


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


PROVISION_ACTIONS: tuple[ProvisionAction, ...] = (
    # System
    ProvisionAction(
        "apt_update", "apt update (preview upgrades)", "System",
        "Refresh package lists and show upgradable packages.",
        timeout=APT_TIMEOUT, confirm=False,
    ),
    ProvisionAction(
        "apt_upgrade", "apt upgrade (install all)", "System",
        "Install all available security and package updates.",
        timeout=APT_TIMEOUT,
    ),
    ProvisionAction(
        "install_deps", "Install common dependencies", "System",
        "curl, wget, git, socat, ufw, fail2ban, openssl, dnsutils, unzip.",
        timeout=APT_TIMEOUT,
    ),
    ProvisionAction(
        "enable_bbr", "Enable BBR congestion control", "System",
        "Add fq + bbr to sysctl (reboot may be required).",
        timeout=DEFAULT_TIMEOUT, confirm=False,
    ),
    ProvisionAction(
        "install_docker", "Install Docker (Marzban / compose)", "System",
        "Official get.docker.com script for panel stacks using Docker.",
        timeout=PANEL_TIMEOUT,
    ),
    # Panels
    ProvisionAction(
        "panel_3xui_sanaei", "Install 3x-ui (Sanaei / MHSanaei)", "Panels",
        "Latest 3x-ui panel from MHSanaei GitHub install.sh.",
        timeout=PANEL_TIMEOUT,
    ),
    ProvisionAction(
        "panel_marzban", "Install Marzban", "Panels",
        "Official Marzban install script (Gozargah).",
        timeout=PANEL_TIMEOUT,
    ),
    ProvisionAction(
        "panel_xui_alireza", "Install x-ui (Alireza0)", "Panels",
        "alireza0/x-ui fork install script.",
        timeout=PANEL_TIMEOUT,
    ),
    ProvisionAction(
        "panel_xui_legacy", "Install x-ui (legacy vaxilu)", "Panels",
        "Original vaxilu x-ui installer (older servers).",
        timeout=PANEL_TIMEOUT,
    ),
    ProvisionAction(
        "panel_status", "Panel / xray service status", "Panels",
        "Show systemd status for common panels and xray.",
        timeout=DEFAULT_TIMEOUT, confirm=False,
    ),
    # SSL
    ProvisionAction(
        "ssl_certbot", "SSL: Certbot standalone (domain)", "SSL / Domain",
        "Let's Encrypt via certbot — port 80 must be free during issue.",
        timeout=SSL_TIMEOUT, needs_domain=True,
    ),
    ProvisionAction(
        "ssl_acme", "SSL: acme.sh (domain)", "SSL / Domain",
        "Issue cert with acme.sh standalone mode.",
        timeout=SSL_TIMEOUT, needs_domain=True, needs_email=True,
    ),
    ProvisionAction(
        "ssl_list_certs", "SSL: list certificates", "SSL / Domain",
        "List certbot certificates if present.",
        timeout=DEFAULT_TIMEOUT, confirm=False,
    ),
    # Firewall / ports
    ProvisionAction(
        "ufw_xray_ports", "UFW: allow SSH + panel ports", "Firewall",
        "Open 22, 443, 2053, 8443, 2096, 2087 (adjust after if needed).",
        timeout=DEFAULT_TIMEOUT, confirm=False,
    ),
)

ACTION_BY_ID: dict[str, ProvisionAction] = {a.id: a for a in PROVISION_ACTIONS}
ACTION_GROUPS: tuple[str, ...] = tuple(dict.fromkeys(a.group for a in PROVISION_ACTIONS))

# UI sections for Server Setup tab (title → action ids)
SETUP_UI_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("System & packages", ("install_deps", "apt_update", "apt_upgrade", "install_docker", "enable_bbr")),
    ("Proxy panels", ("panel_3xui_sanaei", "panel_marzban", "panel_xui_alireza", "panel_xui_legacy", "panel_status")),
    ("SSL / domain", ("ssl_certbot", "ssl_acme", "ssl_list_certs")),
    ("Firewall & network", ("ufw_xray_ports",)),
)


def actions_for_group(group: str) -> list[ProvisionAction]:
    return [a for a in PROVISION_ACTIONS if a.group == group]


def action_labels_for_group(group: str) -> list[str]:
    return [a.label for a in actions_for_group(group)]


def action_by_label(group: str, label: str) -> Optional[ProvisionAction]:
    for a in actions_for_group(group):
        if a.label == label:
            return a
    return None


def build_command(
    action_id: str,
    *,
    domain: str = "",
    email: str = "",
) -> tuple[str, int]:
    """Return (shell_command, timeout_seconds)."""
    action = ACTION_BY_ID.get(action_id)
    if not action:
        raise ValueError(f"Unknown action: {action_id}")

    domain = domain.strip().lower()
    email = email.strip()

    if action.needs_domain and not domain:
        raise ValueError("Domain is required for this action.")
    if domain and not re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", domain):
        raise ValueError("Invalid domain name.")

    d = _shell_quote(domain)
    e = _shell_quote(email) if email else ""

    commands: dict[str, str] = {
        "apt_update": (
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -qq 2>&1 && apt list --upgradable 2>/dev/null | head -30"
        ),
        "apt_upgrade": (
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -qq && apt-get upgrade -y -qq 2>&1 | tail -40"
        ),
        "install_deps": (
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -qq && apt-get install -y -qq "
            "curl wget ca-certificates socat git unzip ufw fail2ban "
            "dnsutils openssl jq cron 2>&1 | tail -25"
        ),
        "enable_bbr": (
            "grep -q 'net.core.default_qdisc=fq' /etc/sysctl.conf 2>/dev/null || "
            "printf '\\nnet.core.default_qdisc=fq\\nnet.ipv4.tcp_congestion_control=bbr\\n' "
            ">> /etc/sysctl.conf; sysctl -p 2>&1 | tail -5"
        ),
        "install_docker": (
            "curl -fsSL https://get.docker.com | sh 2>&1 | tail -30"
        ),
        "panel_3xui_sanaei": (
            "bash <(curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh)"
        ),
        "panel_marzban": (
            'bash -c "$(curl -sL https://github.com/Gozargah/Marzban-scripts/raw/master/marzban.sh)" @ install'
        ),
        "panel_xui_alireza": (
            "bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)"
        ),
        "panel_xui_legacy": (
            "bash <(curl -Ls https://raw.githubusercontent.com/vaxilu/x-ui/master/install.sh)"
        ),
        "panel_status": (
            "echo '=== Panel / Xray status ==='; "
            "for s in x-ui xray marzban; do "
            "systemctl is-active $s 2>/dev/null && systemctl status $s --no-pager -l 2>/dev/null | head -12; "
            "done; "
            "docker ps --format 'table {{.Names}}\\t{{.Status}}' 2>/dev/null | head -10 || true"
        ),
        "ssl_certbot": (
            f"export DEBIAN_FRONTEND=noninteractive; "
            f"apt-get install -y -qq certbot 2>/dev/null; "
            f"certbot certonly --standalone --preferred-challenges http "
            f"--agree-tos --non-interactive "
            f"{'--email ' + e + ' ' if email else '--register-unsafely-without-email '} "
            f"-d {d} 2>&1"
        ),
        "ssl_acme": (
            f"curl -fsSL https://get.acme.sh | sh -s email={email or 'admin@' + domain}; "
            f"~/.acme.sh/acme.sh --set-default-ca --server letsencrypt; "
            f"~/.acme.sh/acme.sh --issue -d {d} --standalone 2>&1"
        ),
        "ssl_list_certs": (
            "certbot certificates 2>&1 || ls -la /etc/letsencrypt/live/ 2>&1"
        ),
        "ufw_xray_ports": (
            "ufw allow 22/tcp; ufw allow 443/tcp; ufw allow 2053/tcp; "
            "ufw allow 8443/tcp; ufw allow 2096/tcp; ufw allow 2087/tcp; "
            "ufw status numbered 2>&1 | head -25"
        ),
    }

    cmd = commands.get(action_id)
    if not cmd:
        raise ValueError(f"No command for action: {action_id}")
    return cmd, action.timeout


async def run_provisioning_action(
    host: str,
    username: str,
    password: str,
    action_id: str,
    port: int = 22,
    *,
    domain: str = "",
    email: str = "",
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host or not username:
        return "Enter host and username."

    action = ACTION_BY_ID.get(action_id)
    if not action:
        return f"Unknown action: {action_id}"

    try:
        cmd, timeout = build_command(action_id, domain=domain, email=email)
    except ValueError as exc:
        return str(exc)

    if progress:
        progress(f"Running: {action.label}...")

    try:
        code, out, err = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: _run_ssh(host, username, password, cmd, port=port, timeout=timeout),
        )
    except Exception as exc:
        return "\n".join(_header(f"{action.label} — FAILED") + [f"  {exc}", ""])

    lines = _header(action.label)
    lines.append(f"  Server : {username}@{host}:{port}")
    if domain:
        lines.append(f"  Domain : {domain}")
    lines.append(f"  Group  : {action.group}")
    lines.append(f"  Note   : {action.description}")
    lines.append("")
    lines.append(_section("Output"))
    combined = out or err or "(no output)"
    for line in combined.splitlines():
        lines.append(f"  {line}")
    lines.extend([
        "",
        f"  Exit code: {code}",
        "",
        _section("Reminder"),
        "  Panel installers may prompt on the server — use SSH Console for interactive steps.",
        "  Certbot standalone needs port 80 free; stop nginx/x-ui before SSL if needed.",
        "",
    ])
    return "\n".join(lines)


def run_provisioning_action_sync(**kwargs) -> str:
    return asyncio.run(run_provisioning_action(**kwargs))
