"""Parse user-supplied IP lists and CIDR ranges for scanning."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def parse_ip_lines(text: str, *, max_ips: int = 512) -> tuple[list[str], list[str]]:
    """Extract unique IPv4 addresses from pasted text (one per line or comma-separated)."""
    found: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    for raw_line in text.replace(",", "\n").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0] if line.split() else line
        if "/" in token:
            errors.append(f"Use CIDR mode for ranges: {token}")
            continue
        if not _is_ipv4(token):
            errors.append(f"Invalid IP: {token}")
            continue
        if token not in seen:
            seen.add(token)
            found.append(token)
        if len(found) >= max_ips:
            errors.append(f"Truncated to {max_ips} IPs")
            break

    return found, errors


def parse_cidr_lines(text: str, *, max_ips: int = 512) -> tuple[list[str], list[str]]:
    """Expand CIDR lines into host IPs (cap per range and total)."""
    found: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    for raw_line in text.replace(",", "\n").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0]
        try:
            net = ipaddress.IPv4Network(token, strict=False)
        except ValueError:
            errors.append(f"Invalid CIDR: {token}")
            continue

        if net.prefixlen < 20:
            errors.append(f"Skipped {token} — prefix /{net.prefixlen} too large (max /20)")
            continue

        hosts = list(net.hosts())
        if not hosts:
            errors.append(f"No hosts in {token}")
            continue

        per_range = min(len(hosts), max(1, max_ips // max(1, text.count("/") + 1)))
        step = max(1, len(hosts) // per_range)
        for i in range(0, len(hosts), step):
            ip = str(hosts[i])
            if ip not in seen:
                seen.add(ip)
                found.append(ip)
            if len(found) >= max_ips:
                break
        if len(found) >= max_ips:
            errors.append(f"Truncated to {max_ips} IPs total")
            break

    return found, errors


def build_scan_list(
    *,
    mode: str,
    custom_text: str = "",
    region: str = "Cloudflare live",
    max_ips: int = 40,
    cf_cidrs: Optional[list[str]] = None,
) -> tuple[list[str], str, list[str]]:
    """
    Returns (ips, source_label, warnings).
    All IPs come from user input or live Cloudflare publish list — no invented addresses.
    """
    warnings: list[str] = []

    if mode == "Custom IP list":
        ips, errs = parse_ip_lines(custom_text, max_ips=max_ips)
        warnings.extend(errs)
        if not ips:
            raise ValueError("No valid IPs in list. Paste one IPv4 per line.")
        return ips, f"Custom IP list ({len(ips)} addresses)", warnings

    if mode == "Custom CIDR ranges":
        ips, errs = parse_cidr_lines(custom_text, max_ips=max_ips)
        warnings.extend(errs)
        if not ips:
            raise ValueError("No valid CIDR ranges or no hosts expanded. Example: 104.16.0.0/24")
        return ips, f"Custom CIDR expanded ({len(ips)} hosts)", warnings

    # Cloudflare live — official published IPv4 ranges only
    if not cf_cidrs:
        raise ValueError("Could not load Cloudflare IPv4 list from cloudflare.com/ips-v4")
    from tools.cloudflare_ranges import sample_ips_from_cidrs

    ips = sample_ips_from_cidrs(cf_cidrs, max_ips=max_ips)
    if not ips:
        raise ValueError("Cloudflare list empty — check network connection.")
    label = f"Cloudflare published IPv4 (sampled {len(ips)} from {len(cf_cidrs)} ranges)"
    if region and region not in ("Auto (Best Latency)", "All Cloudflare"):
        warnings.append(
            f"Note: Cloudflare uses anycast — '{region}' does not isolate PoP; geo column is measured per IP."
        )
    return ips, label, warnings
