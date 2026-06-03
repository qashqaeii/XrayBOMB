"""General helper utilities."""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any, Optional


def safe_b64decode(data: str) -> bytes:
    """Decode base64 with padding correction."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def safe_b64encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def parse_query_params(query: str) -> dict[str, str]:
    """Parse URL query string into dict."""
    return {k: v[0] if len(v) == 1 else v for k, v in urllib.parse.parse_qs(query).items()}


def is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    ipv4 = re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host)
    if ipv4:
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    ipv6 = re.match(r"^[\da-fA-F:]+$", host) and ":" in host
    return bool(ipv6)


def truncate(text: str, max_len: int = 80) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def mask_sensitive(value: Optional[str], visible: int = 4) -> str:
    """Mask sensitive values for display."""
    if not value:
        return "N/A"
    if len(value) <= visible * 2:
        return "*" * len(value)
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


def try_parse_json(text: str) -> Optional[Any]:
    """Attempt JSON parse, return None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
