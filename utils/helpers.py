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


_ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])"
)
_OSC_ESCAPE_RE = re.compile(r"\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)")
# CSI without ESC (common when xterm sequences are split or ESC is dropped)
_CSI_ORPHAN_RE = re.compile(r"\[[\?0-9][0-9;]*[ -/]*[@-~a-zA-Z]")


def strip_ansi(text: str) -> str:
    """Remove terminal escape sequences for plain-text UI display."""
    text = _OSC_ESCAPE_RE.sub("", text)
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CSI_ORPHAN_RE.sub("", text)
    return text


def normalize_terminal_text(text: str) -> str:
    """Turn CR-separated segments into lines (keep output before prompt redraws)."""
    if "\r" not in text:
        return text
    out_lines: list[str] = []
    for line in text.split("\n"):
        if "\r" in line:
            out_lines.extend(seg for seg in line.split("\r") if seg)
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def clean_terminal_chunk(text: str) -> str:
    """ANSI strip + CR normalization for plain-text terminal widgets."""
    return normalize_terminal_text(strip_ansi(text))


_SHELL_PROMPT_TAIL_RE = re.compile(r"[#$]\s*$")


class TerminalOutputBuffer:
    """Reassemble SSH stream chunks so prompts start on a new line."""

    def __init__(self) -> None:
        self._pending = ""

    def clear(self) -> None:
        self._pending = ""

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        if self._pending and not self._pending.endswith("\n") and not chunk.startswith("\n"):
            chunk = "\n" + chunk
        work = clean_terminal_chunk(self._pending + chunk)
        self._pending = ""
        if not work:
            return ""
        if work.endswith("\n"):
            return work
        last_nl = work.rfind("\n")
        if last_nl >= 0:
            self._pending = work[last_nl + 1 :]
            out = work[: last_nl + 1]
            out += self._flush_prompt_line()
            return out
        self._pending = work
        return self._flush_prompt_line()

    def _flush_prompt_line(self) -> str:
        if self._pending and _SHELL_PROMPT_TAIL_RE.search(self._pending):
            line = self._pending if self._pending.endswith("\n") else self._pending + "\n"
            self._pending = ""
            return line
        return ""

    def flush(self) -> str:
        if not self._pending:
            return ""
        line = self._pending if self._pending.endswith("\n") else self._pending + "\n"
        self._pending = ""
        return line


def try_parse_json(text: str) -> Optional[Any]:
    """Attempt JSON parse, return None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None
