"""Persian/Arabic display helpers for Tk text widgets."""

from __future__ import annotations

import re

_ARABIC_RE = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]")
_ARABIC_PART = re.compile(r"[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]+")
_STEP_RE = re.compile(r"^(\s*)([\u0660-\u0669\u06f0-\u06f90-9]+)\.\s*(.+)$")
_CHECKBOX_RE = re.compile(r"^(\s*)☐\s*(.+)$")
_LTR_PREFIX = re.compile(
    r"^\s*(Protocol|Port|Listen|UUID|Path|Host|Security|SNI|ALPN|Network|Flow|Method|Password|"
    r"address|port|Transport|bash|location|proxy_|grpc_|nginx|ufw|ssh|http|systemctl|"
    r"SSL/|Caching|WebSocket|WAF|Compression|Save|Private|Dest|Server|Short|Fingerprint|"
    r"Certificate|Mode|#|\{|\}|//)",
    re.IGNORECASE,
)

_reshaper = None


def _load_reshaper():
    global _reshaper
    if _reshaper is not None:
        return
    try:
        import arabic_reshaper

        _reshaper = arabic_reshaper.ArabicReshaper(
            configuration={"delete_harakat": False, "support_ligatures": True},
        )
    except ImportError:
        _reshaper = False


def contains_persian(text: str) -> bool:
    return bool(_ARABIC_RE.search(text))


def reshape_mixed(text: str) -> str:
    """Connect Persian/Arabic letters; leave Latin/code segments unchanged."""
    if not text or not contains_persian(text):
        return text
    _load_reshaper()
    if not _reshaper:
        return text
    parts = _ARABIC_PART.split(text)
    out: list[str] = []
    for part in parts:
        if not part:
            continue
        out.append(_reshaper.reshape(part) if _ARABIC_RE.search(part) else part)
    return "".join(out)


def is_ltr_line(line: str) -> bool:
    if not line.strip():
        return True
    if not contains_persian(line):
        return True
    if _LTR_PREFIX.match(line):
        return True
    ascii_chars = sum(1 for ch in line if ord(ch) < 128)
    return ascii_chars / max(len(line.strip()), 1) > 0.72


def format_rtl_line(line: str) -> str:
    """Format one RTL line for Tk (LTR renderer + right justify)."""
    step = _STEP_RE.match(line)
    if step:
        indent, num, body = step.groups()
        return f"{indent}{reshape_mixed(body)} .{num}"

    checkbox = _CHECKBOX_RE.match(line)
    if checkbox:
        indent, body = checkbox.groups()
        return f"{indent}{reshape_mixed(body)} ☐"

    shaped = reshape_mixed(line)
    if shaped.startswith("\u200f"):
        return shaped
    return f"\u200f{shaped}"


def split_persian_lines(text: str) -> list[tuple[str, str]]:
    """Split text into (display_line, tag) pairs for Tk: tag is 'rtl' or 'ltr'."""
    rows: list[tuple[str, str]] = []
    for line in text.split("\n"):
        if is_ltr_line(line):
            rows.append((line, "ltr"))
        else:
            rows.append((format_rtl_line(line), "rtl"))
    return rows


def prepare_persian_display(text: str) -> str:
    """Legacy helper — flat text with direction markers (prefer split_persian_lines)."""
    return "\n".join(display for display, _tag in split_persian_lines(text))
