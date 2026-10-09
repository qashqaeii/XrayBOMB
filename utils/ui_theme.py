"""Shared UI colors, spacing, and font helpers."""

from __future__ import annotations

import sys
import tkinter.font as tkfont

# Layout
SIDEBAR_WIDTH = 340
STATUS_WIDTH = 300
HISTORY_MIN_HEIGHT = 220
LEFT_CONFIG_HISTORY_RATIO = (11, 9)  # config input vs history — analyze btn needs ~300px
PANEL_RADIUS = 10
PANEL_PAD = 12
LOG_MIN_HEIGHT = 150
CONTENT_LOG_RATIO = (4, 1)  # main workspace vs live log

# Palette
BG_DARK = "#0b0f17"
PANEL_BG = "#141b26"
PANEL_BORDER = "#243044"
TOOLBAR_BG = "#111827"
ACCENT = "#38bdf8"
ACCENT_BTN = "#2563eb"
ACCENT_BTN_HOVER = "#1d4ed8"
TEXT_MUTED = "#94a3b8"
TEXT_DIM = "#64748b"
SECTION_DIVIDER = "#1e293b"
SUCCESS = "#22c55e"
WARNING = "#f59e0b"
DANGER = "#ef4444"


def _first_available_font(candidates: tuple[str, ...]) -> str:
    try:
        available = set(tkfont.families())
        for name in candidates:
            if name in available:
                return name
    except Exception:
        pass
    return candidates[0]


def persian_font_family() -> str:
    """Font with Arabic/Persian joining (not monospace)."""
    if sys.platform == "win32":
        candidates = ("Segoe UI", "Tahoma", "Arial", "Microsoft Sans Serif")
    elif sys.platform == "darwin":
        candidates = ("Geeza Pro", "Arial", "Helvetica Neue")
    else:
        candidates = ("Noto Sans Arabic", "DejaVu Sans", "Sans")
    return _first_available_font(candidates)


def monospace_font_family() -> str:
    return _first_available_font(("Consolas", "Cascadia Mono", "Courier New", "monospace"))
