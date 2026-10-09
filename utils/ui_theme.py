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
BG_DARK = "#0d0d1a"
PANEL_BG = "#1a1a2e"
PANEL_BORDER = "#2a2a4e"
TOOLBAR_BG = "#16213e"
ACCENT = "#00d4ff"
ACCENT_BTN = "#0066cc"
ACCENT_BTN_HOVER = "#0052a3"
TEXT_MUTED = "#8888aa"
TEXT_DIM = "#666688"
SECTION_DIVIDER = "#2a2a4e"


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
