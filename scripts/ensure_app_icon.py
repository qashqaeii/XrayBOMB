#!/usr/bin/env python3
"""Build images/Bomb.ico from images/Bomb.png for Windows EXE/taskbar."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PNG = ROOT / "images" / "Bomb.png"
ICO = ROOT / "images" / "Bomb.ico"


def ensure_app_icon() -> Path:
    if not PNG.is_file():
        raise FileNotFoundError(f"Logo PNG missing: {PNG}")
    try:
        from PIL import Image
    except ImportError:
        raise SystemExit("Pillow required: pip install pillow") from None

    png_mtime = PNG.stat().st_mtime
    if ICO.is_file() and ICO.stat().st_mtime >= png_mtime:
        return ICO

    img = Image.open(PNG)
    if img.mode != "RGBA":
        img = img.convert("RGBA")
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    img.save(ICO, format="ICO", sizes=sizes)
    print(f"Wrote {ICO}")
    return ICO


if __name__ == "__main__":
    ensure_app_icon()
    sys.exit(0)
