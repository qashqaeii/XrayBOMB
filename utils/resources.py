"""Bundled asset paths (dev tree vs PyInstaller _MEIPASS)."""

from __future__ import annotations

import sys
from pathlib import Path


def project_root() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    return project_root().joinpath(*parts)


def app_logo_png() -> Path:
    return resource_path("images", "Bomb.png")


def app_logo_ico() -> Path:
    return resource_path("images", "Bomb.ico")
