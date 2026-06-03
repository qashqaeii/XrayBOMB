"""Professional logging configuration."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logging(log_dir: Optional[Path] = None, level: int = logging.INFO) -> None:
    """Configure application-wide logging."""
    log_dir = log_dir or Path.home() / ".xray_analyzer" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "xray_analyzer.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a named logger."""
    return logging.getLogger(name)
