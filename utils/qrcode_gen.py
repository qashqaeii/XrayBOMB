"""QR code generation for share links."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Optional

from backend.models import ParsedConfig
from utils.logger import get_logger

logger = get_logger(__name__)


def get_share_link(config: ParsedConfig) -> str:
    """Return best available share link for QR encoding."""
    if config.raw_url and "://" in config.raw_url:
        return config.raw_url.strip()
    return ""


def generate_qr_png(link: str, box_size: int = 8) -> bytes:
    """Generate QR code PNG bytes from a link string."""
    import qrcode

    qr = qrcode.QRCode(box_size=box_size, border=2)
    qr.add_data(link)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def save_qr_png(config: ParsedConfig, path: Path) -> Optional[Path]:
    """Save QR PNG for config; returns path or None if no link."""
    link = get_share_link(config)
    if not link:
        return None
    path.write_bytes(generate_qr_png(link))
    return path


def generate_qr_for_config(config: ParsedConfig) -> tuple[Optional[bytes], str]:
    """Return (png_bytes, share_link). png_bytes is None if no link."""
    link = get_share_link(config)
    if not link:
        return None, ""
    return generate_qr_png(link), link
