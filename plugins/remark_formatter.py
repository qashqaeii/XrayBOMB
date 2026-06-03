"""Sample plugin: normalize remark for reseller display."""

from __future__ import annotations

import re

from backend.models import AnalysisResult, ParsedConfig


def _format_remark(config: ParsedConfig) -> str:
    base = config.remark or config.address or "Unnamed"
    base = re.sub(r"\s+", " ", base.strip())
    proto = config.protocol.value
    country = ""
    if config.extra.get("country"):
        country = f" [{config.extra['country']}]"
    tls = "🔒" if config.tls else ""
    return f"{base}{country} | {proto} {config.address}:{config.port} {tls}".strip()


def analyze(result: AnalysisResult, config: ParsedConfig) -> AnalysisResult:
    """Plugin hook: add formatted remark for sales/export."""
    formatted = _format_remark(config)
    result.raw_data.setdefault("plugins", {})["remark_formatter"] = {
        "original": config.remark,
        "formatted": formatted,
    }
    if config.remark != formatted:
        result.config.remark = formatted
    return result
