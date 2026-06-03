"""Application settings persistence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

SETTINGS_PATH = Path.home() / ".xray_analyzer" / "config.json"


class AppSettings(BaseModel):
    appearance_mode: str = "dark"
    color_theme: str = "blue"
    run_xray_test: bool = True
    real_proxy_test: bool = True
    redact_secrets_export: bool = True
    mask_secrets_ui: bool = True
    geo_cache_hours: int = 24
    analysis_timeout: int = 30
    latency_samples: int = 5
    enable_traceroute: bool = True
    enable_threat_intel: bool = True
    enable_cert_transparency: bool = True
    enable_health_monitor: bool = False
    health_check_interval_min: int = 60
    cloud_sync_url: Optional[str] = None
    cloud_sync_token: Optional[str] = None
    ip_api_key: Optional[str] = None
    plugin_dir: Optional[str] = None
    extra: dict[str, Any] = Field(default_factory=dict)


_settings: Optional[AppSettings] = None


def load_settings() -> AppSettings:
    global _settings
    if _settings is not None:
        return _settings
    if SETTINGS_PATH.exists():
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
            _settings = AppSettings.model_validate(data)
            return _settings
        except Exception:
            pass
    _settings = AppSettings()
    return _settings


def save_settings(settings: AppSettings) -> None:
    global _settings
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(settings.model_dump_json(indent=2), encoding="utf-8")
    _settings = settings


def get_settings() -> AppSettings:
    return load_settings()
