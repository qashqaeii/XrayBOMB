"""Cloud sync for analysis history."""

from __future__ import annotations

import json
from typing import Optional

import httpx

from backend.models import AnalysisResult
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)


async def sync_upload(result: AnalysisResult) -> bool:
    settings = get_settings()
    if not settings.cloud_sync_url:
        return False
    headers = {"Content-Type": "application/json"}
    if settings.cloud_sync_token:
        headers["Authorization"] = f"Bearer {settings.cloud_sync_token}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                settings.cloud_sync_url,
                content=result.model_dump_json(),
                headers=headers,
            )
            return resp.status_code < 300
    except Exception as exc:
        logger.warning("Cloud sync upload failed: %s", exc)
        return False


async def sync_download(limit: int = 50) -> list[dict]:
    settings = get_settings()
    if not settings.cloud_sync_url:
        return []
    headers = {}
    if settings.cloud_sync_token:
        headers["Authorization"] = f"Bearer {settings.cloud_sync_token}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(settings.cloud_sync_url, headers=headers, params={"limit": limit})
            if resp.status_code == 200:
                data = resp.json()
                return data if isinstance(data, list) else data.get("results", [])
    except Exception as exc:
        logger.warning("Cloud sync download failed: %s", exc)
    return []
