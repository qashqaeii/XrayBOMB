"""Periodic health monitoring for saved configs."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime
from typing import Callable, Optional

from backend.analyzer import ConfigAnalyzer
from backend.config_parser import parse_share_link
from database.db import AnalysisDatabase
from utils.logger import get_logger
from utils.settings import get_settings

logger = get_logger(__name__)


class HealthMonitor:
    def __init__(
        self,
        on_result: Optional[Callable[[int, str, int], None]] = None,
    ) -> None:
        self._timer: Optional[threading.Timer] = None
        self._running = False
        self._on_result = on_result
        self._db = AnalysisDatabase()
        self._analyzer = ConfigAnalyzer(run_xray_test=False)

    def start(self) -> None:
        settings = get_settings()
        if not settings.enable_health_monitor:
            return
        self._running = True
        self._schedule(settings.health_check_interval_min * 60)

    def stop(self) -> None:
        self._running = False
        if self._timer:
            self._timer.cancel()

    def _schedule(self, interval_sec: int) -> None:
        if not self._running:
            return
        self._timer = threading.Timer(interval_sec, self._run_check)
        self._timer.daemon = True
        self._timer.start()

    def _run_check(self) -> None:
        try:
            asyncio.run(self._check_all())
        except Exception as exc:
            logger.error("Health monitor error: %s", exc)
        settings = get_settings()
        self._schedule(settings.health_check_interval_min * 60)

    async def _check_all(self) -> None:
        for row in self._db.list_recent(limit=20):
            result = self._db.load(row["id"])
            if not result or not result.config.raw_url:
                continue
            try:
                cfg = parse_share_link(result.config.raw_url)
                new_result = await self._analyzer.analyze(cfg)
                score = new_result.security.score
                status = "OK" if score >= 50 else "DEGRADED"
                self._db.update_health(row["id"], score, status)
                if self._on_result:
                    self._on_result(row["id"], status, score)
            except Exception as exc:
                logger.debug("Health check failed for id=%s: %s", row["id"], exc)
