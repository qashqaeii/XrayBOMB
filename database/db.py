"""SQLite database for analysis history."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from backend.models import AnalysisResult, BatchAnalysisResult
from utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisDatabase:
    """Persist analysis results."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self.db_path = db_path or Path.home() / ".xray_analyzer" / "history.db"
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    protocol TEXT,
                    address TEXT,
                    port INTEGER,
                    remark TEXT,
                    security_score INTEGER,
                    analyzed_at TEXT,
                    result_json TEXT,
                    health_status TEXT DEFAULT 'unknown',
                    last_health_check TEXT,
                    health_score INTEGER
                )
            """)
            conn.commit()
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()}
        for col, typedef in [
            ("health_status", "TEXT DEFAULT 'unknown'"),
            ("last_health_check", "TEXT"),
            ("health_score", "INTEGER"),
        ]:
            if col not in cols:
                conn.execute(f"ALTER TABLE analyses ADD COLUMN {col} {typedef}")
        conn.commit()

    def save(self, result: AnalysisResult) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """INSERT INTO analyses (protocol, address, port, remark, security_score, analyzed_at, result_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.config.protocol.value,
                    result.config.address,
                    result.config.port,
                    result.config.remark,
                    result.security.score,
                    result.analyzed_at.isoformat(),
                    result.model_dump_json(),
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0

    def save_batch(self, batch: BatchAnalysisResult) -> list[int]:
        return [self.save(r) for r in batch.results]

    def list_recent(self, limit: int = 50) -> list[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT id, protocol, address, port, remark, security_score, analyzed_at,
                          health_status, health_score FROM analyses ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]

    def search(self, query: str, limit: int = 50) -> list[dict]:
        q = f"%{query}%"
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT id, protocol, address, port, remark, security_score, analyzed_at,
                          health_status FROM analyses
                   WHERE protocol LIKE ? OR address LIKE ? OR remark LIKE ?
                   ORDER BY id DESC LIMIT ?""",
                (q, q, q, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def load(self, analysis_id: int) -> Optional[AnalysisResult]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute("SELECT result_json FROM analyses WHERE id = ?", (analysis_id,)).fetchone()
            if row:
                return AnalysisResult.model_validate_json(row[0])
        return None

    def delete(self, analysis_id: int) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
            conn.commit()

    def update_health(self, analysis_id: int, score: int, status: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """UPDATE analyses SET health_score=?, health_status=?, last_health_check=?
                   WHERE id=?""",
                (score, status, datetime.now().isoformat(), analysis_id),
            )
            conn.commit()
