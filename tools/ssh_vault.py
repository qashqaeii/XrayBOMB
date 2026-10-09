"""Encrypted local vault for SSH server profiles."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken

from utils.logger import get_logger

logger = get_logger(__name__)

VAULT_DIR = Path.home() / ".xray_analyzer"
KEY_FILE = VAULT_DIR / "ssh_vault.key"
DB_FILE = VAULT_DIR / "ssh_servers.db"


@dataclass
class SSHServerProfile:
    id: int
    label: str
    host: str
    port: int
    username: str
    password: str
    region: str = ""
    notes: str = ""
    last_used: Optional[str] = None
    created_at: Optional[str] = None

    @property
    def display(self) -> str:
        reg = f" [{self.region}]" if self.region else ""
        return f"{self.label} — {self.username}@{self.host}:{self.port}{reg}"


class SSHVault:
    """SQLite + Fernet vault for SSH credentials (local machine only)."""

    def __init__(self) -> None:
        VAULT_DIR.mkdir(parents=True, exist_ok=True)
        self._fernet = Fernet(self._load_or_create_key())
        self._init_db()

    @staticmethod
    def _load_or_create_key() -> bytes:
        if KEY_FILE.exists():
            return KEY_FILE.read_bytes()
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        try:
            KEY_FILE.chmod(0o600)
        except OSError:
            pass
        return key

    def _init_db(self) -> None:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ssh_servers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    label TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL DEFAULT 22,
                    username TEXT NOT NULL,
                    password_enc TEXT NOT NULL,
                    region TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    last_used TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

    def _encrypt(self, plain: str) -> str:
        return self._fernet.encrypt(plain.encode("utf-8")).decode("ascii")

    def _decrypt(self, token: str) -> str:
        try:
            return self._fernet.decrypt(token.encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Vault decryption failed — key may have changed.") from exc

    def list_profiles(self) -> list[SSHServerProfile]:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM ssh_servers ORDER BY COALESCE(last_used, created_at) DESC"
            ).fetchall()
        out: list[SSHServerProfile] = []
        for row in rows:
            try:
                pwd = self._decrypt(row["password_enc"])
            except ValueError:
                pwd = ""
            out.append(self._row_to_profile(row, pwd))
        return out

    def get(self, profile_id: int) -> Optional[SSHServerProfile]:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM ssh_servers WHERE id = ?", (profile_id,)).fetchone()
        if not row:
            return None
        return self._row_to_profile(row, self._decrypt(row["password_enc"]))

    def save(
        self,
        *,
        label: str,
        host: str,
        username: str,
        password: str,
        port: int = 22,
        region: str = "",
        notes: str = "",
        profile_id: Optional[int] = None,
    ) -> int:
        label = label.strip() or host.strip()
        host = host.strip()
        username = username.strip()
        if not host or not username:
            raise ValueError("Host and username are required.")
        now = datetime.now(timezone.utc).isoformat()
        enc = self._encrypt(password or "")

        with sqlite3.connect(DB_FILE) as conn:
            if profile_id:
                conn.execute(
                    """UPDATE ssh_servers SET label=?, host=?, port=?, username=?,
                       password_enc=?, region=?, notes=? WHERE id=?""",
                    (label, host, port, username, enc, region, notes, profile_id),
                )
                conn.commit()
                return profile_id
            cur = conn.execute(
                """INSERT INTO ssh_servers
                   (label, host, port, username, password_enc, region, notes, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (label, host, port, username, enc, region, notes, now),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def delete(self, profile_id: int) -> None:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM ssh_servers WHERE id = ?", (profile_id,))
            conn.commit()

    def touch(self, profile_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("UPDATE ssh_servers SET last_used = ? WHERE id = ?", (now, profile_id))
            conn.commit()

    @staticmethod
    def _row_to_profile(row: sqlite3.Row, password: str) -> SSHServerProfile:
        return SSHServerProfile(
            id=int(row["id"]),
            label=row["label"],
            host=row["host"],
            port=int(row["port"]),
            username=row["username"],
            password=password,
            region=row["region"] or "",
            notes=row["notes"] or "",
            last_used=row["last_used"],
            created_at=row["created_at"],
        )


_vault: Optional[SSHVault] = None


def get_ssh_vault() -> SSHVault:
    global _vault
    if _vault is None:
        _vault = SSHVault()
    return _vault
