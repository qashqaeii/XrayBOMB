"""Tests for SSH vault encryption."""

import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def isolated_vault(monkeypatch):
    tmp = Path(tempfile.mkdtemp())
    monkeypatch.setattr("tools.ssh_vault.VAULT_DIR", tmp)
    monkeypatch.setattr("tools.ssh_vault.KEY_FILE", tmp / "key")
    monkeypatch.setattr("tools.ssh_vault.DB_FILE", tmp / "db")
    import tools.ssh_vault as mod
    mod._vault = None
    return mod.get_ssh_vault()


def test_vault_save_load(isolated_vault):
    vid = isolated_vault.save(
        label="Test DE",
        host="1.2.3.4",
        username="root",
        password="secret-pass",
        port=22,
        region="Foreign",
    )
    p = isolated_vault.get(vid)
    assert p is not None
    assert p.host == "1.2.3.4"
    assert p.password == "secret-pass"
    assert p.label == "Test DE"


def test_vault_list_and_delete(isolated_vault):
    vid = isolated_vault.save(label="A", host="10.0.0.1", username="u", password="p")
    assert len(isolated_vault.list_profiles()) == 1
    isolated_vault.delete(vid)
    assert isolated_vault.list_profiles() == []
