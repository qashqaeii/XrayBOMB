"""Xray-core download and process management."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import threading
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

from utils.logger import get_logger
from utils.port_allocator import DEFAULT_LOOPBACK, is_port_listening

logger = get_logger(__name__)

GITHUB_RELEASES = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"
LOG_MAX_CHARS = 8000


@dataclass
class XrayBackgroundRun:
    proc: subprocess.Popen
    config_path: Path
    socks_host: str = DEFAULT_LOOPBACK
    socks_port: int = 0
    log_lines: list[str] = field(default_factory=list)
    _reader_done: threading.Event = field(default_factory=threading.Event)

    def _read_streams(self) -> None:
        assert self.proc.stderr is not None
        try:
            for line in self.proc.stderr:
                self.log_lines.append(line.rstrip("\n\r"))
                if sum(len(x) for x in self.log_lines) > LOG_MAX_CHARS:
                    self.log_lines = self.log_lines[-200:]
        except Exception as exc:
            self.log_lines.append(f"[log reader error] {exc}")
        finally:
            self._reader_done.set()

    def start_log_reader(self) -> None:
        t = threading.Thread(target=self._read_streams, daemon=True)
        t.start()

    def filtered_log(self) -> str:
        return "\n".join(self.log_lines[-120:])

    def poll_exit(self) -> Optional[int]:
        return self.proc.poll()

    def is_alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3)
            except Exception:
                pass


class XrayManager:
    """Manage Xray-core binary lifecycle."""

    def __init__(self, install_dir: Optional[Path] = None) -> None:
        self.install_dir = install_dir or Path.home() / ".xray_analyzer" / "xray"
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self._binary: Optional[Path] = None

    @property
    def binary_path(self) -> Path:
        if self._binary and self._binary.exists():
            return self._binary
        system = platform.system().lower()
        name = "xray.exe" if system == "windows" else "xray"
        path = self.install_dir / name
        self._binary = path
        return path

    def is_installed(self) -> bool:
        return self.binary_path.exists()

    def get_version(self) -> Optional[str]:
        if not self.is_installed():
            return None
        try:
            result = subprocess.run(
                [str(self.binary_path), "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
            for line in output.splitlines():
                if "Xray" in line:
                    return line.strip()
            return output.strip()[:100]
        except Exception as exc:
            logger.error("Version check failed: %s", exc)
            return None

    def _platform_asset(self, assets: list[dict]) -> Optional[str]:
        system = platform.system().lower()
        machine = platform.machine().lower()
        arch_map = {"x86_64": "64", "amd64": "64", "aarch64": "arm64-v8a", "arm64": "arm64-v8a"}
        arch = arch_map.get(machine, "64")
        if system == "windows":
            pattern = f"windows-{arch}.zip"
        elif system == "darwin":
            pattern = f"macos-{arch}.zip" if "arm" in arch else "macos-64.zip"
        else:
            pattern = f"linux-{arch}.zip"
        for asset in assets:
            name = asset.get("name", "").lower()
            if pattern.replace("-64", "") in name or pattern in name:
                return asset.get("browser_download_url")
        for asset in assets:
            name = asset.get("name", "").lower()
            if system in name and name.endswith(".zip"):
                return asset.get("browser_download_url")
        return None

    async def download_latest(self, progress_callback=None) -> bool:
        headers = {
            "User-Agent": "XrayConfigAnalyzerPro/1.0",
            "Accept": "application/vnd.github+json",
        }
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(120.0, connect=30.0),
                follow_redirects=True,
                headers=headers,
            ) as client:
                response = await client.get(GITHUB_RELEASES)
                response.raise_for_status()
                release = response.json()
                assets = release.get("assets", [])
                url = self._platform_asset(assets)
                if not url:
                    logger.error("No matching xray release asset found")
                    return False
                if progress_callback:
                    progress_callback("Downloading Xray-core...")
                dl_response = await client.get(url)
                dl_response.raise_for_status()
                if not dl_response.content:
                    logger.error("Downloaded file is empty")
                    return False
            zip_path = self.install_dir / "xray.zip"
            zip_path.write_bytes(dl_response.content)
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(self.install_dir)
            zip_path.unlink(missing_ok=True)
            if not self.is_installed():
                system = platform.system().lower()
                name = "xray.exe" if system == "windows" else "xray"
                for candidate in self.install_dir.rglob(name):
                    if candidate.is_file():
                        shutil.copy2(candidate, self.binary_path)
                        break
            if platform.system().lower() != "windows" and self.binary_path.exists():
                os.chmod(self.binary_path, 0o755)
            if progress_callback:
                progress_callback("Xray-core installed successfully")
            return self.is_installed()
        except httpx.HTTPStatusError as exc:
            logger.error("Xray download HTTP error: %s %s", exc.response.status_code, exc.request.url)
            return False
        except Exception as exc:
            logger.error("Xray download failed: %s", exc)
            return False

    def build_temp_config(
        self,
        outbound: dict,
        inbound_port: int = 10808,
        listen_host: str = DEFAULT_LOOPBACK,
    ) -> dict:
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "listen": listen_host,
                    "port": inbound_port,
                    "protocol": "socks",
                    "settings": {"udp": True, "auth": "noauth"},
                    "tag": "socks-in",
                }
            ],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {
                "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": outbound.get("tag", "proxy")}]
            },
        }

    def write_config(self, config: dict, path: Path) -> None:
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def validate_config_file(self, config_path: Path, timeout: int = 12) -> tuple:
        from backend.models import TestStatus

        if not self.is_installed():
            return TestStatus.SKIPPED, "Xray-core not installed"
        try:
            proc = subprocess.run(
                [str(self.binary_path), "run", "-test", "-c", str(config_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            log = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode == 0:
                return TestStatus.VALID, log[:500] or "Config accepted by xray -test"
            return TestStatus.INVALID, log[:800] or f"xray -test exit {proc.returncode}"
        except subprocess.TimeoutExpired:
            return TestStatus.INVALID, "Config validation timed out"
        except Exception as exc:
            return TestStatus.INVALID, str(exc)[:200]

    def run_test(self, config_path: Path, timeout: int = 15) -> tuple[int, str, str]:
        """Run xray briefly; timeout or non-zero exit = failure."""
        if not self.is_installed():
            return -1, "", "Xray-core not installed"
        proc = subprocess.Popen(
            [str(self.binary_path), "run", "-c", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            code = proc.returncode if proc.returncode is not None else 1
            return code, stdout, stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return -2, stdout, (stderr or "") + "\n[Timed out — treated as failed startup test]"
        except Exception as exc:
            return -1, "", str(exc)

    def start_background(
        self,
        config_path: Path,
        *,
        socks_host: str = DEFAULT_LOOPBACK,
        socks_port: int,
    ) -> XrayBackgroundRun:
        proc = subprocess.Popen(
            [str(self.binary_path), "run", "-c", str(config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        run = XrayBackgroundRun(
            proc=proc,
            config_path=config_path,
            socks_host=socks_host,
            socks_port=socks_port,
        )
        run.start_log_reader()
        return run

    async def wait_ready(
        self,
        run: XrayBackgroundRun,
        *,
        deadline_sec: float = 20.0,
        poll_interval: float = 0.25,
    ) -> tuple[bool, str]:
        """Wait until process alive and SOCKS port accepts connections."""
        deadline = time.monotonic() + deadline_sec
        while time.monotonic() < deadline:
            code = run.poll_exit()
            if code is not None:
                return False, f"Xray exited early (code {code})"
            if is_port_listening(run.socks_host, run.socks_port):
                return True, "SOCKS listener ready"
            await asyncio_sleep(poll_interval)
        if run.is_alive() and is_port_listening(run.socks_host, run.socks_port):
            return True, "SOCKS listener ready (deadline edge)"
        return False, "Timeout waiting for SOCKS readiness"

    @staticmethod
    def stop_run(run: Optional[XrayBackgroundRun]) -> None:
        if run:
            run.stop()


# Avoid importing asyncio at module top for sync contexts
async def asyncio_sleep(seconds: float) -> None:
    import asyncio

    await asyncio.sleep(seconds)

