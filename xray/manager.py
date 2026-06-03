"""Xray-core download and process management."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)

GITHUB_RELEASES = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"


class XrayManager:
    """Manage Xray-core binary lifecycle."""

    def __init__(self, install_dir: Optional[Path] = None) -> None:
        self.install_dir = install_dir or Path.home() / ".xray_analyzer" / "xray"
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self._binary: Optional[Path] = None

    @property
    def binary_path(self) -> Path:
        """Return path to xray binary."""
        if self._binary and self._binary.exists():
            return self._binary
        system = platform.system().lower()
        name = "xray.exe" if system == "windows" else "xray"
        path = self.install_dir / name
        self._binary = path
        return path

    def is_installed(self) -> bool:
        """Check if xray binary exists."""
        return self.binary_path.exists()

    def get_version(self) -> Optional[str]:
        """Get installed xray version."""
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
        """Find matching release asset URL."""
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
        # Fallback: any zip for platform
        for asset in assets:
            name = asset.get("name", "").lower()
            if system in name and name.endswith(".zip"):
                return asset.get("browser_download_url")
        return None

    async def download_latest(self, progress_callback=None) -> bool:
        """Download latest Xray-core release."""
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

            # Binary may be at root or in a subfolder inside the zip
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

    def build_temp_config(self, outbound: dict, inbound_port: int = 10808) -> dict:
        """Build minimal xray config for testing."""
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": inbound_port,
                    "protocol": "socks",
                    "settings": {"udp": True},
                    "tag": "socks-in",
                }
            ],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {
                "rules": [{"type": "field", "inboundTag": ["socks-in"], "outboundTag": outbound.get("tag", "proxy")}]
            },
        }

    def write_config(self, config: dict, path: Path) -> None:
        """Write config to file."""
        path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    def run_test(self, config_path: Path, timeout: int = 15) -> tuple[int, str, str]:
        """Run xray with config and capture output."""
        if not self.is_installed():
            return -1, "", "Xray-core not installed"

        try:
            proc = subprocess.Popen(
                [str(self.binary_path), "run", "-c", str(config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
                return 0, stdout, stderr + "\n[Process terminated after timeout - likely running OK]"
            return proc.returncode or 0, stdout, stderr
        except Exception as exc:
            return -1, "", str(exc)

    def start_background(self, config_path: Path) -> subprocess.Popen:
        """Start xray in background for proxy testing."""
        return subprocess.Popen(
            [str(self.binary_path), "run", "-c", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    @staticmethod
    def stop_process(proc: subprocess.Popen) -> None:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
