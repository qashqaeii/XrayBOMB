#!/usr/bin/env python3
"""Build Windows release ZIP with the GUI executable for GitHub deploy."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "XrayConfigAnalyzerPro.spec"
DIST_DIR = ROOT / "dist" / "XrayConfigAnalyzerPro"
RELEASE_DIR = ROOT / "release"
ZIP_NAME = "XrayConfigAnalyzerPro-Windows-x64.zip"


def _run_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print("Installing PyInstaller...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller>=6.11.0", "pydantic>=2.6.0"])

    subprocess.check_call(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            str(SPEC),
        ],
        cwd=ROOT,
    )


def _make_zip() -> Path:
    if not DIST_DIR.is_dir():
        raise FileNotFoundError(f"Build output not found: {DIST_DIR}")

    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = RELEASE_DIR / ZIP_NAME
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(DIST_DIR.rglob("*")):
            if path.is_file():
                arcname = Path("XrayConfigAnalyzerPro") / path.relative_to(DIST_DIR)
                zf.write(path, arcname.as_posix())

    exe = DIST_DIR / "XrayConfigAnalyzerPro.exe"
    if not exe.is_file():
        raise FileNotFoundError(f"Executable missing after build: {exe}")

    return zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Build release ZIP for GitHub")
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Only repackage dist/ into release/ (PyInstaller already ran)",
    )
    args = parser.parse_args()

    if sys.platform != "win32":
        print("Warning: this script targets Windows; output may not run on other OS.")

    if not args.skip_build:
        _run_pyinstaller()

    zip_path = _make_zip()
    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"Release ready: {zip_path} ({size_mb:.1f} MB)")
    print("Run: release\\XrayConfigAnalyzerPro\\XrayConfigAnalyzerPro.exe (after unzip)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
