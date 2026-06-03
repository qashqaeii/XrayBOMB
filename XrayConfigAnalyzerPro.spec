# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — run via: python scripts/build_release.py"""

import sys
from pathlib import Path

block_cipher = None
root = Path(SPECPATH)

a = Analysis(
    [str(root / "main.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[
        (str(root / "plugins"), "plugins"),
    ],
    hiddenimports=[
        "customtkinter",
        "PIL",
        "PIL._tkinter_finder",
        "dns",
        "dns.asyncresolver",
        "httpx",
        "httpx_socks",
        "socksio",
        "pydantic",
        "reportlab",
        "reportlab.pdfbase",
        "reportlab.pdfbase.ttfonts",
        "rich",
        "psutil",
        "qrcode",
        "ipwhois",
        "cryptography",
        "websocket",
    ],
    hookspath=[str(root / "build" / "hooks")],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "matplotlib",
        "IPython",
        "jupyter",
        "notebook",
        "pytest",
        "tkinter.test",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="XrayConfigAnalyzerPro",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="XrayConfigAnalyzerPro",
)
