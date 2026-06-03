# Release package (GitHub deploy)

This folder holds the **Windows distributable ZIP** for end users who do not install Python.

## Contents

| File | Description |
|------|-------------|
| `XrayConfigAnalyzerPro-Windows-x64.zip` | Archive containing `XrayConfigAnalyzerPro/XrayConfigAnalyzerPro.exe` and dependencies |

## Build locally (Windows)

```powershell
cd XrayBOMB
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
python scripts\build_release.py
```

After a successful build, unzip and run:

```text
XrayConfigAnalyzerPro\XrayConfigAnalyzerPro.exe
```

## GitHub Actions

Push a tag `v*` (e.g. `v2.0.1`) to trigger `.github/workflows/release.yml`, which builds the same ZIP and attaches it to a GitHub Release.

## Site tests in proxy diagnostics

Tunnel tests include **YouTube** and **Instagram** in addition to Google, Telegram, and Cloudflare trace.
