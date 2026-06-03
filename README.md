# Xray Config Analyzer Pro

Professional desktop application for analyzing Xray/V2Ray proxy configurations with a modern CustomTkinter GUI.

![Python](https://img.shields.io/badge/Python-3.12+-blue)
![License](https://img.shields.io/badge/License-MIT-green)

**Developer:** Qashqaeii · **Telegram:** [@Hypertunneladmin](https://t.me/Hypertunneladmin)

## Features

- **Multi-Protocol Support**: VLESS, VMESS, Trojan, Shadowsocks, Hysteria2, TUIC
- **Share Link & JSON Parsing**: Paste links, import files, or fetch subscription URLs
- **DNS Analysis**: A/AAAA/CNAME records, TTL, reverse DNS, all resolved IPs
- **Network Intelligence**: ASN, ISP, organization, geolocation, CDN detection
- **Connectivity Tests**: DNS resolve, TCP connect, TLS handshake, WebSocket upgrade, HTTP response, latency, packet loss
- **TLS Analysis**: Certificate details, cipher suites, expiry, fingerprint
- **Xray-Core Integration**: Auto-download and test configs with real Xray binary
- **Deployment Detection**: Heuristic analysis (Direct VPS, CDN Fronted, Cloudflare, Arvan, Reverse Proxy, etc.)
- **Security Scoring**: 0–100 score with detailed findings
- **Reproduction Guide**: What can/cannot be reconstructed from config
- **Export**: JSON, CSV, Markdown, HTML, PDF

## Requirements

- Python 3.12+
- Windows / macOS / Linux

## Installation

```bash
# Clone or extract the project
cd XrayBOMB

# Create virtual environment (recommended)
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

```bash
python main.py
```

### Quick Start

1. **Paste a config link** (e.g. `vless://...`) in the left panel
2. Click **Analyze Config**
3. Browse results across 9 tabs: Overview, Protocol, DNS, Network, TLS, Xray Test, Security, Reproduction, Raw Data
4. Use **Download Xray** to enable live config testing
5. **Export** results in your preferred format

### Supported Input Formats

| Format | Example |
|--------|---------|
| VLESS | `vless://uuid@host:443?...` |
| VMESS | `vmess://base64...` |
| Trojan | `trojan://password@host:443?...` |
| Shadowsocks | `ss://method:pass@host:port` |
| Hysteria2 | `hysteria2://pass@host:443?...` |
| TUIC | `tuic://uuid:pass@host:443?...` |
| JSON Config | Full Xray/V2Ray JSON |
| Subscription | HTTP(S) subscription URL |

## Project Structure

```
XrayBOMB/
├── main.py                 # Entry point
├── requirements.txt
├── README.md
├── backend/                # Core analysis engine
│   ├── models.py           # Pydantic data models
│   ├── config_parser.py    # Share link & JSON parser
│   ├── analyzer.py         # Main orchestrator
│   └── security.py         # Security & deployment analysis
├── dns_analyzer/           # DNS resolution module
├── network/                # Connectivity & CDN detection
├── tls/                    # TLS certificate analysis
├── xray/                   # Xray-core integration
├── gui/                    # CustomTkinter interface
│   ├── app.py              # Main window
│   ├── components/         # Sidebar, status, log panels
│   └── tabs/               # Analysis tab views
├── database/               # SQLite history
├── reports/                # Export formats
└── utils/                  # Logging & helpers
```

## GUI Layout

```
┌─────────────────────────────────────────────────────────────┐
│  ⚡ Xray Config Analyzer Pro       [Download Xray] [Export] │
├──────────┬─────────────────────────────────┬────────────────┤
│ Config   │  [Overview|Protocol|DNS|...]    │ Status Panel   │
│ Input    │                                 │ Connection ●   │
│          │  Analysis Results               │ DNS        ●   │
│ [Paste]  │                                 │ TLS        ●   │
│ [Import] │                                 │ Xray Test  ●   │
│ [Sub URL]│                                 │ Score: 92/100  │
│          │                                 │                │
│ [Analyze]│                                 │                │
├──────────┴─────────────────────────────────┴────────────────┤
│ Live Log: [12:00:01] Starting analysis...                    │
└─────────────────────────────────────────────────────────────┘
```

## Important Notes

- **No fabricated data**: When information cannot be inferred from the config, the app explicitly states: *"این اطلاعات از روی کانفیگ قابل استنتاج قطعی نیست."*
- **Non-blocking UI**: All network/analysis operations run in background threads
- **Xray-core**: Downloaded to `~/.xray_analyzer/xray/` on first use
- **History**: Analysis results saved to `~/.xray_analyzer/history.db`

## CDN Detection

The app detects these CDNs heuristically:

- Cloudflare
- ArvanCloud
- Akamai
- Fastly
- CloudFront (AWS)
- Bunny CDN
- Gcore

## GitHub release (Windows executable)

The project ships a **ZIP in `release/`** with the standalone GUI (no Python install required for end users).

```powershell
pip install -r requirements.txt
python scripts\build_release.py
```

Output: `release/XrayConfigAnalyzerPro-Windows-x64.zip` → unzip → run `XrayConfigAnalyzerPro\XrayConfigAnalyzerPro.exe`.

To publish on GitHub: push a version tag (e.g. `git tag v2.0.1 && git push origin v2.0.1`). The workflow in `.github/workflows/release.yml` builds the same ZIP and attaches it to the GitHub Release.

Proxy tunnel tests include **YouTube** and **Instagram** reachability checks.

## License

MIT License — free for personal and commercial use.
