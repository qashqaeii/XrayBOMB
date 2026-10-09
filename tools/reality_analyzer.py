"""REALITY settings analyzer from share link or JSON snippet."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from backend.config_parser import parse_input


async def analyze_reality_config(
    text: str,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    text = text.strip()
    if not text:
        return "Paste a VLESS REALITY share link or JSON outbound."

    if progress:
        progress("Parsing config...")
    configs = parse_input(text)
    if not configs:
        return "Could not parse config — paste vless:// or JSON outbound."

    c = configs[0]
    lines = [
        "REALITY Analyzer",
        "═" * 58,
        "",
        f"  Protocol  : {c.protocol.value if c.protocol else '—'}",
        f"  Address   : {c.address}:{c.port}",
        f"  Transport : {c.transport_type.value if c.transport_type else '—'}",
        "",
    ]

    if not c.reality:
        lines.extend([
            "── Status ──",
            "  security ≠ reality — this config is not REALITY.",
            f"  TLS enabled: {c.tls}",
            f"  security   : {c.security or 'none'}",
        ])
        if c.tls:
            lines.extend([
                "",
                "── TLS fields ──",
                f"  SNI        : {c.sni or '—'}",
                f"  ALPN       : {c.alpn or '—'}",
                f"  Fingerprint: {c.fingerprint or '—'}",
            ])
        return "\n".join(lines)

    lines.extend([
        "── REALITY parameters ──",
        f"  SNI (dest)     : {c.sni or '—'}",
        f"  Public Key     : {c.public_key or '—'}",
        f"  Short ID       : {c.short_id or '—'}",
        f"  Fingerprint    : {c.fingerprint or 'chrome (default)'}",
        f"  Flow           : {c.flow or '—'}",
        f"  Host header    : {c.host or '—'}",
        f"  Path           : {c.path or '—'}",
        "",
        "── Checklist ──",
    ])

    checks = []
    if c.public_key:
        checks.append("  ✓ Public key (pbk) present")
    else:
        checks.append("  ✗ Missing public key — REALITY will not work")

    if c.short_id:
        checks.append(f"  ✓ Short ID: {c.short_id}")
    else:
        checks.append("  ⚠ No short ID — server may accept empty sid only")

    if c.sni:
        checks.append(f"  ✓ SNI set to {c.sni} — must match dest site cert")
    else:
        checks.append("  ✗ SNI missing — required for REALITY camouflage")

    fp = (c.fingerprint or "chrome").lower()
    checks.append(f"  • Client fingerprint: {fp} (must match uTLS on client)")

    lines.extend(checks)
    lines.extend([
        "",
        "── Server-side hints ──",
        "  dest = SNI:443 with valid cert from that site",
        "  serverNames must include SNI; privateKey matches pbk",
        "  shortIds must include sid (or empty if omitted)",
        "",
        "  Test TLS to SNI: run TLS Intelligence on the SNI domain.",
    ])
    return "\n".join(lines)


def analyze_reality_config_sync(**kwargs) -> str:
    return asyncio.run(analyze_reality_config(**kwargs))
