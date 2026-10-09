"""TLS fingerprint and certificate intelligence."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from tls.analyzer import _analyze_cert_sync
from utils.helpers import is_ip_address


async def scan_tls_target(
    host: str,
    port: int = 443,
    sni: Optional[str] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    host = host.strip()
    if not host:
        return "Enter hostname or IP."

    connect_host = host
    sni_used = sni or (None if is_ip_address(host) else host)

    if progress:
        progress(f"TLS handshake {connect_host}:{port}...")

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _analyze_cert_sync, connect_host, port, sni_used)

    lines = [
        "TLS Intelligence Scanner",
        "═" * 58,
        "",
        f"  Host : {host}:{port}",
        f"  SNI  : {result.sni_used or '—'}",
        "",
        "── Handshake ──",
        f"  TLS version  : {result.version or '—'}",
        f"  Cipher suite : {result.cipher_suite or '—'}",
        f"  Weak cipher  : {'yes' if result.weak_cipher else 'no'}",
        f"  ALPN         : {', '.join(result.alpn_protocols) if result.alpn_protocols else 'none'}",
        "",
        "── Certificate ──",
        f"  Subject      : {result.certificate_subject or '—'}",
        f"  Issuer (CA)  : {result.certificate_issuer or '—'}",
        f"  Expiry       : {result.certificate_expiry or '—'}",
        f"  Days left    : {result.days_until_expiry if result.days_until_expiry is not None else '—'}",
        f"  Expired      : {'yes' if result.certificate_expired else 'no'}",
        f"  SHA256 FP    : {result.fingerprint_sha256 or '—'}",
    ]

    if result.errors:
        lines.extend(["", "── Errors ──"])
        for e in result.errors:
            lines.append(f"  • {e}")

    lines.extend([
        "",
        "  Note: JA3/browser fingerprint requires packet capture — not available here.",
        "  For Xray REALITY, compare SNI cert with front domain in Reality Analyzer.",
    ])
    return "\n".join(lines)


def scan_tls_target_sync(**kwargs) -> str:
    return asyncio.run(scan_tls_target(**kwargs))
