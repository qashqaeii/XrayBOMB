"""TLS certificate and cipher analysis."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from backend.models import ParsedConfig, TLSAnalysis
from utils.logger import get_logger

logger = get_logger(__name__)

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "anon",
}


def _analyze_cert_sync(host: str, port: int, sni: Optional[str]) -> TLSAnalysis:
    """Synchronous TLS certificate analysis."""
    result = TLSAnalysis(enabled=True, sni_used=sni or host)
    sni = sni or host

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                result.version = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result.cipher_suite = cipher[0]
                    cipher_name = cipher[0].upper()
                    result.weak_cipher = any(w in cipher_name for w in WEAK_CIPHERS)

                try:
                    result.alpn_protocols = ssock.selected_alpn_protocol() or ""
                    if result.alpn_protocols:
                        result.alpn_protocols = [result.alpn_protocols]
                    else:
                        result.alpn_protocols = []
                except Exception:
                    result.alpn_protocols = []

                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    from cryptography.hazmat.primitives import hashes

                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    result.certificate_subject = cert.subject.rfc4514_string()
                    result.certificate_issuer = cert.issuer.rfc4514_string()
                    result.certificate_expiry = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    delta = result.certificate_expiry - now
                    result.days_until_expiry = delta.days
                    result.certificate_expired = delta.days < 0
                    result.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex(":").upper()

    except ssl.SSLError as exc:
        result.errors.append(f"SSL error: {exc}")
        result.enabled = False
    except Exception as exc:
        result.errors.append(f"TLS analysis failed: {exc}")
        result.enabled = False

    return result


async def analyze_tls(config: ParsedConfig, connect_host: Optional[str] = None) -> TLSAnalysis:
    """Analyze TLS for a config."""
    if not config.tls and not config.reality and config.port != 443:
        return TLSAnalysis(enabled=False)

    host = connect_host or config.address
    port = config.port or 443
    sni = config.sni or config.host or config.address

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _analyze_cert_sync, host, port, sni)
