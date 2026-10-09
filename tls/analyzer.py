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


def _hostname_matches_cert(hostname: str, cert_dict: dict) -> bool:
    """Match hostname against SAN/CN with basic wildcard support."""
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    sans = []
    for subj in cert_dict.get("subjectAltName", ()) or ():
        if subj[0] == "DNS":
            sans.append(subj[1].lower())
    if host in sans:
        return True
    for pattern in sans:
        if pattern.startswith("*.") and host.endswith(pattern[1:]):
            return True
    for tup in cert_dict.get("subject", ()) or ():
        for k, v in tup:
            if k == "commonName":
                cn = v.lower()
                if cn == host or (cn.startswith("*.") and host.endswith(cn[1:])):
                    return True
    return False


def _analyze_cert_sync(host: str, port: int, sni: Optional[str], *, verify_chain: bool) -> TLSAnalysis:
    sni = sni or host
    result = TLSAnalysis(
        enabled=True,
        tls_configured=True,
        sni_used=sni,
        collection_mode="verified" if verify_chain else "unverified_probe",
    )

    try:
        ctx = ssl.create_default_context()
        if verify_chain:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                result.handshake_observed = True
                result.version = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    result.cipher_suite = cipher[0]
                    cipher_name = cipher[0].upper()
                    result.weak_cipher = any(w in cipher_name for w in WEAK_CIPHERS)

                try:
                    alpn = ssock.selected_alpn_protocol()
                    result.alpn_protocols = [alpn] if alpn else []
                except Exception:
                    result.alpn_protocols = []

                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                if cert_dict:
                    result.hostname_matched = _hostname_matches_cert(sni, cert_dict)
                result.chain_trusted = verify_chain

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
        result.handshake_observed = False
    except Exception as exc:
        result.errors.append(f"TLS analysis failed: {exc}")
        result.handshake_observed = False

    return result


async def analyze_tls(
    config: ParsedConfig,
    connect_host: Optional[str] = None,
    *,
    tls_sni: Optional[str] = None,
) -> TLSAnalysis:
    tls_on = bool(config.tls or config.reality or (config.security or "").lower() in ("tls", "reality", "xtls"))
    if not tls_on and (config.port or 0) != 443:
        return TLSAnalysis(enabled=False, tls_configured=False)

    host = connect_host or config.address
    port = config.port or 443
    sni = tls_sni or config.sni or config.host or config.address

    loop = asyncio.get_event_loop()
    probe = await loop.run_in_executor(None, _analyze_cert_sync, host, port, sni, False)
    probe.tls_configured = bool(config.tls or config.reality or (config.security or "").lower() in ("tls", "reality"))
    return probe
