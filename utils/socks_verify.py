"""SOCKS5 readiness check (greeting + username/password auth only — no CONNECT)."""

from __future__ import annotations

import socket
from typing import Optional


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("Unexpected EOF during SOCKS handshake")
        buf += chunk
    return buf


def verify_socks5_username_auth(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    timeout: float = 5.0,
) -> tuple[bool, str]:
    """
    SOCKS5 method negotiation (RFC 1928) and username/password auth (RFC 1929).
    Does not CONNECT to any remote target — readiness only.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            u = username.encode("utf-8")
            p = password.encode("utf-8")
            if len(u) > 255 or len(p) > 255:
                return False, "Credentials too long for SOCKS5"
            sock.sendall(b"\x05\x01\x02")
            resp = _recv_exact(sock, 2)
            if resp[0] != 0x05:
                return False, f"SOCKS greeting failed: version={resp[0]} (expected 5)"
            if resp[1] != 0x02:
                return False, f"SOCKS greeting failed: method={resp[1]} (expected username/password 2)"
            auth_req = b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p
            sock.sendall(auth_req)
            auth_resp = _recv_exact(sock, 2)
            if auth_resp[0] != 0x01:
                return False, f"SOCKS auth subnegotiation version={auth_resp[0]} (expected 1)"
            if auth_resp[1] != 0x00:
                return False, f"SOCKS username/password rejected (status={auth_resp[1]})"
            return True, "SOCKS5 greeting + username/password auth OK (no CONNECT performed)"
    except Exception as exc:
        return False, str(exc)[:200]


def pid_listening_on_port(pid: int, port: int, host: str = "127.0.0.1") -> Optional[bool]:
    """True/False if PID owns listener; None if ownership cannot be observed."""
    try:
        import psutil
    except ImportError:
        return None
    try:
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != psutil.CONN_LISTEN:
                continue
            if conn.laddr and conn.laddr.port == port and conn.pid == pid:
                if host in ("127.0.0.1", "0.0.0.0", "::1", "") or conn.laddr.ip in (host, "0.0.0.0", "::"):
                    return True
        return False
    except PermissionError:
        return None
    except Exception as exc:
        if exc.__class__.__name__ == "AccessDenied":
            return None
        return None
