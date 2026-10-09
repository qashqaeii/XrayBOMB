"""SOCKS5 handshake verification (auth + CONNECT probe) — no HTTP."""

from __future__ import annotations

import socket
import struct
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
    connect_target: tuple[str, int] = ("198.18.0.1", 80),
) -> tuple[bool, str]:
    """
    Perform SOCKS5 greeting, username/password auth, and a minimal CONNECT.
    Fails if credentials wrong or listener is not our authenticated SOCKS.
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
                return False, f"Bad SOCKS version {resp[0]}"
            if resp[1] != 0x02:
                return False, f"Server did not select username auth (method={resp[1]})"
            auth_req = b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p
            sock.sendall(auth_req)
            auth_resp = _recv_exact(sock, 2)
            if auth_resp[1] != 0x00:
                return False, "SOCKS username/password rejected"
            dst_host, dst_port = connect_target
            host_b = dst_host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", dst_port)
            sock.sendall(req)
            hdr = _recv_exact(sock, 4)
            if hdr[1] != 0x00:
                return False, f"SOCKS CONNECT failed (rep={hdr[1]})"
            atyp = hdr[3]
            if atyp == 0x01:
                _recv_exact(sock, 4 + 2)
            elif atyp == 0x03:
                ln = _recv_exact(sock, 1)[0]
                _recv_exact(sock, ln + 2)
            elif atyp == 0x04:
                _recv_exact(sock, 16 + 2)
            return True, "SOCKS5 auth + CONNECT OK"
    except Exception as exc:
        return False, str(exc)[:200]


def pid_listening_on_port(pid: int, port: int, host: str = "127.0.0.1") -> Optional[bool]:
    """Return True/False if psutil can confirm PID owns the TCP listener; None if unknown."""
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
    except (PermissionError, OSError):
        return None
