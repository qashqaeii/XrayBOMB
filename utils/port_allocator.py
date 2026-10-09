"""Pick candidate loopback ports (bind probe only — does not reserve the port)."""

from __future__ import annotations

import socket
from contextlib import closing

DEFAULT_LOOPBACK = "127.0.0.1"
PORT_MIN = 20000
PORT_MAX = 45000
MAX_ATTEMPTS = 40


def allocate_loopback_port(
    host: str = DEFAULT_LOOPBACK,
    *,
    min_port: int = PORT_MIN,
    max_port: int = PORT_MAX,
    max_attempts: int = MAX_ATTEMPTS,
) -> int:
    """Bind an ephemeral port on loopback; retries on collision."""
    import random

    tried: set[int] = set()
    for _ in range(max_attempts):
        port = random.randint(min_port, max_port)
        if port in tried:
            continue
        tried.add(port)
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"Could not allocate loopback port on {host} after {max_attempts} attempts")


def is_port_listening(host: str, port: int, timeout: float = 0.4) -> bool:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False
