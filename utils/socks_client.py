"""httpx clients via SOCKS — uses httpx-socks to avoid socksio bytearray bug."""

from __future__ import annotations

from typing import Optional

import httpx
from httpx_socks import AsyncProxyTransport

DEFAULT_TIMEOUT = 25.0


def socks_proxy_url(port: int, host: str = "127.0.0.1") -> str:
    return f"socks5://{host}:{port}"


def make_async_socks_client(
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify: bool = False,
) -> httpx.AsyncClient:
    """Async httpx client through local SOCKS5 (httpx built-in proxy has a socksio bug)."""
    transport = AsyncProxyTransport.from_url(socks_proxy_url(port))
    return httpx.AsyncClient(transport=transport, timeout=timeout, verify=verify)
