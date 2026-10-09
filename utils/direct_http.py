"""HTTP clients that never inherit system proxy / VPN env."""

from __future__ import annotations

import httpx

DIRECT_CLIENT_KW = {
    "timeout": 12.0,
    "trust_env": False,
    "follow_redirects": True,
}


def make_direct_async_client(**overrides) -> httpx.AsyncClient:
    kw = {**DIRECT_CLIENT_KW, **overrides}
    return httpx.AsyncClient(**kw)
