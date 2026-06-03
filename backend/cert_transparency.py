"""Certificate Transparency lookup via crt.sh."""

from __future__ import annotations

import httpx

from backend.models import CertTransparencyEntry, CertTransparencyResult
from utils.helpers import is_ip_address
from utils.logger import get_logger

logger = get_logger(__name__)


async def lookup_cert_transparency(domain: str, limit: int = 25) -> CertTransparencyResult:
    result = CertTransparencyResult(domain=domain)
    if is_ip_address(domain):
        result.errors.append("CT lookup requires a domain name, not IP")
        return result

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
            )
            if resp.status_code != 200:
                result.errors.append(f"crt.sh returned HTTP {resp.status_code}")
                return result
            data = resp.json()
            seen: set[str] = set()
            for entry in data[:limit * 3]:
                name = entry.get("name_value", "")
                issuer = entry.get("issuer_name", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and sub not in seen and domain in sub:
                        seen.add(sub)
                        result.entries.append(CertTransparencyEntry(subdomain=sub, issuer=issuer[:80] if issuer else None))
                        if len(result.entries) >= limit:
                            break
                if len(result.entries) >= limit:
                    break
            result.total_count = len(seen) if seen else len(data)
    except Exception as exc:
        logger.debug("CT lookup failed: %s", exc)
        result.errors.append(str(exc)[:200])
    return result
