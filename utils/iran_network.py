"""Iranian operator ASN/ISP identity — shared by geo and operator tools."""

from __future__ import annotations

import re
from typing import Optional

# Primary mobile operators — ASN is authoritative (who owns the IP block).
IRAN_ASN_MAP: dict[str, tuple[str, str]] = {
    "AS197207": ("MCI", "همراه اول (MCI)"),
    "AS196874": ("MCI", "همراه اول (MCI)"),
    "AS44244": ("Irancell", "ایرانسل"),
    "AS57218": ("Irancell", "ایرانسل"),
    "AS60330": ("Irancell", "ایرانسل"),
    "AS57235": ("Rightel", "رایتل"),
    "AS25184": ("Rightel", "رایتل"),
    "AS16322": ("Mokhaberat", "مخابرات / تلفن ثابت"),
    "AS12880": ("ITC/TIC", "شرکت ارتباطات زیرساخت (تزریق ترانزیت)"),
}

ISP_KEYWORDS: tuple[tuple[str, str, str], ...] = (
    ("irancell", "Irancell", "ایرانسل"),
    ("mtn", "Irancell", "ایرانسل"),
    ("iran cell", "Irancell", "ایرانسل"),
    ("hamrah", "MCI", "همراه اول"),
    ("mci", "MCI", "همراه اول"),
    ("mobile communication company", "MCI", "همراه اول"),
    ("rightel", "Rightel", "رایتل"),
    ("mokhaberat", "Mokhaberat", "مخابرات"),
    ("telecommunication company", "Mokhaberat", "مخابرات"),
)


def normalize_asn(asn_raw: Optional[str]) -> Optional[str]:
    if not asn_raw:
        return None
    m = re.search(r"AS\d+", str(asn_raw).upper())
    return m.group(0) if m else None


def is_iranian_network_identity(
    *,
    asn: Optional[str] = None,
    isp: Optional[str] = None,
    organization: Optional[str] = None,
) -> bool:
    """True when ASN/ISP clearly belongs to an Iranian operator (any geo label)."""
    asn_norm = normalize_asn(asn)
    if asn_norm and asn_norm in IRAN_ASN_MAP:
        return True
    blob = " ".join(filter(None, [isp, organization])).lower()
    return any(keyword in blob for keyword, _, _ in ISP_KEYWORDS)
