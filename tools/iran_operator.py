"""Map Iranian ASN / ISP strings to mobile operator (MCI, Irancell, Rightel)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from utils.iran_network import (
    IRAN_ASN_MAP,
    ISP_KEYWORDS,
    is_iranian_network_identity,
    normalize_asn,
)


@dataclass(frozen=True)
class IranOperatorMatch:
    operator: str
    operator_fa: str
    confidence: str  # high | medium | low
    source: str  # asn | isp_keyword | unknown
    asn: Optional[str] = None


def resolve_iran_operator(
    *,
    country_code: str,
    asn: Optional[str] = None,
    isp: Optional[str] = None,
    organization: Optional[str] = None,
) -> Optional[IranOperatorMatch]:
    if country_code != "IR":
        return None

    asn_norm = normalize_asn(asn)
    if asn_norm and asn_norm in IRAN_ASN_MAP:
        op, op_fa = IRAN_ASN_MAP[asn_norm]
        return IranOperatorMatch(
            operator=op, operator_fa=op_fa, confidence="high", source="asn", asn=asn_norm,
        )

    blob = " ".join(filter(None, [isp, organization])).lower()
    for keyword, op, op_fa in ISP_KEYWORDS:
        if keyword in blob:
            return IranOperatorMatch(
                operator=op, operator_fa=op_fa, confidence="medium", source="isp_keyword", asn=asn_norm,
            )

    if asn_norm:
        return IranOperatorMatch(
            operator="Unknown IR",
            operator_fa="اپراتور نامشخص",
            confidence="low",
            source="asn",
            asn=asn_norm,
        )
    return None


def mismatch_hint(expected: str, detected: IranOperatorMatch) -> Optional[str]:
    """If user expects Irancell but ASN says MCI, return explanation."""
    exp = expected.strip().lower()
    det = detected.operator.lower()
    if "irancell" in exp and det == "mci":
        return (
            "شما ایرانسل انتخاب کرده‌اید، اما IP عمومی شما روی شبکه همراه اول (ASN MCI) است. "
            "این یعنی ترافیک واقعی از مسیر MCI خارج می‌شود — نه باگ برنامه."
        )
    if "mci" in exp and det == "irancell":
        return (
            "شما MCI انتخاب کرده‌اید، اما IP روی ایرانسل (ASN Irancell) است."
        )
    return None
