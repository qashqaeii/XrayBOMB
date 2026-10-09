"""Operator comparison — run Multi-Region Ping from your current ISP."""

from __future__ import annotations

import asyncio
from typing import Callable, Optional

from network.geo import lookup_geo_ip
from tools.multi_region_ping import REGION_TARGETS, build_ping_matrix


# Reference ASN map — not live per-operator; user must test from each SIM/ISP
ISP_ASN_REF = {
    "MCI (Hamrah-e Aval)": "AS197207",
    "Irancell": "AS44244",
    "Rightel": "AS57235",
    "Shatel": "AS31549",
    "Mokhaberat": "AS16322",
    "Asiatech": "AS25184",
    "Pars Online": "AS16322",
    "HiWEB": "AS56402",
}


async def build_operator_comparison(
    progress: Optional[Callable[[str], None]] = None,
) -> str:
    geo = await lookup_geo_ip()
    asn = (geo or {}).get("asn", "—")
    isp = (geo or {}).get("isp", "—")

    lines = [
        "Operator Comparison Lab",
        "═" * 58,
        "",
        "  Measures YOUR current connection only.",
        "  To compare MCI vs Irancell — repeat test on each operator's network.",
        "",
        f"  Current ISP : {isp}",
        f"  Current ASN : {asn}",
        "",
        "── ASN reference (Iran operators) ──",
        f"  {'Operator':<22} {'Primary ASN'}",
        "  " + "─" * 36,
    ]
    for name, ref_asn in ISP_ASN_REF.items():
        marker = " ← you" if ref_asn in str(asn) else ""
        lines.append(f"  {name:<22} {ref_asn}{marker}")

    lines.extend(["", "── Live EU route matrix (your ISP) ──", ""])
    matrix = await build_ping_matrix(samples=4, progress=progress)
    # Skip duplicate header from matrix
    matrix_lines = matrix.splitlines()[4:]
    lines.extend(matrix_lines)

    lines.extend([
        "",
        "── How to compare operators ──",
        "  1. Run this tool on MCI SIM → note Frankfurt avg ms",
        "  2. Repeat on Irancell / Shatel / ADSL",
        "  3. Pick DC region matching lowest avg for your buyers",
        "",
        "  No simulated RTT — table above is live from this session.",
    ])
    return "\n".join(lines)


def build_operator_comparison_sync(**kwargs) -> str:
    return asyncio.run(build_operator_comparison(**kwargs))
