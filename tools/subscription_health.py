"""Subscription link health check — expanded protocol and node analysis."""



from __future__ import annotations



import asyncio

from collections import Counter

from typing import Callable, Optional

from urllib.parse import urlparse



from backend.config_parser import fetch_subscription





async def check_subscription_async(

    url: str,

    progress: Optional[Callable[[str], None]] = None,

) -> str:

    url = url.strip()

    if not url:

        return "Enter a subscription URL (http/https)."

    if not url.startswith(("http://", "https://")):

        return "URL must start with http:// or https://"



    if progress:

        progress("Fetching subscription...")

    try:

        configs = await fetch_subscription(url)

    except Exception as exc:

        url_line = f"{url[:80]}..." if len(url) > 80 else url

        return (

            "Subscription Health — FAILED\n"

            + "═" * 58 + "\n\n"

            f"  URL    : {url_line}\n"

            f"  Error  : {exc}\n"

        )



    protos: Counter[str] = Counter()

    transports: Counter[str] = Counter()

    ports: Counter[int] = Counter()

    addrs: set[str] = set()

    tls_count = reality_count = ws_count = grpc_count = 0



    for c in configs:

        p = c.protocol.value if hasattr(c.protocol, "value") else str(c.protocol)

        protos[p] += 1

        if c.address:

            addrs.add(c.address)

        if c.port:

            ports[c.port] += 1

        if c.tls:

            tls_count += 1

        if c.reality:

            reality_count += 1

        t = c.transport_type.value if hasattr(c.transport_type, "value") else str(c.transport_type)

        transports[t] += 1

        if "ws" in t.lower():

            ws_count += 1

        if "grpc" in t.lower():

            grpc_count += 1



    host = urlparse(url).netloc



    lines = [

        "Subscription Health",

        "═" * 58,

        "",

        f"  URL              : {url[:100]}{'...' if len(url) > 100 else ''}",

        f"  Panel host       : {host}",

        f"  Total configs    : {len(configs)}",

        f"  Unique addresses : {len(addrs)}",

        f"  TLS enabled      : {tls_count}",

        f"  REALITY          : {reality_count}",

        f"  WebSocket        : {ws_count}",

        f"  gRPC             : {grpc_count}",

        "",

        "── Protocol breakdown ──",

        f"  {'Protocol':<14} {'Count':>6}",

        "  " + "─" * 22,

    ]

    for p, n in protos.most_common():

        lines.append(f"  {p:<14} {n:>6}")



    lines.extend(["", "── Transport breakdown ──"])

    for t, n in transports.most_common():

        lines.append(f"  {t:<14} {n:>6}")



    lines.extend(["", "── Port distribution ──"])

    for port, n in ports.most_common(8):

        lines.append(f"  {port:<6} {n}")



    lines.extend(["", "── Unique hosts ──"])

    for addr in sorted(addrs)[:20]:

        lines.append(f"  {addr}")

    if len(addrs) > 20:

        lines.append(f"  ... +{len(addrs) - 20} more")



    lines.extend(["", "── Sample configs (first 10) ──"])

    for c in configs[:10]:

        tls = "TLS" if c.tls else "plain"

        rl = "+REALITY" if c.reality else ""

        tr = c.transport_type.value if hasattr(c.transport_type, "value") else "?"

        lines.append(f"  {c.protocol.value} {c.address}:{c.port} [{tls}{rl}] {tr}")



    lines.extend([

        "",

        "── Health summary ──",

        f"  REALITY ratio  : {reality_count}/{len(configs)} ({100*reality_count//max(len(configs),1)}%)",

        f"  TLS ratio      : {tls_count}/{len(configs)}",

        f"  Host diversity : {len(addrs)} unique IP/hostnames",

        "",

    ])

    return "\n".join(lines)





def check_subscription_sync(

    url: str,

    progress: Optional[Callable[[str], None]] = None,

) -> str:

    return asyncio.run(check_subscription_async(url, progress=progress))


