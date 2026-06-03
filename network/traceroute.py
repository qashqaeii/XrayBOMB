"""Traceroute / hop count detection."""

from __future__ import annotations

import asyncio
import platform
import re
import subprocess
from typing import Optional

from backend.models import TracerouteHop, TracerouteResult
from utils.logger import get_logger

logger = get_logger(__name__)


def _parse_tracert_windows(output: str) -> list[TracerouteHop]:
    hops: list[TracerouteHop] = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)\s+(?:(\d+)\s+ms\s+)?(?:(\d+)\s+ms\s+)?(?:(\d+)\s+ms\s+)?(.+)", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        latencies = [float(x) for x in (m.group(2), m.group(3), m.group(4)) if x]
        target = m.group(5).strip()
        if "timed out" in target.lower() or target == "*":
            hops.append(TracerouteHop(hop=hop_num))
            continue
        ip_match = re.search(r"\[([\d.]+)\]|(\d{1,3}(?:\.\d{1,3}){3})", target)
        ip = ip_match.group(1) or ip_match.group(2) if ip_match else None
        hostname = target.split("[")[0].strip() if "[" in target else (target if not ip else None)
        hops.append(TracerouteHop(
            hop=hop_num, ip=ip, hostname=hostname or None,
            latency_ms=round(sum(latencies) / len(latencies), 2) if latencies else None,
        ))
    return hops


def _parse_traceroute_unix(output: str) -> list[TracerouteHop]:
    hops: list[TracerouteHop] = []
    for line in output.splitlines():
        m = re.match(r"\s*(\d+)\s+(.+)", line)
        if not m:
            continue
        hop_num = int(m.group(1))
        rest = m.group(2)
        if "*" in rest and not re.search(r"\d+\.\d+\.\d+\.\d+", rest):
            hops.append(TracerouteHop(hop=hop_num))
            continue
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", rest)
        ip = ip_match.group(1) if ip_match else None
        lat_match = re.findall(r"([\d.]+)\s+ms", rest)
        latency = round(sum(float(x) for x in lat_match) / len(lat_match), 2) if lat_match else None
        hostname = rest.split("(")[0].strip() if "(" in rest else None
        hops.append(TracerouteHop(hop=hop_num, ip=ip, hostname=hostname, latency_ms=latency))
    return hops


def _sync_traceroute(host: str, max_hops: int = 20) -> TracerouteResult:
    result = TracerouteResult()
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["tracert", "-d", "-h", str(max_hops), host]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25, encoding="utf-8", errors="replace")
            result.hops = _parse_tracert_windows(proc.stdout)
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), host]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
            result.hops = _parse_traceroute_unix(proc.stdout + proc.stderr)
        valid = [h for h in result.hops if h.ip]
        result.hop_count = len(valid) if valid else len(result.hops)
    except FileNotFoundError:
        result.errors.append("traceroute/tracert not available on this system")
    except subprocess.TimeoutExpired:
        result.errors.append("Traceroute timed out")
    except Exception as exc:
        result.errors.append(str(exc))
        logger.debug("Traceroute failed: %s", exc)
    return result


async def run_traceroute(host: str, max_hops: int = 20) -> TracerouteResult:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _sync_traceroute, host, max_hops)
