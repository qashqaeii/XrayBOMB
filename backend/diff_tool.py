"""Compare two parsed configs."""

from __future__ import annotations

from backend.models import ParsedConfig


def diff_configs(a: ParsedConfig, b: ParsedConfig) -> list[dict]:
    fields = [
        "protocol", "address", "port", "uuid", "password", "encryption", "flow",
        "security", "tls", "reality", "public_key", "short_id", "sni", "host",
        "alpn", "path", "service_name", "transport_type", "fingerprint", "allow_insecure", "remark",
    ]
    diffs: list[dict] = []
    for field in fields:
        va = getattr(a, field, None)
        vb = getattr(b, field, None)
        if hasattr(va, "value"):
            va = va.value
        if hasattr(vb, "value"):
            vb = vb.value
        if str(va) != str(vb):
            diffs.append({"field": field, "a": va, "b": vb, "changed": True})
        else:
            diffs.append({"field": field, "a": va, "b": vb, "changed": False})
    return diffs


def format_diff_text(diffs: list[dict]) -> str:
    lines = ["Config Diff", "=" * 50, ""]
    changed = [d for d in diffs if d["changed"]]
    if not changed:
        lines.append("  No differences found.")
        return "\n".join(lines)
    for d in changed:
        lines.append(f"  {d['field']}:")
        lines.append(f"    A: {d['a']}")
        lines.append(f"    B: {d['b']}")
        lines.append("")
    return "\n".join(lines)
