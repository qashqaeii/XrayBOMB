"""Pre-analysis config validation."""

from __future__ import annotations

from backend.models import ConfigValidation, ParsedConfig, ProtocolType, TransportType, ValidationIssue


def validate_config(config: ParsedConfig) -> ConfigValidation:
    issues: list[ValidationIssue] = []

    if config.protocol == ProtocolType.UNKNOWN:
        issues.append(ValidationIssue(
            severity="error", code="UNKNOWN_PROTOCOL",
            message="Could not detect protocol from input.",
        ))

    if not config.address:
        issues.append(ValidationIssue(
            severity="error", code="MISSING_ADDRESS",
            message="Server address is missing.",
        ))

    if not config.port or config.port <= 0 or config.port > 65535:
        issues.append(ValidationIssue(
            severity="error", code="INVALID_PORT",
            message=f"Invalid port: {config.port}",
        ))

    if config.protocol in (ProtocolType.VLESS, ProtocolType.VMESS) and not config.uuid:
        issues.append(ValidationIssue(
            severity="error", code="MISSING_UUID",
            message=f"{config.protocol.value} requires a UUID.",
        ))

    if config.protocol == ProtocolType.TROJAN and not config.password:
        issues.append(ValidationIssue(
            severity="error", code="MISSING_PASSWORD",
            message="Trojan requires a password.",
        ))

    if config.protocol == ProtocolType.SHADOWSOCKS and not config.password:
        issues.append(ValidationIssue(
            severity="warning", code="MISSING_SS_PASSWORD",
            message="Shadowsocks password may be missing.",
        ))

    if config.reality and not config.public_key:
        issues.append(ValidationIssue(
            severity="warning", code="REALITY_NO_PBK",
            message="REALITY enabled but public key (pbk) is missing.",
        ))

    if config.transport_type == TransportType.WS:
        issues.append(ValidationIssue(
            severity="warning", code="DEPRECATED_WS",
            message="WebSocket transport is deprecated in Xray 26+. Consider migrating to XHTTP.",
        ))

    if config.transport_type == TransportType.WS and config.host and config.extra.get("host"):
        issues.append(ValidationIssue(
            severity="info", code="DEPRECATED_WS_HOST",
            message="WS 'host' in headers is deprecated; use independent 'host' field.",
        ))

    if not config.tls and not config.reality and config.port not in (80, 8080):
        issues.append(ValidationIssue(
            severity="warning", code="NO_TLS",
            message="No TLS/Reality — traffic is unencrypted.",
        ))

    if config.allow_insecure:
        issues.append(ValidationIssue(
            severity="warning", code="ALLOW_INSECURE",
            message="allowInsecure enabled — certificate verification disabled.",
        ))

    has_errors = any(i.severity == "error" for i in issues)
    return ConfigValidation(valid=not has_errors, issues=issues)
