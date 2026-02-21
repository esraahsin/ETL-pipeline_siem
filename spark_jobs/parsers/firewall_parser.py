"""Firewall log parser — normalizes Syslog/CEF firewall logs to ECS schema."""

import re
from datetime import datetime, timezone
from typing import Optional


# CEF field extraction pattern
_CEF_PATTERN = re.compile(
    r"CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|"
    r"(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)"
)
_EXT_PATTERN = re.compile(r"(\w+)=([^\s]+(?:\s+[^\w=][^\s]*)*)")


def _parse_cef_extension(extension: str) -> dict:
    """Parse key=value pairs from a CEF extension string."""
    return {k: v for k, v in _EXT_PATTERN.findall(extension)}


def parse_firewall_log(raw: str) -> Optional[dict]:
    """Parse a raw Syslog/CEF firewall log line into an ECS-compliant dict.

    Args:
        raw: Raw CEF log string, optionally prefixed with a syslog header.

    Returns:
        ECS-compliant dict, or None if the line cannot be parsed.
    """
    match = _CEF_PATTERN.search(raw)
    if not match:
        return None

    ext = _parse_cef_extension(match.group("extension"))
    now_utc = datetime.now(timezone.utc).isoformat()

    return {
        "@timestamp": now_utc,
        "event": {
            "kind": "event",
            "category": "network",
            "type": "connection",
            "action": ext.get("act", "unknown").lower(),
            "severity": _map_severity(match.group("severity")),
            "dataset": "firewall",
            "original": raw,
        },
        "source": {
            "ip": ext.get("src"),
            "port": _safe_int(ext.get("spt")),
        },
        "destination": {
            "ip": ext.get("dst"),
            "port": _safe_int(ext.get("dpt")),
        },
        "network": {
            "transport": ext.get("proto", "unknown").lower(),
        },
        "observer": {
            "vendor": match.group("vendor"),
            "product": match.group("product"),
            "ingress": {"interface": {"name": ext.get("deviceInboundInterface")}},
        },
        "tags": ["firewall", "cef"],
        "ingest_timestamp": now_utc,
        "source_type": "firewall",
    }


def _map_severity(raw_severity: str) -> int:
    """Map a CEF severity string (0-10) to an integer."""
    try:
        val = int(raw_severity)
        return max(0, min(10, val))
    except (ValueError, TypeError):
        return 5


def _safe_int(value) -> Optional[int]:
    """Convert a value to int, returning None on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
