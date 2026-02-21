"""Web server log parser — normalizes Apache/Nginx combined-format logs to
the ECS schema."""

import re
from datetime import datetime, timezone
from typing import Optional


# Apache/Nginx combined log format pattern
_APACHE_PATTERN = re.compile(
    r'(?P<src_ip>\S+)\s+'           # client IP
    r'\S+\s+\S+\s+'                  # ident / authuser
    r'\[(?P<timestamp>[^\]]+)\]\s+'  # timestamp
    r'"(?P<method>\S+)\s+'           # HTTP method
    r'(?P<uri>\S+)\s+'               # URI
    r'(?P<http_version>[^"]+)"\s+'   # HTTP version
    r'(?P<status>\d{3})\s+'          # status code
    r'(?P<bytes>\S+)'                # bytes sent
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'  # optional referer/UA
)

_TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"


def parse_webserver_log(raw: str) -> Optional[dict]:
    """Parse a raw Apache/Nginx combined log line into an ECS-compliant dict.

    Args:
        raw: Raw Apache/Nginx combined-format access log line.

    Returns:
        ECS-compliant dict, or None if the line cannot be parsed.
    """
    match = _APACHE_PATTERN.match(raw.strip())
    if not match:
        return None

    g = match.groupdict()
    now_utc = datetime.now(timezone.utc).isoformat()
    status = int(g["status"])

    try:
        ts = datetime.strptime(g["timestamp"], _TIMESTAMP_FMT).isoformat()
    except ValueError:
        ts = now_utc

    return {
        "@timestamp": ts,
        "event": {
            "kind": "event",
            "category": "web",
            "type": "access",
            "action": g["method"].lower(),
            "dataset": "webserver",
            "original": raw,
            "outcome": "success" if status < 400 else "failure",
        },
        "source": {
            "ip": g["src_ip"],
        },
        "http": {
            "request": {
                "method": g["method"].upper(),
                "referrer": g.get("referer") or None,
            },
            "response": {
                "status_code": status,
                "bytes": _safe_int(g.get("bytes")),
            },
            "version": g["http_version"].replace("HTTP/", ""),
        },
        "url": {
            "path": g["uri"],
            "original": g["uri"],
        },
        "user_agent": {
            "original": g.get("user_agent"),
        },
        "tags": ["webserver", "apache"],
        "ingest_timestamp": now_utc,
        "source_type": "webserver",
    }


def _safe_int(value) -> Optional[int]:
    """Convert a value to int, returning None on failure."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
