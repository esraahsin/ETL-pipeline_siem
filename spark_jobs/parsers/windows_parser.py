"""Windows Event log parser — normalizes Windows Security Event JSON records
to the ECS schema."""

from datetime import datetime, timezone
from typing import Optional, Union


_LOGON_TYPE_NAMES = {
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
}

_SEVERITY_MAP = {
    "INFORMATION": 1,
    "WARNING": 4,
    "ERROR": 7,
    "CRITICAL": 9,
    "AUDIT_SUCCESS": 2,
    "AUDIT_FAILURE": 6,
}


def parse_windows_log(raw: Union[dict, str]) -> Optional[dict]:
    """Parse a Windows Security Event (dict or JSON string) into an ECS-compliant dict.

    Args:
        raw: Windows event as a dict or a JSON string.

    Returns:
        ECS-compliant dict, or None if the record cannot be parsed.
    """
    import json as _json

    if isinstance(raw, str):
        try:
            raw = _json.loads(raw)
        except _json.JSONDecodeError:
            return None

    if not isinstance(raw, dict):
        return None

    event_id = raw.get("EventID")
    if event_id is None:
        return None

    now_utc = datetime.now(timezone.utc).isoformat()
    level = str(raw.get("Level", "INFORMATION")).upper()

    return {
        "@timestamp": raw.get("TimeCreated", now_utc),
        "event": {
            "kind": "event",
            "category": "authentication",
            "type": "start",
            "code": str(event_id),
            "action": raw.get("Description", "unknown").lower(),
            "dataset": "windows",
            "severity": _SEVERITY_MAP.get(level, 5),
            "outcome": "success" if raw.get("Keywords", "").lower() == "audit success" else "failure",
            "original": str(raw),
        },
        "host": {
            "hostname": raw.get("Computer"),
            "domain": raw.get("Domain"),
        },
        "user": {
            "name": raw.get("TargetUserName"),
            "domain": raw.get("SubjectDomainName"),
        },
        "source": {
            "ip": raw.get("IpAddress"),
        },
        "process": {
            "name": raw.get("ProcessName"),
        },
        "winlog": {
            "event_id": event_id,
            "channel": raw.get("Channel", "Security"),
            "logon": {
                "type": _LOGON_TYPE_NAMES.get(raw.get("LogonType"), "unknown"),
            },
        },
        "tags": ["windows", "security-event"],
        "ingest_timestamp": now_utc,
        "source_type": "windows",
    }
