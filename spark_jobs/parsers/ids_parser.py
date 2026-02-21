"""IDS log parser — normalizes Suricata Eve JSON alert records to the ECS schema."""

from datetime import datetime, timezone
from typing import Optional, Union


_SEVERITY_MAP = {1: 9, 2: 6, 3: 3, 4: 1}


def parse_ids_log(raw: Union[dict, str]) -> Optional[dict]:
    """Parse a Suricata Eve JSON record into an ECS-compliant dict.

    Args:
        raw: Suricata Eve JSON record as a dict or JSON string.

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

    alert = raw.get("alert", {})
    if not alert:
        return None

    now_utc = datetime.now(timezone.utc).isoformat()
    suricata_severity = alert.get("severity", 3)

    return {
        "@timestamp": raw.get("timestamp", now_utc),
        "event": {
            "kind": "alert",
            "category": "intrusion_detection",
            "type": "denied" if alert.get("action") == "blocked" else "allowed",
            "action": alert.get("action", "unknown"),
            "dataset": "ids",
            "severity": _SEVERITY_MAP.get(suricata_severity, 5),
            "original": str(raw),
        },
        "source": {
            "ip": raw.get("src_ip"),
            "port": raw.get("src_port"),
        },
        "destination": {
            "ip": raw.get("dest_ip"),
            "port": raw.get("dest_port"),
        },
        "network": {
            "transport": raw.get("proto", "unknown").lower(),
        },
        "observer": {
            "product": "Suricata",
            "type": "ids",
        },
        "rule": {
            "id": str(alert.get("signature_id")),
            "name": alert.get("signature"),
            "category": alert.get("category"),
        },
        "tags": ["ids", "suricata"],
        "ingest_timestamp": now_utc,
        "source_type": "ids",
    }
