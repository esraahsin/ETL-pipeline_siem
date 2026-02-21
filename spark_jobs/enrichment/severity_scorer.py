"""Severity scorer — calculates a unified severity score (1–10) for ECS events
based on source type, event action, and existing severity indicators."""

from typing import Optional


# Base scores by event dataset
_BASE_SCORES: dict = {
    "ids": 7,
    "firewall": 4,
    "windows": 5,
    "webserver": 3,
}

# Modifiers for specific event actions / patterns
_ACTION_MODIFIERS: dict = {
    "blocked": +1,
    "deny": +1,
    "drop": +1,
    "reject": +1,
    "failure": +2,
    "allow": -1,
    "success": -1,
}

# High-risk HTTP status codes
_HIGH_RISK_HTTP_STATUS = {401, 403, 404, 500, 503}


def calculate_severity(event: dict) -> int:
    """Calculate a unified severity score (1–10) for a normalised ECS event.

    The score is computed from:
    - A base score determined by the event dataset (source type).
    - Modifiers derived from the event action.
    - The existing ``event.severity`` value if already populated.
    - HTTP response status codes for webserver events.

    Args:
        event: ECS-compliant event dict.

    Returns:
        Integer severity score clamped to the range [1, 10].
    """
    ev = event.get("event", {})
    dataset = ev.get("dataset", "")
    action = (ev.get("action") or "").lower()
    existing_severity: Optional[int] = ev.get("severity")

    score = _BASE_SCORES.get(dataset, 5)

    # Apply action modifier
    for keyword, modifier in _ACTION_MODIFIERS.items():
        if keyword in action:
            score += modifier
            break

    # Blend with existing severity if present (already on 0–10 scale)
    if existing_severity is not None:
        score = round((score + existing_severity) / 2)

    # Penalize high-risk HTTP status codes
    http_status = (event.get("http") or {}).get("response", {}).get("status_code")
    if http_status in _HIGH_RISK_HTTP_STATUS:
        score += 2

    # Penalize IDS events that are alerts with severity 1 (critical)
    if dataset == "ids" and (event.get("rule", {}).get("severity_raw") == 1):
        score = max(score, 8)

    return max(1, min(10, score))


def enrich_with_severity(event: dict) -> dict:
    """Add or update the ``event.severity`` field with the calculated score.

    Args:
        event: ECS-compliant event dict (mutated in-place and returned).

    Returns:
        The enriched event dict.
    """
    score = calculate_severity(event)
    event.setdefault("event", {})["severity"] = score
    return event
