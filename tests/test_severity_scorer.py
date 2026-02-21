"""Unit tests for spark_jobs.enrichment.severity_scorer."""

import pytest

from spark_jobs.enrichment.severity_scorer import calculate_severity, enrich_with_severity


def _make_event(dataset: str, action: str = "", severity: int = None, http_status: int = None) -> dict:
    """Helper to build a minimal ECS event for testing."""
    event: dict = {
        "event": {
            "dataset": dataset,
            "action": action,
        },
        "source_type": dataset,
    }
    if severity is not None:
        event["event"]["severity"] = severity
    if http_status is not None:
        event["http"] = {"response": {"status_code": http_status}}
    return event


class TestCalculateSeverity:
    """Tests for the calculate_severity function."""

    def test_ids_base_score_is_high(self):
        event = _make_event("ids", action="allowed")
        score = calculate_severity(event)
        # IDS base=7, allow modifier=-1 → 6
        assert score == 6

    def test_firewall_deny_increases_score(self):
        event = _make_event("firewall", action="deny")
        score = calculate_severity(event)
        # base=4, deny=+1 → 5
        assert score == 5

    def test_firewall_allow_decreases_score(self):
        event = _make_event("firewall", action="allow")
        score = calculate_severity(event)
        # base=4, allow=-1 → 3
        assert score == 3

    def test_authentication_failure_increases_score(self):
        event = _make_event("windows", action="failure")
        score = calculate_severity(event)
        # base=5, failure=+2 → 7
        assert score == 7

    def test_webserver_http_500_increases_score(self):
        event = _make_event("webserver", http_status=500)
        score = calculate_severity(event)
        # base=3, 500 penalty +2 → 5
        assert score == 5

    def test_score_clamped_to_max_10(self):
        # Construct an event likely to exceed 10
        event = _make_event("ids", action="failure", severity=10)
        score = calculate_severity(event)
        assert score <= 10

    def test_score_clamped_to_min_1(self):
        event = _make_event("webserver", action="success", severity=1)
        score = calculate_severity(event)
        assert score >= 1

    def test_unknown_dataset_uses_default_base(self):
        event = _make_event("unknown_source")
        score = calculate_severity(event)
        assert 1 <= score <= 10

    def test_existing_severity_blended(self):
        event = _make_event("firewall", severity=8)
        score = calculate_severity(event)
        # base=4, blended with 8 → round((4+8)/2) = 6
        assert score == 6


class TestEnrichWithSeverity:
    """Tests for the enrich_with_severity function."""

    def test_adds_severity_field(self):
        event = _make_event("firewall", action="deny")
        result = enrich_with_severity(event)
        assert "severity" in result["event"]

    def test_severity_is_integer(self):
        event = _make_event("firewall", action="deny")
        result = enrich_with_severity(event)
        assert isinstance(result["event"]["severity"], int)

    def test_returns_same_event_dict(self):
        event = _make_event("firewall")
        result = enrich_with_severity(event)
        assert result is event
