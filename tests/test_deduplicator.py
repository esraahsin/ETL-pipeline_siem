"""Unit tests for spark_jobs.quality.deduplicator."""

import pytest

from spark_jobs.quality.deduplicator import compute_event_hash, deduplicate, is_duplicate


def _make_event(source_type: str, action: str = "allow", ts: str = "2026-01-01T00:00:00Z") -> dict:
    """Helper to build a minimal ECS event for testing."""
    return {
        "@timestamp": ts,
        "source_type": source_type,
        "event": {"action": action, "dataset": source_type},
        "ingest_timestamp": "2026-01-01T00:00:01Z",  # intentionally different
    }


class TestComputeEventHash:
    """Tests for the compute_event_hash function."""

    def test_same_event_produces_same_hash(self):
        event = _make_event("firewall")
        assert compute_event_hash(event) == compute_event_hash(event)

    def test_different_action_produces_different_hash(self):
        e1 = _make_event("firewall", action="allow")
        e2 = _make_event("firewall", action="deny")
        assert compute_event_hash(e1) != compute_event_hash(e2)

    def test_different_source_type_produces_different_hash(self):
        e1 = _make_event("firewall")
        e2 = _make_event("webserver")
        assert compute_event_hash(e1) != compute_event_hash(e2)

    def test_ingest_timestamp_ignored_in_hash(self):
        e1 = _make_event("firewall")
        e2 = _make_event("firewall")
        e2["ingest_timestamp"] = "2026-06-01T12:00:00Z"
        assert compute_event_hash(e1) == compute_event_hash(e2)

    def test_returns_hex_string(self):
        h = compute_event_hash(_make_event("ids"))
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest length


class TestDeduplicate:
    """Tests for the deduplicate generator function."""

    def test_removes_exact_duplicate(self):
        event = _make_event("firewall")
        events = [event, dict(event)]  # two identical events
        result = list(deduplicate(events))
        assert len(result) == 1

    def test_keeps_different_events(self):
        e1 = _make_event("firewall", action="allow")
        e2 = _make_event("firewall", action="deny")
        result = list(deduplicate([e1, e2]))
        assert len(result) == 2

    def test_annotates_event_with_id(self):
        event = _make_event("webserver")
        result = list(deduplicate([event]))
        assert "_id" in result[0]

    def test_id_matches_hash(self):
        event = _make_event("webserver")
        expected_hash = compute_event_hash(event)
        result = list(deduplicate([event]))
        assert result[0]["_id"] == expected_hash

    def test_empty_input_yields_nothing(self):
        result = list(deduplicate([]))
        assert result == []

    def test_deduplication_across_large_batch(self):
        event = _make_event("ids")
        events = [dict(event) for _ in range(100)]
        result = list(deduplicate(events))
        assert len(result) == 1


class TestIsDuplicate:
    """Tests for the is_duplicate helper function."""

    def test_first_occurrence_not_duplicate(self):
        event = _make_event("firewall")
        seen = set()
        assert is_duplicate(event, seen) is False

    def test_second_occurrence_is_duplicate(self):
        event = _make_event("firewall")
        seen = set()
        is_duplicate(event, seen)
        assert is_duplicate(event, seen) is True

    def test_different_event_not_duplicate(self):
        e1 = _make_event("firewall", action="allow")
        e2 = _make_event("firewall", action="deny")
        seen = set()
        is_duplicate(e1, seen)
        assert is_duplicate(e2, seen) is False
