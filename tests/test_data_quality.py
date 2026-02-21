"""Data quality tests — validate ECS field constraints using a Great
Expectations-style approach implemented with standard pytest assertions.

These tests verify:
  - Required ECS fields are non-null after transformation
  - IP address fields contain valid IPv4/IPv6 addresses
"""

import re
import pytest

from spark_jobs.parsers.firewall_parser import parse_firewall_log
from spark_jobs.parsers.webserver_parser import parse_webserver_log
from spark_jobs.parsers.windows_parser import parse_windows_log
from spark_jobs.parsers.ids_parser import parse_ids_log

# ---------------------------------------------------------------------------
# Sample inputs
# ---------------------------------------------------------------------------

SAMPLE_CEF = (
    "Jan 01 12:00:00 host CEF:0|Vendor|FW|1.0|DENY|Deny|8|"
    "src=1.2.3.4 spt=1234 dst=5.6.7.8 dpt=443 proto=TCP act=DENY"
)

SAMPLE_APACHE = (
    '10.0.0.1 - - [01/Jan/2026:10:00:00 +0000] '
    '"GET /api/data HTTP/1.1" 200 1024 "-" "curl/7.68.0"'
)

SAMPLE_WINDOWS = {
    "EventID": 4625,
    "Description": "An account failed to log on",
    "TimeCreated": "2026-01-01T10:00:00Z",
    "Computer": "WS-01.corp.local",
    "Domain": "corp.local",
    "SubjectUserName": "jdoe",
    "SubjectDomainName": "CORP",
    "TargetUserName": "admin",
    "LogonType": 3,
    "IpAddress": "192.168.1.200",
    "ProcessName": "lsass.exe",
    "Channel": "Security",
    "Level": "ERROR",
    "Keywords": "Audit Failure",
}

SAMPLE_IDS = {
    "timestamp": "2026-01-01T10:00:00Z",
    "src_ip": "203.0.113.10",
    "src_port": 54321,
    "dest_ip": "10.0.0.5",
    "dest_port": 22,
    "proto": "TCP",
    "alert": {
        "action": "blocked",
        "signature_id": 2001219,
        "rev": 1,
        "signature": "ET SCAN Potential SSH Scan",
        "category": "Attempted Information Leak",
        "severity": 2,
    },
}

# ---------------------------------------------------------------------------
# Required ECS fields that must always be present and non-null
# ---------------------------------------------------------------------------

_REQUIRED_FIELDS = ["@timestamp", "source_type", "event"]
_IP_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"             # IPv4
    r"|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{0,4}$"  # IPv6 (simplified)
)


def _check_required_fields(event: dict):
    """Assert that all required ECS fields are present and non-null."""
    for field in _REQUIRED_FIELDS:
        assert field in event, f"Missing required field: '{field}'"
        assert event[field] is not None, f"Required field '{field}' is None"


def _check_ip_field(ip_value):
    """Assert that an IP field contains a valid IPv4 or IPv6 address."""
    if ip_value is None:
        return  # Optional — skip if absent
    assert _IP_PATTERN.match(str(ip_value)), f"Invalid IP address format: '{ip_value}'"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRequiredFieldsNotNull:
    """Validate that required ECS fields are non-null after parsing."""

    def test_firewall_required_fields(self):
        event = parse_firewall_log(SAMPLE_CEF)
        assert event is not None
        _check_required_fields(event)

    def test_webserver_required_fields(self):
        event = parse_webserver_log(SAMPLE_APACHE)
        assert event is not None
        _check_required_fields(event)

    def test_windows_required_fields(self):
        event = parse_windows_log(SAMPLE_WINDOWS)
        assert event is not None
        _check_required_fields(event)

    def test_ids_required_fields(self):
        event = parse_ids_log(SAMPLE_IDS)
        assert event is not None
        _check_required_fields(event)

    def test_event_sub_fields_not_null(self):
        """The 'event' dict must contain 'dataset' and 'kind' sub-fields."""
        for parser, input_data in [
            (parse_firewall_log, SAMPLE_CEF),
            (parse_webserver_log, SAMPLE_APACHE),
            (parse_windows_log, SAMPLE_WINDOWS),
            (parse_ids_log, SAMPLE_IDS),
        ]:
            result = parser(input_data)
            assert result is not None
            assert "dataset" in result["event"], f"'event.dataset' missing in {result['source_type']} event"
            assert "kind" in result["event"], f"'event.kind' missing in {result['source_type']} event"


class TestIPAddressFormat:
    """Validate that IP address fields contain valid IPv4/IPv6 addresses."""

    def test_firewall_source_ip_valid(self):
        event = parse_firewall_log(SAMPLE_CEF)
        _check_ip_field(event["source"]["ip"])

    def test_firewall_destination_ip_valid(self):
        event = parse_firewall_log(SAMPLE_CEF)
        _check_ip_field(event["destination"]["ip"])

    def test_webserver_source_ip_valid(self):
        event = parse_webserver_log(SAMPLE_APACHE)
        _check_ip_field(event["source"]["ip"])

    def test_windows_source_ip_valid(self):
        event = parse_windows_log(SAMPLE_WINDOWS)
        _check_ip_field(event["source"]["ip"])

    def test_ids_source_ip_valid(self):
        event = parse_ids_log(SAMPLE_IDS)
        _check_ip_field(event["source"]["ip"])

    def test_ids_destination_ip_valid(self):
        event = parse_ids_log(SAMPLE_IDS)
        _check_ip_field(event["destination"]["ip"])
