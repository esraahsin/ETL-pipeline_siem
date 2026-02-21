"""Unit tests for spark_jobs.parsers.firewall_parser."""

import pytest

from spark_jobs.parsers.firewall_parser import _map_severity, _safe_int, parse_firewall_log

# ---------------------------------------------------------------------------
# Sample CEF log lines
# ---------------------------------------------------------------------------

VALID_CEF_LOG = (
    "Jan 01 12:00:00 fw-host CEF:0|FW-Vendor|NGFW|1.0|DENY|Firewall DENY|8|"
    "src=192.168.1.100 spt=54321 dst=10.0.0.1 dpt=443 proto=TCP "
    "deviceInboundInterface=eth0 act=DENY"
)

ALLOW_CEF_LOG = (
    "Jan 01 13:00:00 fw-host CEF:0|FW-Vendor|NGFW|1.0|ALLOW|Firewall ALLOW|2|"
    "src=203.0.113.5 spt=12345 dst=192.168.1.50 dpt=80 proto=TCP "
    "deviceInboundInterface=wan0 act=ALLOW"
)

INVALID_LOG = "This is not a valid CEF log line at all."


class TestFirewallParserValidInput:
    """Tests that the parser correctly handles well-formed CEF logs."""

    def test_returns_dict_for_valid_cef_log(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert isinstance(result, dict)

    def test_timestamp_field_present(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert "@timestamp" in result

    def test_source_ip_extracted(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["source"]["ip"] == "192.168.1.100"

    def test_destination_ip_extracted(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["destination"]["ip"] == "10.0.0.1"

    def test_source_port_extracted(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["source"]["port"] == 54321

    def test_destination_port_extracted(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["destination"]["port"] == 443

    def test_action_is_deny(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["event"]["action"] == "deny"

    def test_action_is_allow(self):
        result = parse_firewall_log(ALLOW_CEF_LOG)
        assert result["event"]["action"] == "allow"

    def test_network_transport_extracted(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["network"]["transport"] == "tcp"

    def test_source_type_tag(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["source_type"] == "firewall"

    def test_event_category_is_network(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["event"]["category"] == "network"

    def test_severity_mapped_correctly(self):
        result = parse_firewall_log(VALID_CEF_LOG)
        assert result["event"]["severity"] == 8


class TestFirewallParserInvalidInput:
    """Tests that the parser gracefully handles malformed input."""

    def test_returns_none_for_non_cef_line(self):
        result = parse_firewall_log(INVALID_LOG)
        assert result is None

    def test_returns_none_for_empty_string(self):
        result = parse_firewall_log("")
        assert result is None


class TestHelperFunctions:
    """Tests for helper functions used by the firewall parser."""

    def test_map_severity_valid_int_string(self):
        assert _map_severity("7") == 7

    def test_map_severity_clamps_above_10(self):
        assert _map_severity("15") == 10

    def test_map_severity_clamps_below_0(self):
        assert _map_severity("-3") == 0

    def test_map_severity_invalid_returns_default(self):
        assert _map_severity("bad") == 5

    def test_safe_int_valid(self):
        assert _safe_int("443") == 443

    def test_safe_int_invalid_returns_none(self):
        assert _safe_int("notanumber") is None

    def test_safe_int_none_returns_none(self):
        assert _safe_int(None) is None
