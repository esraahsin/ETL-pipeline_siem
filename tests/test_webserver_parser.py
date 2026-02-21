"""Unit tests for spark_jobs.parsers.webserver_parser."""

import pytest

from spark_jobs.parsers.webserver_parser import parse_webserver_log

# ---------------------------------------------------------------------------
# Sample Apache combined-format log lines
# ---------------------------------------------------------------------------

VALID_GET_200 = (
    '203.0.113.42 - - [01/Jan/2026:12:00:00 +0000] '
    '"GET /index.html HTTP/1.1" 200 4523 "-" '
    '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"'
)

VALID_POST_401 = (
    '198.51.100.7 - - [01/Jan/2026:13:30:00 +0000] '
    '"POST /login HTTP/1.1" 401 312 "http://example.com" '
    '"python-requests/2.28.0"'
)

VALID_GET_404 = (
    '192.0.2.1 - - [01/Jan/2026:14:00:00 +0000] '
    '"GET /wp-admin HTTP/1.1" 404 189 "-" "sqlmap/1.7.8"'
)

INVALID_LOG = "not a valid apache log line"


class TestWebserverParserValidInput:
    """Tests that the parser correctly handles well-formed Apache log lines."""

    def test_returns_dict_for_valid_get_200(self):
        result = parse_webserver_log(VALID_GET_200)
        assert isinstance(result, dict)

    def test_source_ip_extracted(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["source"]["ip"] == "203.0.113.42"

    def test_http_method_extracted(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["http"]["request"]["method"] == "GET"

    def test_http_status_extracted(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["http"]["response"]["status_code"] == 200

    def test_url_path_extracted(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["url"]["path"] == "/index.html"

    def test_outcome_success_for_200(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["event"]["outcome"] == "success"

    def test_outcome_failure_for_401(self):
        result = parse_webserver_log(VALID_POST_401)
        assert result["event"]["outcome"] == "failure"

    def test_outcome_failure_for_404(self):
        result = parse_webserver_log(VALID_GET_404)
        assert result["event"]["outcome"] == "failure"

    def test_user_agent_extracted(self):
        result = parse_webserver_log(VALID_GET_200)
        assert "Mozilla" in result["user_agent"]["original"]

    def test_source_type_is_webserver(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["source_type"] == "webserver"

    def test_event_category_is_web(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["event"]["category"] == "web"

    def test_bytes_extracted(self):
        result = parse_webserver_log(VALID_GET_200)
        assert result["http"]["response"]["bytes"] == 4523

    def test_post_method_extracted(self):
        result = parse_webserver_log(VALID_POST_401)
        assert result["http"]["request"]["method"] == "POST"

    def test_referer_extracted(self):
        result = parse_webserver_log(VALID_POST_401)
        assert result["http"]["request"]["referrer"] == "http://example.com"


class TestWebserverParserInvalidInput:
    """Tests that the parser gracefully handles malformed input."""

    def test_returns_none_for_invalid_log(self):
        result = parse_webserver_log(INVALID_LOG)
        assert result is None

    def test_returns_none_for_empty_string(self):
        result = parse_webserver_log("")
        assert result is None
