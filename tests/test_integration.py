"""Integration test placeholder — end-to-end flow: raw log → Kafka → Spark → Elasticsearch.

This test validates the full pipeline flow:
  1. A raw log is published to a Kafka topic by a generator.
  2. The Spark Structured Streaming job consumes the message.
  3. The log is parsed, enriched (GeoIP, severity), and deduplicated.
  4. The resulting ECS document is indexed into Elasticsearch.
  5. The document is retrievable from Elasticsearch and has the expected fields.

NOTE: These tests require a running infrastructure (Kafka, Spark, Elasticsearch).
      They are skipped automatically when the infrastructure is not available.
      Run with: pytest tests/test_integration.py -v
      Or with infrastructure: SIEM_INTEGRATION_TESTS=1 pytest tests/test_integration.py -v
"""

import json
import os
import time

import pytest

# Skip all integration tests unless explicitly enabled
INTEGRATION_ENABLED = os.getenv("SIEM_INTEGRATION_TESTS", "0") == "1"
pytestmark = pytest.mark.skipif(
    not INTEGRATION_ENABLED,
    reason="Integration tests are disabled. Set SIEM_INTEGRATION_TESTS=1 to enable.",
)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = int(os.getenv("ELASTICSEARCH_PORT", "9200"))


@pytest.fixture(scope="module")
def kafka_producer():
    """Create a Kafka producer for integration tests."""
    from kafka import KafkaProducer

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )
    yield producer
    producer.close()


@pytest.fixture(scope="module")
def es_client():
    """Create an Elasticsearch client for integration tests."""
    from elasticsearch import Elasticsearch

    client = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")
    assert client.ping(), "Elasticsearch is not reachable"
    return client


def _wait_for_es_document(es_client, index_pattern: str, doc_id: str, timeout: int = 30):
    """Poll Elasticsearch until a document with the given ID appears."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = es_client.search(
                index=index_pattern,
                body={"query": {"term": {"_id": doc_id}}},
            )
            if result["hits"]["total"]["value"] > 0:
                return result["hits"]["hits"][0]
        except Exception:
            pass
        time.sleep(2)
    return None


class TestFirewallEndToEnd:
    """End-to-end test: firewall log → Kafka → Spark → Elasticsearch."""

    def test_firewall_log_indexed_in_elasticsearch(self, kafka_producer, es_client):
        """Publish a firewall CEF log and verify it appears in Elasticsearch."""
        import uuid

        correlation_id = str(uuid.uuid4())
        message = {
            "id": correlation_id,
            "timestamp": "2026-01-01T12:00:00Z",
            "source_type": "firewall",
            "raw": (
                "Jan 01 12:00:00 test-fw CEF:0|TestVendor|NGFW|1.0|DENY|Test DENY|8|"
                f"src=203.0.113.1 spt=54321 dst=10.0.0.1 dpt=443 proto=TCP act=DENY "
                f"correlation_id={correlation_id}"
            ),
        }
        kafka_producer.send("firewall-logs", value=message)
        kafka_producer.flush()

        doc = _wait_for_es_document(es_client, "siem-firewall*", correlation_id, timeout=30)
        assert doc is not None, "Document not found in Elasticsearch within 30 seconds"
        assert doc["_source"].get("source_type") == "firewall"
        assert doc["_source"].get("event", {}).get("action") == "deny"


class TestWebserverEndToEnd:
    """End-to-end test: webserver log → Kafka → Spark → Elasticsearch."""

    def test_webserver_log_indexed_in_elasticsearch(self, kafka_producer, es_client):
        """Publish a webserver Apache log and verify it appears in Elasticsearch."""
        import uuid

        correlation_id = str(uuid.uuid4())
        message = {
            "id": correlation_id,
            "timestamp": "2026-01-01T12:00:00Z",
            "source_type": "webserver",
            "raw": (
                '198.51.100.5 - - [01/Jan/2026:12:00:00 +0000] '
                '"GET /test-integration HTTP/1.1" 200 512 "-" "integration-test/1.0"'
            ),
        }
        kafka_producer.send("web-logs", value=message)
        kafka_producer.flush()

        doc = _wait_for_es_document(es_client, "siem-webserver*", correlation_id, timeout=30)
        assert doc is not None, "Document not found in Elasticsearch within 30 seconds"
        assert doc["_source"].get("source_type") == "webserver"
        assert doc["_source"].get("http", {}).get("response", {}).get("status_code") == 200
