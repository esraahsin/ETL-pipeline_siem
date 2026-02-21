#!/usr/bin/env bash
# =============================================================================
# create_topics.sh — Create the 4 Kafka topics for the SIEM pipeline
# =============================================================================
# Usage: bash kafka/create_topics.sh
# Requires: KAFKA_BOOTSTRAP_SERVERS env var (default: localhost:9092)
# =============================================================================

set -euo pipefail

KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}"
PARTITIONS="${KAFKA_NUM_PARTITIONS:-3}"
REPLICATION="${KAFKA_REPLICATION_FACTOR:-1}"

TOPICS=(
    "firewall-logs"
    "web-logs"
    "windows-logs"
    "ids-logs"
    "siem-errors"
)

echo "[INFO] Creating Kafka topics on ${KAFKA_BOOTSTRAP}..."

for TOPIC in "${TOPICS[@]}"; do
    echo "[INFO] Creating topic: ${TOPIC}"
    kafka-topics.sh \
        --bootstrap-server "${KAFKA_BOOTSTRAP}" \
        --create \
        --if-not-exists \
        --topic "${TOPIC}" \
        --partitions "${PARTITIONS}" \
        --replication-factor "${REPLICATION}" \
        --config retention.ms=604800000
    echo "[OK]   Topic '${TOPIC}' ready."
done

echo "[INFO] Listing all topics:"
kafka-topics.sh --bootstrap-server "${KAFKA_BOOTSTRAP}" --list

echo "[INFO] All topics created successfully."
