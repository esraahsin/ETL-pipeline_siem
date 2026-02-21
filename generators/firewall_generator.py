"""Firewall log generator — produces Syslog/CEF formatted firewall events
and publishes them to the Kafka topic ``firewall-logs``."""

import json
import os
import random
import time
import uuid
from datetime import datetime, timezone

import structlog
from faker import Faker
from kafka import KafkaProducer
from tenacity import retry, stop_after_attempt, wait_exponential

log = structlog.get_logger(component="firewall_generator")
fake = Faker()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_FIREWALL", "firewall-logs")
INTERVAL = float(os.getenv("GENERATOR_INTERVAL_SECONDS", "1"))
BATCH_SIZE = int(os.getenv("GENERATOR_BATCH_SIZE", "10"))

ACTIONS = ["ALLOW", "DENY", "DROP", "REJECT"]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
INTERFACES = ["eth0", "eth1", "wan0", "lan0"]


def generate_cef_log() -> str:
    """Return a single CEF-formatted firewall log line."""
    src_ip = fake.ipv4_public()
    dst_ip = fake.ipv4_public()
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([22, 23, 25, 53, 80, 443, 3389, 8080, 8443])
    action = random.choice(ACTIONS)
    protocol = random.choice(PROTOCOLS)
    interface = random.choice(INTERFACES)
    severity = random.randint(0, 10)
    timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    hostname = fake.hostname()

    cef = (
        f"{timestamp} {hostname} CEF:0|FW-Vendor|NGFW|1.0|{action}|"
        f"Firewall {action}|{severity}|"
        f"src={src_ip} spt={src_port} dst={dst_ip} dpt={dst_port} "
        f"proto={protocol} deviceInboundInterface={interface} act={action}"
    )
    return cef


def build_message(raw_log: str) -> dict:
    """Wrap raw log in a metadata envelope."""
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "firewall",
        "raw": raw_log,
    }


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
)
def create_producer() -> KafkaProducer:
    """Create a Kafka producer with retry on connection failure."""
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=3,
    )


def run():
    """Main loop: generate firewall logs and publish to Kafka."""
    producer = create_producer()
    log.info("firewall_generator_started", topic=KAFKA_TOPIC, batch_size=BATCH_SIZE)

    try:
        while True:
            for _ in range(BATCH_SIZE):
                raw = generate_cef_log()
                msg = build_message(raw)
                producer.send(KAFKA_TOPIC, value=msg)
                log.debug("log_sent", topic=KAFKA_TOPIC, id=msg["id"])
            producer.flush()
            log.info("batch_sent", topic=KAFKA_TOPIC, count=BATCH_SIZE)
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        log.info("generator_stopped")
    finally:
        producer.close()


if __name__ == "__main__":
    run()
