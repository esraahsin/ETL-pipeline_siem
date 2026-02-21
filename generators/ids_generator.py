"""IDS log generator — produces Suricata Eve JSON alert records and publishes
them to the Kafka topic ``ids-logs``."""

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

log = structlog.get_logger(component="ids_generator")
fake = Faker()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_IDS", "ids-logs")
INTERVAL = float(os.getenv("GENERATOR_INTERVAL_SECONDS", "1"))
BATCH_SIZE = int(os.getenv("GENERATOR_BATCH_SIZE", "10"))

SIGNATURES = [
    {"sid": 2001219, "msg": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2},
    {"sid": 2002910, "msg": "ET SCAN Potential VNC Scan", "category": "Attempted Information Leak", "severity": 2},
    {"sid": 2008578, "msg": "ET EXPLOIT MS17-010 EternalBlue", "category": "Attempted Administrator Privilege Gain", "severity": 1},
    {"sid": 2019284, "msg": "ET MALWARE Mirai Botnet Checkin", "category": "Trojan Activity", "severity": 1},
    {"sid": 2024897, "msg": "ET WEB_SERVER SQL Injection Attempt", "category": "Web Application Attack", "severity": 2},
    {"sid": 2013028, "msg": "ET POLICY PE EXE or DLL Windows file download", "category": "Potential Corporate Privacy Violation", "severity": 3},
    {"sid": 2100498, "msg": "GPL ATTACK_RESPONSE id check returned root", "category": "Potentially Bad Traffic", "severity": 2},
    {"sid": 2016922, "msg": "ET INFO Suspicious POST with no referer", "category": "Potentially Bad Traffic", "severity": 3},
]

PROTOCOLS = ["TCP", "UDP", "ICMP"]


def generate_eve_json() -> dict:
    """Return a single Suricata Eve JSON alert record as a dict."""
    sig = random.choice(SIGNATURES)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "flow_id": random.randint(1000000000, 9999999999),
        "in_iface": random.choice(["eth0", "eth1"]),
        "event_type": "alert",
        "src_ip": fake.ipv4_public(),
        "src_port": random.randint(1024, 65535),
        "dest_ip": fake.ipv4_public(),
        "dest_port": random.choice([22, 80, 443, 445, 3389]),
        "proto": random.choice(PROTOCOLS),
        "alert": {
            "action": random.choice(["allowed", "blocked"]),
            "gid": 1,
            "signature_id": sig["sid"],
            "rev": 1,
            "signature": sig["msg"],
            "category": sig["category"],
            "severity": sig["severity"],
        },
        "payload_printable": fake.sentence(nb_words=6),
        "stream": 0,
    }


def build_message(event: dict) -> dict:
    """Wrap event in a metadata envelope."""
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "ids",
        "raw": event,
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
    """Main loop: generate Suricata IDS logs and publish to Kafka."""
    producer = create_producer()
    log.info("ids_generator_started", topic=KAFKA_TOPIC, batch_size=BATCH_SIZE)

    try:
        while True:
            for _ in range(BATCH_SIZE):
                event = generate_eve_json()
                msg = build_message(event)
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
