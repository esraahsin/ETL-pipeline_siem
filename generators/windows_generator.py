"""Windows Event log generator — produces Windows Security Event records in
JSON format and publishes them to the Kafka topic ``windows-logs``."""

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

log = structlog.get_logger(component="windows_generator")
fake = Faker()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_WINDOWS", "windows-logs")
INTERVAL = float(os.getenv("GENERATOR_INTERVAL_SECONDS", "1"))
BATCH_SIZE = int(os.getenv("GENERATOR_BATCH_SIZE", "10"))

# Common Windows Security Event IDs
EVENT_IDS = {
    4624: "An account was successfully logged on",
    4625: "An account failed to log on",
    4634: "An account was logged off",
    4648: "A logon was attempted using explicit credentials",
    4672: "Special privileges assigned to new logon",
    4688: "A new process has been created",
    4698: "A scheduled task was created",
    4720: "A user account was created",
    4726: "A user account was deleted",
    4740: "A user account was locked out",
}
LOGON_TYPES = {2: "Interactive", 3: "Network", 4: "Batch", 5: "Service", 10: "RemoteInteractive"}
SEVERITIES = ["INFORMATION", "WARNING", "ERROR", "CRITICAL"]


def generate_windows_event() -> dict:
    """Return a single Windows Security Event as a dict."""
    event_id = random.choice(list(EVENT_IDS.keys()))
    return {
        "EventID": event_id,
        "Description": EVENT_IDS[event_id],
        "TimeCreated": datetime.now(timezone.utc).isoformat(),
        "Computer": fake.hostname(),
        "Domain": fake.domain_name(),
        "SubjectUserName": fake.user_name(),
        "SubjectDomainName": fake.domain_word().upper(),
        "TargetUserName": fake.user_name(),
        "LogonType": random.choice(list(LOGON_TYPES.keys())),
        "IpAddress": fake.ipv4_public(),
        "ProcessName": random.choice(["lsass.exe", "svchost.exe", "cmd.exe", "powershell.exe", "explorer.exe"]),
        "Channel": "Security",
        "Level": random.choice(SEVERITIES),
        "Keywords": "Audit Success" if event_id in [4624, 4634, 4672] else "Audit Failure",
    }


def build_message(event: dict) -> dict:
    """Wrap event in a metadata envelope."""
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "windows",
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
    """Main loop: generate Windows Event logs and publish to Kafka."""
    producer = create_producer()
    log.info("windows_generator_started", topic=KAFKA_TOPIC, batch_size=BATCH_SIZE)

    try:
        while True:
            for _ in range(BATCH_SIZE):
                event = generate_windows_event()
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
