"""Web server log generator — produces Apache/Nginx combined access log
entries and publishes them to the Kafka topic ``web-logs``."""

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

log = structlog.get_logger(component="webserver_generator")
fake = Faker()

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC_WEBSERVER", "web-logs")
INTERVAL = float(os.getenv("GENERATOR_INTERVAL_SECONDS", "1"))
BATCH_SIZE = int(os.getenv("GENERATOR_BATCH_SIZE", "10"))

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
HTTP_STATUS_CODES = [200, 200, 200, 201, 301, 302, 400, 401, 403, 404, 500, 503]
URIS = [
    "/", "/index.html", "/login", "/api/v1/users", "/api/v1/data",
    "/admin", "/wp-admin", "/.env", "/phpmyadmin", "/api/v1/auth",
    "/static/main.js", "/favicon.ico", "/robots.txt",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.0",
    "Nmap Scripting Engine",
    "sqlmap/1.7.8",
]


def generate_apache_log() -> str:
    """Return a single Apache combined-format access log line."""
    ip = fake.ipv4_public()
    timestamp = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    method = random.choice(HTTP_METHODS)
    uri = random.choice(URIS)
    status = random.choice(HTTP_STATUS_CODES)
    size = random.randint(100, 50000)
    referer = "-"
    user_agent = random.choice(USER_AGENTS)

    return f'{ip} - - [{timestamp}] "{method} {uri} HTTP/1.1" {status} {size} "{referer}" "{user_agent}"'


def build_message(raw_log: str) -> dict:
    """Wrap raw log in a metadata envelope."""
    return {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_type": "webserver",
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
    """Main loop: generate web server logs and publish to Kafka."""
    producer = create_producer()
    log.info("webserver_generator_started", topic=KAFKA_TOPIC, batch_size=BATCH_SIZE)

    try:
        while True:
            for _ in range(BATCH_SIZE):
                raw = generate_apache_log()
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
