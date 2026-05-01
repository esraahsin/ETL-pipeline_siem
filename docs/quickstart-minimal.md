# Quickstart — Minimal SIEM Stack (Streaming + Kibana)

This guide deploys only the essentials: Kafka, Elasticsearch, Kibana, the four log generators, and the Spark streaming job. No Airflow, no batch processing, no MinIO.

```
Log Generators (×4)
      │  CEF / Apache / JSON / EveJSON
      ▼
  Kafka (4 topics)
      │
      ▼
Spark Streaming Job
  (parse → enrich → deduplicate)
      │
      ▼
Elasticsearch → Kibana (http://localhost:5601)
```

---

## Prerequisites

| Tool | Version |
|---|---|
| Docker | 24.x+ |
| Docker Compose | v2.20+ |
| RAM | 6 GB free minimum |

---

## Step 1 — Start the stack

```bash
docker compose -f docker/docker-compose.minimal.yml up -d
```

First startup takes 2–4 minutes because:
- Spark downloads the Kafka connector JAR (`spark-sql-kafka-0-10_2.12:3.5.0`)
- Python containers install their dependencies
- Elasticsearch performs its initial setup

Watch the streaming job come online:

```bash
docker logs -f siem-spark-streaming
```

You should see lines like:

```
[batch 0] total=40 processed=40 es_errors=0
[batch 1] total=40 processed=40 es_errors=0
```

---

## Step 2 — Open Kibana and create a Data View

1. Open **http://localhost:5601** in your browser.
2. Click the hamburger menu (☰) → **Stack Management** → **Data Views**.
3. Click **Create data view**.
4. Set **Name** to `SIEM Logs` and **Index pattern** to `siem-*`.
5. Set **Timestamp field** to `@timestamp`.
6. Click **Save data view to Kibana**.

---

## Step 3 — Explore live logs

1. Click ☰ → **Discover**.
2. Select the **SIEM Logs** data view from the dropdown.
3. Set the time range to **Last 15 minutes**.

You will see a live stream of enriched security events from all four sources (firewall, webserver, windows, IDS) flowing in every second.

Useful fields to add as columns: `source_type`, `source.ip`, `destination.ip`, `event.action`, `event.severity`.

---

## Useful commands

```bash
# Check all services are running
docker compose -f docker/docker-compose.minimal.yml ps

# Stream logs from the Spark job
docker logs -f siem-spark-streaming

# Stream logs from a generator
docker logs -f siem-generator-firewall

# Stop everything and remove containers
docker compose -f docker/docker-compose.minimal.yml down

# Stop and also delete Elasticsearch data
docker compose -f docker/docker-compose.minimal.yml down -v
```

---

## Service URLs

| Service | URL |
|---|---|
| **Kibana** | http://localhost:5601 |
| **Elasticsearch** | http://localhost:9200 |
| **Kafka** (external) | localhost:9092 |

---

## Notes

- **GeoIP enrichment** uses the bundled `geoip/GeoLite2-City.mmdb`. IP geolocation data will appear in the `source.geo` and `destination.geo` fields in Kibana.
- **Raw log persistence** (MinIO) is disabled in this minimal setup. The streaming job will log a connection warning but will continue indexing into Elasticsearch normally.
- **Spark checkpoint** is stored in `/tmp/siem-es-checkpoint` inside the `siem-spark-streaming` container. It is reset on container restart, which is fine for a dev/demo deployment.
- If `siem-spark-streaming` exits on first start (Kafka or ES not yet ready), Docker will automatically restart it. It stabilizes within about 60 seconds.
