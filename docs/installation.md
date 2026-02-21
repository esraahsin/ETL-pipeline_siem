# Installation Guide — SIEM ETL Pipeline

This guide covers the complete installation and deployment of the SIEM ETL Pipeline
on a local machine using Docker Compose.

---

## Prerequisites

| Tool | Minimum Version | Notes |
|---|---|---|
| Docker | 24.x | Required |
| Docker Compose | v2.20+ | Included with Docker Desktop |
| Python | 3.10+ | For generators and tests |
| Git | 2.x | To clone the repository |
| RAM | 8 GB | 16 GB recommended for full stack |
| Disk | 20 GB | For Docker images and log storage |

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/esraahsin/ETL-pipeline_siem.git
cd ETL-pipeline_siem
```

---

## Step 2 — Configure Environment Variables

Copy the example environment file and edit it for your environment:

```bash
cp .env.example .env
```

Key variables to review:

| Variable | Default | Description |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker address |
| `ELASTICSEARCH_HOST` | `localhost` | Elasticsearch host |
| `ELASTICSEARCH_PASSWORD` | `changeme` | Elasticsearch password |
| `MINIO_ACCESS_KEY` | `minioadmin` | MinIO access key |
| `MINIO_SECRET_KEY` | `minioadmin` | MinIO secret key |
| `MAXMIND_DB_PATH` | `/opt/geoip/GeoLite2-City.mmdb` | Path to MaxMind DB |

---

## Step 3 — Start the Infrastructure

```bash
docker-compose -f docker/docker-compose.yml up -d
```

Wait approximately 60 seconds for all services to become healthy:

```bash
docker-compose -f docker/docker-compose.yml ps
```

Expected output: all services in `running` or `healthy` state.

---

## Step 4 — Install Python Dependencies

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Step 5 — Create Kafka Topics

```bash
bash kafka/create_topics.sh
```

This creates the following topics:
- `firewall-logs`
- `web-logs`
- `windows-logs`
- `ids-logs`
- `siem-errors` (dead-letter queue)

---

## Step 6 — (Optional) Configure MaxMind GeoIP2

1. Register for a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
2. Download the **GeoLite2-City** database (`.mmdb` format)
3. Place it at the path configured in `MAXMIND_DB_PATH`

---

## Step 7 — Apply Elasticsearch Index Templates

```bash
curl -X PUT "http://localhost:9200/_index_template/siem-template" \
  -H "Content-Type: application/json" \
  -d @elasticsearch/index_templates/siem_template.json

curl -X PUT "http://localhost:9200/_ilm/policy/siem-ilm-policy" \
  -H "Content-Type: application/json" \
  -d @elasticsearch/ilm_policies/siem_ilm_policy.json
```

---

## Step 8 — Start Log Generators

Open 4 separate terminals (or run in background):

```bash
python generators/firewall_generator.py &
python generators/webserver_generator.py &
python generators/windows_generator.py &
python generators/ids_generator.py &
```

---

## Step 9 — Start the Spark Streaming Job

```bash
spark-submit \
  --master local[*] \
  --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,org.elasticsearch:elasticsearch-spark-30_2.12:8.11.0 \
  spark_jobs/streaming_job.py
```

---

## Step 10 — Access the Dashboards

| Service | URL | Credentials |
|---|---|---|
| **Kibana** (SIEM) | http://localhost:5601 | elastic / changeme |
| **Grafana** (Monitoring) | http://localhost:3000 | admin / admin |
| **Airflow** | http://localhost:8080 | airflow / airflow |
| **MinIO Console** | http://localhost:9001 | minioadmin / minioadmin |
| **Kafka UI** | http://localhost:8081 | — |

---

## Running Tests

```bash
# All unit tests (no infrastructure required)
pytest tests/ -v -k "not integration"

# All tests including integration (requires running infrastructure)
SIEM_INTEGRATION_TESTS=1 pytest tests/ -v
```

---

## Troubleshooting

### Elasticsearch fails to start
Increase the virtual memory limit on Linux:
```bash
sudo sysctl -w vm.max_map_count=262144
```

### Kafka connection refused
Ensure the `KAFKA_BOOTSTRAP_SERVERS` matches the advertised listener in `docker/docker-compose.yml`.

### Out of memory errors
Reduce Elasticsearch heap in `docker/docker-compose.yml`:
```yaml
ES_JAVA_OPTS: "-Xms256m -Xmx256m"
```
