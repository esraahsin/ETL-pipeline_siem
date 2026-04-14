"""
Spark Structured Streaming job — reads from Kafka topics, applies T1-T4
transformations, and writes results to Elasticsearch + MinIO.
"""

import json as _json
import os

import structlog
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, udf
from pyspark.sql.types import StringType, StructField, StructType

from spark_jobs.enrichment.geoip_enricher import enrich_with_geoip
from spark_jobs.enrichment.severity_scorer import enrich_with_severity
from spark_jobs.parsers.firewall_parser import parse_firewall_log
from spark_jobs.parsers.ids_parser import parse_ids_log
from spark_jobs.parsers.webserver_parser import parse_webserver_log
from spark_jobs.parsers.windows_parser import parse_windows_log
from spark_jobs.quality.deduplicator import compute_event_hash

log = structlog.get_logger(component="streaming_job")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET_RAW = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
MINIO_BUCKET_PROCESSED = os.getenv("MINIO_BUCKET_PROCESSED", "siem-processed-logs")

TOPICS = ["firewall-logs", "web-logs", "windows-logs", "ids-logs"]

# ============================
# Parsing + Enrichment UDF
# ============================

def _parse_and_enrich(raw: str, source_type: str) -> str:
    """Parse a raw log string, enrich it, and return a JSON string."""
    import json as _j

    # For structured sources (windows, ids), the raw field may itself be JSON
    try:
        raw_data = _j.loads(raw) if isinstance(raw, str) else raw
        if source_type in ("windows", "ids") and isinstance(raw_data, dict):
            raw = raw_data
    except Exception:
        pass

    parsers = {
        "firewall": parse_firewall_log,
        "webserver": parse_webserver_log,
        "windows": parse_windows_log,
        "ids": parse_ids_log,
    }

    parser = parsers.get(source_type)
    if parser is None:
        return None

    try:
        event = parser(raw)
        if event is None:
            return None

        event = enrich_with_geoip(event)
        event = enrich_with_severity(event)
        event["_id"] = compute_event_hash(event)

        return _j.dumps(event)
    except Exception as exc:
        log.error("parse_error", source_type=source_type, error=str(exc))
        return None


parse_udf = udf(_parse_and_enrich, StringType())

_MESSAGE_SCHEMA = StructType([
    StructField("id", StringType()),
    StructField("timestamp", StringType()),
    StructField("source_type", StringType()),
    StructField("raw", StringType()),
])


# ============================
# Spark Session
# ============================

def create_spark_session() -> SparkSession:
    return (
        SparkSession.builder
        .appName(os.getenv("SPARK_APP_NAME", "SIEM-ETL-Streaming"))
        .config(
            "spark.jars.packages",
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,"
            "org.elasticsearch:elasticsearch-spark-30_2.12:8.11.0",
        )
        .getOrCreate()
    )


# ============================
# MinIO S3 client (lazy, per-executor)
# ============================

def _make_s3_client():
    """Build a boto3 S3 client pointing at MinIO."""
    import boto3
    from botocore.client import Config

    return boto3.client(
        "s3",
        endpoint_url=f"http://{MINIO_ENDPOINT}",
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )


def _ensure_buckets(s3):
    """Create MinIO buckets if they do not already exist."""
    for bucket in (MINIO_BUCKET_RAW, MINIO_BUCKET_PROCESSED):
        try:
            s3.head_bucket(Bucket=bucket)
        except Exception:
            try:
                s3.create_bucket(Bucket=bucket)
                log.info("bucket_created", bucket=bucket)
            except Exception as exc:
                log.warning("bucket_create_failed", bucket=bucket, error=str(exc))


# ============================
# foreachBatch sink
# ============================

def write_to_es(batch_df, batch_id):
    """
    Persist each micro-batch to Elasticsearch and MinIO.

    Raw original logs  → s3://siem-raw-logs/<source>/<date>/<id>.json
    Processed ECS docs → s3://siem-processed-logs/processed/<source>/<date>/<id>.json
    ECS document       → Elasticsearch index siem-<source_type>
    """
    from elasticsearch import Elasticsearch

    if batch_df.rdd.isEmpty():
        return

    es = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")
    s3 = _make_s3_client()
    _ensure_buckets(s3)

    rows = batch_df.collect()

    for row in rows:
        try:
            # ----------------------------------------------------------------
            # 1. Parse the enriched ECS JSON string produced by the UDF
            # ----------------------------------------------------------------
            ecs_json = row["ecs_event"]           # Spark Row — use [] not .get()
            if not ecs_json:
                continue

            doc = _json.loads(ecs_json)

            # ----------------------------------------------------------------
            # 2. Recover the original raw log safely from the Spark Row
            # ----------------------------------------------------------------
            try:
                raw_original = row["raw"] or ""
            except Exception:
                raw_original = ""

            source_type = doc.get("source_type", "unknown")
            date_str = (doc.get("@timestamp") or "")[:10] or "unknown-date"
            doc_id = doc.pop("_id", None)        # remove before indexing

            # ----------------------------------------------------------------
            # 3. Write to Elasticsearch
            # ----------------------------------------------------------------
            index_name = f"siem-{source_type}"
            try:
                es.index(index=index_name, id=doc_id, document=doc)
            except Exception as exc:
                log.error("es_index_error", index=index_name, error=str(exc))

            # ----------------------------------------------------------------
            # 4. Write RAW log to MinIO  (siem-raw-logs bucket)
            # ----------------------------------------------------------------
            raw_key = f"{source_type}/{date_str}/{doc_id}.json"
            raw_payload = _json.dumps({
                "id": doc_id,
                "source_type": source_type,
                "raw": raw_original,
            }).encode("utf-8")
            try:
                s3.put_object(Bucket=MINIO_BUCKET_RAW, Key=raw_key, Body=raw_payload)
            except Exception as exc:
                log.error("minio_raw_write_error", key=raw_key, error=str(exc))

            # ----------------------------------------------------------------
            # 5. Write PROCESSED ECS doc to MinIO  (siem-processed-logs bucket)
            # ----------------------------------------------------------------
            processed_key = f"processed/{source_type}/{date_str}/{doc_id}.json"
            processed_payload = _json.dumps(doc).encode("utf-8")
            try:
                s3.put_object(
                    Bucket=MINIO_BUCKET_PROCESSED,
                    Key=processed_key,
                    Body=processed_payload,
                )
            except Exception as exc:
                log.error("minio_processed_write_error", key=processed_key, error=str(exc))

        except Exception as exc:
            log.error("write_batch_row_error", batch_id=batch_id, error=str(exc))


# ============================
# Main Streaming Job
# ============================

def run():
    spark = create_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    raw_df = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", ",".join(TOPICS))
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .load()
    )

    parsed_df = (
        raw_df
        .select(
            from_json(col("value").cast("string"), _MESSAGE_SCHEMA).alias("msg"),
            col("topic"),
        )
        .select("msg.*", "topic")
    )

    enriched_df = (
        parsed_df
        .withColumn("ecs_event", parse_udf(col("raw"), col("source_type")))
        .filter(col("ecs_event").isNotNull())
    )

    query = (
        enriched_df
        .writeStream
        .foreachBatch(write_to_es)
        .option("checkpointLocation", "/tmp/siem-es-checkpoint")
        .outputMode("append")
        .start()
    )

    log.info("streaming_job_started", topics=TOPICS)
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    run()