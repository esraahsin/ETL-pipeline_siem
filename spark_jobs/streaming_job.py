"""Spark Structured Streaming job — reads from Kafka topics, applies T1-T4
transformations, writes raw logs to MinIO, and writes enriched events to Elasticsearch.
"""

import json
import json as _json
import os
from datetime import datetime, timezone

import structlog
from elasticsearch import Elasticsearch
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

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:29092")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET_RAW = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
MINIO_BUCKET_PROCESSED = os.getenv("MINIO_BUCKET_PROCESSED", "siem-processed-logs")

TOPICS = ["firewall-logs", "web-logs", "windows-logs", "ids-logs"]


def safe_float(x):
    try:
        return float(x)
    except Exception:
        return None


def _parse_and_enrich(raw: str, source_type: str) -> str:
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

        # Fix geo types
        geo = event.get("geo", {}).get("location", {})
        lat = safe_float(geo.get("lat"))
        lon = safe_float(geo.get("lon"))
        if lat is None or lon is None:
            event.pop("geo", None)
        else:
            event["geo"]["location"]["lat"] = lat
            event["geo"]["location"]["lon"] = lon

        event["_id"] = compute_event_hash(event)
        return json.dumps(event)

    except Exception as e:
        print(f"[parse error] source_type={source_type} error={e}")
        return None


parse_udf = udf(_parse_and_enrich, StringType())

_MESSAGE_SCHEMA = StructType([
    StructField("id", StringType()),
    StructField("timestamp", StringType()),
    StructField("source_type", StringType()),
    StructField("raw", StringType()),
])


def _get_minio_client():
    """Return a boto3 S3 client pointed at MinIO."""
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


def _ensure_bucket(s3_client, bucket: str):
    """Create the bucket if it does not already exist."""
    try:
        s3_client.head_bucket(Bucket=bucket)
    except Exception:
        try:
            s3_client.create_bucket(Bucket=bucket)
            print(f"[MinIO] Created bucket: {bucket}")
        except Exception as e:
            print(f"[MinIO] Could not create bucket {bucket}: {e}")


def _save_raw_to_minio(rows, source_type: str, batch_id: int):
    """Save raw log lines for *source_type* to MinIO as a JSON-lines file.

    Path convention: siem-raw-logs/{source_type}/{YYYY-MM-DD}/batch_{batch_id}.jsonl
    """
    if not rows:
        return

    s3 = _get_minio_client()
    _ensure_bucket(s3, MINIO_BUCKET_RAW)

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{source_type}/{date_str}/batch_{batch_id}.jsonl"

    lines = []
    for row in rows:
        try:
            entry = {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "source_type": row["source_type"],
                "raw": row["raw"],
            }
            lines.append(json.dumps(entry))
        except Exception as e:
            print(f"[MinIO raw] Serialization error: {e}")

    if not lines:
        return

    body = "\n".join(lines).encode("utf-8")
    try:
        s3.put_object(Bucket=MINIO_BUCKET_RAW, Key=key, Body=body)
        print(f"[MinIO] Saved {len(lines)} raw records → s3://{MINIO_BUCKET_RAW}/{key}")
    except Exception as e:
        print(f"[MinIO] Failed to write raw logs: {e}")


def _save_processed_to_minio(rows, source_type: str, batch_id: int):
    """Save processed (ECS) events for *source_type* to MinIO as JSON-lines.

    Path convention: siem-processed-logs/{source_type}/{YYYY-MM-DD}/batch_{batch_id}.jsonl
    """
    if not rows:
        return

    s3 = _get_minio_client()
    _ensure_bucket(s3, MINIO_BUCKET_PROCESSED)

    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{source_type}/{date_str}/batch_{batch_id}.jsonl"

    lines = []
    for row in rows:
        ecs = row.get("ecs_event")
        if ecs:
            lines.append(ecs if isinstance(ecs, str) else json.dumps(ecs))

    if not lines:
        return

    body = "\n".join(lines).encode("utf-8")
    try:
        s3.put_object(Bucket=MINIO_BUCKET_PROCESSED, Key=key, Body=body)
        print(f"[MinIO] Saved {len(lines)} processed records → s3://{MINIO_BUCKET_PROCESSED}/{key}")
    except Exception as e:
        print(f"[MinIO] Failed to write processed logs: {e}")


def write_batch(batch_df, batch_id):
    """foreachBatch handler: saves raw logs to MinIO, enriched events to ES + MinIO."""
    es = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")
    rows = batch_df.collect()

    if not rows:
        return

    # ── Group rows by source_type for MinIO writes ──────────────────────────
    raw_by_source: dict = {}
    processed_by_source: dict = {}

    for row in rows:
        r = row.asDict()

        st = r.get("source_type", "unknown")
        raw_by_source.setdefault(st, []).append(r)

        ecs_str = r.get("ecs_event")
        if ecs_str:
            processed_by_source.setdefault(st, []).append(r)

    # ── Write raw logs to MinIO ──────────────────────────────────────────────
    for source_type, source_rows in raw_by_source.items():
        try:
            _save_raw_to_minio(source_rows, source_type, batch_id)
        except Exception as e:
            print(f"[MinIO raw write error] source={source_type} batch={batch_id} error={e}")

    # ── Write processed events to MinIO ─────────────────────────────────────
    for source_type, source_rows in processed_by_source.items():
        try:
            _save_processed_to_minio(source_rows, source_type, batch_id)
        except Exception as e:
            print(f"[MinIO processed write error] source={source_type} batch={batch_id} error={e}")

    # ── Index enriched events into Elasticsearch ─────────────────────────────
    es_errors = 0
    for row in rows:
        r = row.asDict()
        ecs_str = r.get("ecs_event")
        if not ecs_str:
            continue
        try:
            doc = _json.loads(ecs_str)
            index = f"siem-{doc.get('source_type', 'unknown')}"
            doc_id = doc.pop("_id", None)
            es.index(index=index, id=doc_id, document=doc)
        except Exception as e:
            es_errors += 1
            print(f"[ES write error] {e}")

    print(
        f"[batch {batch_id}] "
        f"total={len(rows)} "
        f"processed={sum(len(v) for v in processed_by_source.values())} "
        f"es_errors={es_errors}"
    )


def create_spark_session() -> SparkSession:
    return (
        SparkSession.builder
        .appName(os.getenv("SPARK_APP_NAME", "SIEM-ETL-Streaming"))
        .config(
            "spark.jars.packages",
            "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0",
        )
        .getOrCreate()
    )


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

    parsed_df = raw_df.select(
        from_json(col("value").cast("string"), _MESSAGE_SCHEMA).alias("msg"),
        col("topic"),
    ).select("msg.*", "topic")

    enriched_df = parsed_df.withColumn(
        "ecs_event",
        parse_udf(col("raw"), col("source_type")),
    )
    # NOTE: do NOT filter out null ecs_event here so we can still save raw logs
    # even for events that fail parsing.

    query = (
        enriched_df.writeStream
        .foreachBatch(write_batch)
        .option("checkpointLocation", "/tmp/siem-es-checkpoint")
        .outputMode("append")
        .start()
    )

    log.info("streaming_job_started", topics=TOPICS)
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    run()