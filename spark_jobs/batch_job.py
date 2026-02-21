"""Spark batch job — reprocesses historical raw logs stored in MinIO (S3)
and re-indexes them in Elasticsearch.

Usage:
    spark-submit spark_jobs/batch_job.py [--date YYYY-MM-DD]
"""

import json
import os
import sys
from datetime import datetime, timezone

import structlog
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, udf
from pyspark.sql.types import StringType

from spark_jobs.enrichment.geoip_enricher import enrich_with_geoip
from spark_jobs.enrichment.severity_scorer import enrich_with_severity
from spark_jobs.parsers.firewall_parser import parse_firewall_log
from spark_jobs.parsers.ids_parser import parse_ids_log
from spark_jobs.parsers.webserver_parser import parse_webserver_log
from spark_jobs.parsers.windows_parser import parse_windows_log
from spark_jobs.quality.deduplicator import compute_event_hash

log = structlog.get_logger(component="batch_job")

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET_RAW = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
MINIO_BUCKET_PROCESSED = os.getenv("MINIO_BUCKET_PROCESSED", "siem-processed-logs")


def _parse_and_enrich(raw: str, source_type: str) -> str:
    """Parse, enrich and serialize a single raw log message to JSON."""
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
        event = parser(raw) if isinstance(raw, str) else parser(json.loads(raw))
        if event is None:
            return None
        event = enrich_with_geoip(event)
        event = enrich_with_severity(event)
        event["_id"] = compute_event_hash(event)
        return json.dumps(event)
    except Exception as exc:
        log.error("parse_error", source_type=source_type, error=str(exc))
        return None


parse_udf = udf(_parse_and_enrich, StringType())


def create_spark_session() -> SparkSession:
    """Build and return a configured SparkSession for batch processing."""
    return (
        SparkSession.builder
        .appName(os.getenv("SPARK_APP_NAME", "SIEM-ETL-Batch"))
        .config("spark.jars.packages",
                "org.elasticsearch:elasticsearch-spark-30_2.12:8.11.0")
        .config("spark.hadoop.fs.s3a.endpoint", f"http://{MINIO_ENDPOINT}")
        .config("spark.hadoop.fs.s3a.access.key", MINIO_ACCESS_KEY)
        .config("spark.hadoop.fs.s3a.secret.key", MINIO_SECRET_KEY)
        .config("spark.hadoop.fs.s3a.path.style.access", "true")
        .getOrCreate()
    )


def run(date_str: str = None):
    """Reprocess raw logs for a given date partition.

    Args:
        date_str: Date in YYYY-MM-DD format. Defaults to today (UTC).
    """
    if date_str is None:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    spark = create_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    for source_type in ("firewall", "webserver", "windows", "ids"):
        input_path = f"s3a://{MINIO_BUCKET_RAW}/{source_type}/{date_str}/"
        output_path = f"s3a://{MINIO_BUCKET_PROCESSED}/{source_type}/{date_str}/"

        log.info("batch_processing_start", source=source_type, date=date_str)

        try:
            raw_df = spark.read.parquet(input_path)
        except Exception as exc:
            log.warning("no_data_for_partition", source=source_type, path=input_path, error=str(exc))
            continue

        enriched_df = raw_df.withColumn(
            "ecs_event",
            parse_udf(col("raw"), col("source_type")),
        ).filter(col("ecs_event").isNotNull())

        # Write processed results to MinIO
        enriched_df.write.mode("overwrite").parquet(output_path)

        # Index into Elasticsearch
        enriched_df.write.format("es") \
            .option("es.nodes", ES_HOST) \
            .option("es.port", ES_PORT) \
            .option("es.resource", f"siem-{source_type}-{date_str.replace('-', '.')}") \
            .option("es.mapping.id", "_id") \
            .mode("append") \
            .save()

        log.info("batch_processing_done", source=source_type, date=date_str)

    spark.stop()


if __name__ == "__main__":
    date_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run(date_arg)
