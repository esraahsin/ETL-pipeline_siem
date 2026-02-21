"""Spark Structured Streaming job — reads from Kafka topics, applies T1–T4
transformations, and writes results to Elasticsearch and MinIO (S3).

Usage:
    spark-submit spark_jobs/streaming_job.py
"""

import json
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
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET_PROCESSED", "siem-processed-logs")

TOPICS = ["firewall-logs", "web-logs", "windows-logs", "ids-logs"]

# ---- UDFs ----------------------------------------------------------------


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
        event = parser(raw)
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

# ---- Kafka message schema ------------------------------------------------

_MESSAGE_SCHEMA = StructType([
    StructField("id", StringType()),
    StructField("timestamp", StringType()),
    StructField("source_type", StringType()),
    StructField("raw", StringType()),
])


def create_spark_session() -> SparkSession:
    """Build and return a configured SparkSession."""
    return (
        SparkSession.builder
        .appName(os.getenv("SPARK_APP_NAME", "SIEM-ETL-Streaming"))
        .config("spark.jars.packages",
                "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.0,"
                "org.elasticsearch:elasticsearch-spark-30_2.12:8.11.0")
        .config("spark.hadoop.fs.s3a.endpoint", f"http://{MINIO_ENDPOINT}")
        .config("spark.hadoop.fs.s3a.access.key", MINIO_ACCESS_KEY)
        .config("spark.hadoop.fs.s3a.secret.key", MINIO_SECRET_KEY)
        .config("spark.hadoop.fs.s3a.path.style.access", "true")
        .getOrCreate()
    )


def run():
    """Entry point for the Spark Structured Streaming job."""
    spark = create_spark_session()
    spark.sparkContext.setLogLevel("WARN")

    # Read from all 4 Kafka topics
    raw_df = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP)
        .option("subscribe", ",".join(TOPICS))
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .load()
    )

    # Deserialize the Kafka message value (JSON envelope)
    parsed_df = raw_df.select(
        from_json(col("value").cast("string"), _MESSAGE_SCHEMA).alias("msg"),
        col("topic"),
    ).select("msg.*", "topic")

    # Apply T1-T4 transformations via UDF
    enriched_df = parsed_df.withColumn(
        "ecs_event",
        parse_udf(col("raw"), col("source_type")),
    ).filter(col("ecs_event").isNotNull())

    # Write to Elasticsearch (SIEM storage)
    es_query = (
        enriched_df.writeStream
        .format("es")
        .option("es.nodes", ES_HOST)
        .option("es.port", ES_PORT)
        .option("es.resource", "siem-{source_type}")
        .option("es.mapping.id", "_id")
        .option("checkpointLocation", "/tmp/siem-es-checkpoint")
        .outputMode("append")
        .start()
    )

    # Write raw logs to MinIO as Parquet (Data Lake)
    minio_query = (
        parsed_df.writeStream
        .format("parquet")
        .option("path", f"s3a://{MINIO_BUCKET}/raw/")
        .option("checkpointLocation", "/tmp/siem-minio-checkpoint")
        .partitionBy("source_type")
        .outputMode("append")
        .start()
    )

    log.info("streaming_job_started", topics=TOPICS)
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    run()
