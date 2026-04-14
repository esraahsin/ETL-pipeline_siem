"""Spark Structured Streaming job — reads from Kafka topics, applies T1-T4
transformations, and writes results to Elasticsearch.
"""

import json
import json as _json
import os

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

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ES_HOST = os.getenv("ELASTICSEARCH_HOST", "localhost")
ES_PORT = os.getenv("ELASTICSEARCH_PORT", "9200")

TOPICS = ["firewall-logs", "web-logs", "windows-logs", "ids-logs"]


def _parse_and_enrich(raw: str, source_type: str) -> str:
    import json as _json
    # Si raw est encore une string JSON imbriquée, la parser d'abord
    try:
        raw_data = _json.loads(raw) if isinstance(raw, str) else raw
        # Pour windows et ids, le raw lui-même peut être un dict sérialisé
        if source_type in ("windows", "ids") and isinstance(raw_data, dict):
            raw = raw_data  # passer le dict directement
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
        return json.dumps(event)
    except Exception:
        return None


parse_udf = udf(_parse_and_enrich, StringType())

_MESSAGE_SCHEMA = StructType([
    StructField("id", StringType()),
    StructField("timestamp", StringType()),
    StructField("source_type", StringType()),
    StructField("raw", StringType()),
])


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

def write_to_es(batch_df, batch_id):
    import boto3
    from botocore.client import Config

    es = Elasticsearch(f"http://{ES_HOST}:{ES_PORT}")

    s3 = boto3.client(
        "s3",
        endpoint_url="http://minio:9000",
        aws_access_key_id="minioadmin",
        aws_secret_access_key="minioadmin",
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )

    # Create buckets if they don't exist
    for bucket in ["siem-raw-logs", "siem-processed-logs"]:
        try:
            s3.head_bucket(Bucket=bucket)
        except Exception:
            s3.create_bucket(Bucket=bucket)

    rows = batch_df.collect()
    for row in rows:
        try:
            doc = _json.loads(row["ecs_event"])

            # 1. Write to Elasticsearch
            index = f"siem-{doc.get('source_type', 'unknown')}"
            doc_id = doc.pop("_id", None)
            es.index(index=index, id=doc_id, document=doc)

            # 2. Write to MinIO
            source_type = doc.get("source_type", "unknown")
            date_str = doc.get("@timestamp", "")[:10]
            key = f"{source_type}/{date_str}/{doc_id}.json"
            s3.put_object(
                Bucket="siem-raw-logs",
                Key=key,
                Body=_json.dumps(doc).encode("utf-8"),
            )
        except Exception as e:
            print(f"[write error] {e}")
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
    ).filter(col("ecs_event").isNotNull())

    es_query = (
        enriched_df.writeStream
        .foreachBatch(write_to_es)
        .option("checkpointLocation", "/tmp/siem-es-checkpoint")
        .outputMode("append")
        .start()
    )

    log.info("streaming_job_started", topics=TOPICS)
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    run()