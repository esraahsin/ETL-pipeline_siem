"""Airflow DAG — Batch ingestion (hourly).

Reads raw log JSONL files from MinIO (written by the streaming job) and
re-publishes them to the appropriate Kafka topics for reprocessing.

File convention in MinIO:
  siem-raw-logs/{source_type}/{YYYY-MM-DD}/batch_*.jsonl
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator

default_args = {
    "owner": "siem-team",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 3,
    "retry_delay": timedelta(minutes=5),
}

dag = DAG(
    dag_id="dag_batch_ingestion",
    description="Hourly batch ingestion of log files from MinIO into Kafka",
    schedule_interval="@hourly",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["siem", "ingestion"],
)


def _ingest_source(source_type: str, **context):
    """Re-publish JSONL raw logs for *source_type* back to the Kafka topic."""
    import json
    import os

    import boto3
    from botocore.client import Config
    from kafka import KafkaProducer

    execution_date = context["execution_date"].strftime("%Y-%m-%d")
    bucket = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
    kafka_bs = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    minio_endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")

    topic_map = {
        "firewall": "firewall-logs",
        "webserver": "web-logs",
        "windows": "windows-logs",
        "ids": "ids-logs",
    }

    s3 = boto3.client(
        "s3",
        endpoint_url=f"http://{minio_endpoint}",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )

    producer = KafkaProducer(
        bootstrap_servers=kafka_bs,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=3,
    )

    prefix = f"{source_type}/{execution_date}/"
    topic = topic_map[source_type]
    count = 0

    try:
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if not key.endswith(".jsonl"):
                    continue
                body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
                for line in body.decode("utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        producer.send(topic, value=record)
                        count += 1
                    except json.JSONDecodeError as e:
                        print(f"[{source_type}] Skipping invalid JSON line: {e}")

        producer.flush()
    finally:
        producer.close()

    print(f"[{source_type}] Re-ingested {count} records for {execution_date} → {topic}")


for _source in ("firewall", "webserver", "windows", "ids"):
    PythonOperator(
        task_id=f"ingest_{_source}_logs",
        python_callable=_ingest_source,
        op_kwargs={"source_type": _source},
        dag=dag,
    )