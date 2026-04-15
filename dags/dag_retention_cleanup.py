"""Airflow DAG — Retention cleanup (weekly).

Deletes Elasticsearch indices and MinIO objects that exceed the configured
retention period (ES: 30 days, MinIO raw: 365 days).
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator
import os
import boto3
from botocore.client import Config
from datetime import timezone

default_args = {
    "owner": "siem-team",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 2,
    "retry_delay": timedelta(minutes=10),
}

dag = DAG(
    dag_id="dag_retention_cleanup",
    description="Weekly cleanup of expired ES indices and MinIO raw logs",
    schedule_interval="@weekly",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["siem", "retention"],
)

ES_RETENTION_DAYS = 30
MINIO_RETENTION_DAYS = 365


def _cleanup_elasticsearch(**context):
    """Delete Elasticsearch SIEM indices older than ES_RETENTION_DAYS."""
    import os

    import requests

    es_host = os.getenv("ELASTICSEARCH_HOST", "localhost")
    es_port = os.getenv("ELASTICSEARCH_PORT", "9200")
    cutoff = context["execution_date"] - timedelta(days=ES_RETENTION_DAYS)

    resp = requests.get(f"http://{es_host}:{es_port}/_cat/indices/siem-*?h=index&format=json", timeout=10)
    resp.raise_for_status()
    indices = [i["index"] for i in resp.json()]

    deleted = []
    for index in indices:
        # Index naming convention: siem-<source>-YYYY.MM.DD
        parts = index.rsplit("-", 1)
        if len(parts) == 2:
            try:
                idx_date = datetime.strptime(parts[1], "%Y.%m.%d")
                if idx_date < cutoff:
                    del_resp = requests.delete(f"http://{es_host}:{es_port}/{index}", timeout=10)
                    del_resp.raise_for_status()
                    deleted.append(index)
            except ValueError:
                continue

    print(f"Deleted {len(deleted)} expired ES indices: {deleted}")

def _cleanup_minio(**context):
   
    cutoff = context["execution_date"].replace(tzinfo=timezone.utc) - timedelta(days=MINIO_RETENTION_DAYS)
    
    s3 = boto3.client(
        "s3",
        endpoint_url=f"http://{os.getenv('MINIO_ENDPOINT', 'minio:9000')}",
        aws_access_key_id=os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
        aws_secret_access_key=os.getenv("MINIO_SECRET_KEY", "minioadmin"),
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )
    bucket = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
    
    paginator = s3.get_paginator("list_objects_v2")
    deleted = 0
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            if obj["LastModified"].replace(tzinfo=timezone.utc) < cutoff:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
                deleted += 1
    print(f"Deleted {deleted} expired MinIO objects.")

cleanup_es = PythonOperator(
    task_id="cleanup_elasticsearch_indices",
    python_callable=_cleanup_elasticsearch,
    dag=dag,
)

cleanup_minio = PythonOperator(
    task_id="cleanup_minio_raw_logs",
    python_callable=_cleanup_minio,
    dag=dag,
)

cleanup_es >> cleanup_minio
