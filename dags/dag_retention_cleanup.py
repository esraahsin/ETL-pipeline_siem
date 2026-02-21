"""Airflow DAG — Retention cleanup (weekly).

Deletes Elasticsearch indices and MinIO objects that exceed the configured
retention period (ES: 30 days, MinIO raw: 365 days).
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.python import PythonOperator

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
    """Delete MinIO raw log objects older than MINIO_RETENTION_DAYS."""
    import os
    from datetime import timezone

    from minio import Minio

    cutoff = context["execution_date"].replace(tzinfo=timezone.utc) - timedelta(days=MINIO_RETENTION_DAYS)
    client = Minio(
        os.getenv("MINIO_ENDPOINT", "localhost:9000"),
        access_key=os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("MINIO_SECRET_KEY", "minioadmin"),
        secure=False,
    )
    bucket = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
    objects = client.list_objects(bucket, recursive=True)
    deleted = 0
    for obj in objects:
        if obj.last_modified and obj.last_modified < cutoff:
            client.remove_object(bucket, obj.object_name)
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
