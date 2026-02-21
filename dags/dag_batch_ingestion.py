"""Airflow DAG — Batch ingestion (hourly).

Reads historical log files from MinIO and publishes them to the appropriate
Kafka topics so the streaming job can reprocess them.
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
    """Publish logs for *source_type* to the corresponding Kafka topic."""
    import json
    import os

    from kafka import KafkaProducer
    from minio import Minio

    execution_date = context["execution_date"].strftime("%Y-%m-%d")
    bucket = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
    kafka_bs = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    topic_map = {
        "firewall": "firewall-logs",
        "webserver": "web-logs",
        "windows": "windows-logs",
        "ids": "ids-logs",
    }

    minio_client = Minio(
        os.getenv("MINIO_ENDPOINT", "localhost:9000"),
        access_key=os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
        secret_key=os.getenv("MINIO_SECRET_KEY", "minioadmin"),
        secure=False,
    )
    producer = KafkaProducer(
        bootstrap_servers=kafka_bs,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        retries=3,
    )

    prefix = f"{source_type}/{execution_date}/"
    objects = minio_client.list_objects(bucket, prefix=prefix, recursive=True)
    count = 0
    for obj in objects:
        data = minio_client.get_object(bucket, obj.object_name).read()
        for line in data.decode("utf-8").splitlines():
            if line.strip():
                producer.send(topic_map[source_type], value={"raw": line, "source_type": source_type})
                count += 1
    producer.flush()
    producer.close()
    print(f"[{source_type}] Ingested {count} records for {execution_date}")


for _source in ("firewall", "webserver", "windows", "ids"):
    PythonOperator(
        task_id=f"ingest_{_source}_logs",
        python_callable=_ingest_source,
        op_kwargs={"source_type": _source},
        dag=dag,
    )
