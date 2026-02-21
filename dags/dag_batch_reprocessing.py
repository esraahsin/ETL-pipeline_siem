"""Airflow DAG — Batch reprocessing (daily).

Triggers the PySpark batch job to reprocess raw logs stored in MinIO for
the previous day and re-index them in Elasticsearch.
"""

from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

default_args = {
    "owner": "siem-team",
    "depends_on_past": False,
    "email_on_failure": False,
    "email_on_retry": False,
    "retries": 3,
    "retry_delay": timedelta(minutes=10),
}

dag = DAG(
    dag_id="dag_batch_reprocessing",
    description="Daily Spark batch reprocessing of raw logs from MinIO",
    schedule_interval="@daily",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["siem", "reprocessing"],
)

reprocess = BashOperator(
    task_id="spark_batch_reprocess",
    bash_command=(
        "spark-submit "
        "--master {{ var.value.get('SPARK_MASTER', 'local[*]') }} "
        "/opt/siem/spark_jobs/batch_job.py "
        "{{ (execution_date - macros.timedelta(days=1)).strftime('%Y-%m-%d') }}"
    ),
    dag=dag,
)

verify = BashOperator(
    task_id="verify_es_index",
    bash_command=(
        "curl -sf http://${ELASTICSEARCH_HOST:-localhost}:${ELASTICSEARCH_PORT:-9200}/"
        "_cat/indices/siem-*?v || echo 'ES check failed'"
    ),
    dag=dag,
)

reprocess >> verify
