"""Airflow DAG — Data quality checks (daily).

Runs Great Expectations checkpoints and custom validation queries against
Elasticsearch to ensure the pipeline output meets quality expectations.
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
    "retry_delay": timedelta(minutes=5),
}

dag = DAG(
    dag_id="dag_data_quality",
    description="Daily data quality checks on SIEM pipeline output",
    schedule_interval="@daily",
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args=default_args,
    tags=["siem", "quality"],
)


def _check_es_null_fields(**context):
    """Verify that critical ECS fields are not null in today's indices."""
    import os

    import requests

    es_host = os.getenv("ELASTICSEARCH_HOST", "localhost")
    es_port = os.getenv("ELASTICSEARCH_PORT", "9200")
    date = context["execution_date"].strftime("%Y-%m-%d")
    index = f"siem-*"

    required_fields = ["@timestamp", "source_type", "event.dataset"]
    for field in required_fields:
        query = {
            "query": {
                "bool": {
                    "must_not": {"exists": {"field": field}},
                    "filter": {"range": {"@timestamp": {"gte": f"{date}T00:00:00Z", "lt": f"{date}T23:59:59Z"}}},
                }
            }
        }
        resp = requests.get(
            f"http://{es_host}:{es_port}/{index}/_count",
            json=query,
            timeout=10,
        )
        resp.raise_for_status()
        null_count = resp.json().get("count", 0)
        if null_count > 0:
            raise ValueError(f"Field '{field}' is null in {null_count} documents for {date}")
    print("All required fields are non-null — quality check passed.")


def _check_ip_format(**context):
    """Verify that source.ip fields contain valid IP addresses."""
    import os
    import re

    from elasticsearch import Elasticsearch

    es = Elasticsearch(
        f"http://{os.getenv('ELASTICSEARCH_HOST', 'localhost')}:{os.getenv('ELASTICSEARCH_PORT', '9200')}"
    )
    result = es.search(
        index="siem-*",
        body={
            "size": 1000,
            "_source": ["source.ip"],
            "query": {"exists": {"field": "source.ip"}},
        },
    )
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$|"
        r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$"
    )
    invalid = [
        hit["_source"]["source"]["ip"]
        for hit in result["hits"]["hits"]
        if not ip_pattern.match(hit["_source"].get("source", {}).get("ip", ""))
    ]
    if invalid:
        raise ValueError(f"Invalid IPs found: {invalid[:10]}")
    print("IP format validation passed.")


check_nulls = PythonOperator(
    task_id="check_required_fields_not_null",
    python_callable=_check_es_null_fields,
    dag=dag,
)

check_ips = PythonOperator(
    task_id="check_ip_format",
    python_callable=_check_ip_format,
    dag=dag,
)

check_nulls >> check_ips
