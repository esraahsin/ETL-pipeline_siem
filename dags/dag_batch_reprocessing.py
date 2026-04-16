# dags/dag_batch_reprocessing.py
from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator

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


def _reprocess(**context):
    import os, json, boto3
    from datetime import timedelta        

    from botocore.client import Config
    from elasticsearch import Elasticsearch

    date_str = (context["execution_date"] - timedelta(days=1)).strftime("%Y-%m-%d")

    minio_endpoint = os.getenv("MINIO_ENDPOINT", "minio:9000")
    access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
    secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
    bucket_raw = os.getenv("MINIO_BUCKET_RAW", "siem-raw-logs")
    es_host = os.getenv("ELASTICSEARCH_HOST", "elasticsearch")
    es_port = os.getenv("ELASTICSEARCH_PORT", "9200")

    s3 = boto3.client(
        "s3",
        endpoint_url=f"http://{minio_endpoint}",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        config=Config(signature_version="s3v4"),
        region_name="us-east-1",
    )
    es = Elasticsearch(f"http://{es_host}:{es_port}")

    from spark_jobs.parsers.firewall_parser import parse_firewall_log
    from spark_jobs.parsers.webserver_parser import parse_webserver_log
    from spark_jobs.parsers.windows_parser import parse_windows_log
    from spark_jobs.parsers.ids_parser import parse_ids_log
    from spark_jobs.enrichment.geoip_enricher import enrich_with_geoip
    from spark_jobs.enrichment.severity_scorer import enrich_with_severity
    from spark_jobs.quality.deduplicator import compute_event_hash

    parsers = {
        "firewall": parse_firewall_log,
        "webserver": parse_webserver_log,
        "windows": parse_windows_log,
        "ids": parse_ids_log,
    }

    for source_type, parser in parsers.items():
        prefix = f"{source_type}/{date_str}/"
        paginator = s3.get_paginator("list_objects_v2")
        count = 0
        for page in paginator.paginate(Bucket=bucket_raw, Prefix=prefix):
            for obj in page.get("Contents", []):
                if not obj["Key"].endswith(".jsonl"):
                    continue
                body = s3.get_object(Bucket=bucket_raw, Key=obj["Key"])["Body"].read()
                for line in body.decode("utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        raw = record.get("raw", "")
                        if isinstance(raw, dict):
                            import json as _json_inner
                            raw_input = _json_inner.dumps(raw)
                        else:
                            raw_input = raw
                        event = parser(raw_input)
                        if event is None:
                            continue
                        event = enrich_with_geoip(event)
                        event = enrich_with_severity(event)
                        doc_id = compute_event_hash(event)
                        index = f"siem-{source_type}"
                        es.index(index=index, id=doc_id, document=event)
                        count += 1
                    except Exception as e:
                        print(f"[{source_type}] Error: {e}")
        print(f"[{source_type}] Reprocessed {count} docs for {date_str}")


def _verify_es(**context):
    import os
    import requests
    es_host = os.getenv("ELASTICSEARCH_HOST", "elasticsearch")
    es_port = os.getenv("ELASTICSEARCH_PORT", "9200")
    resp = requests.get(f"http://{es_host}:{es_port}/_cat/indices/siem-*?v", timeout=10)
    print(resp.text)


reprocess = PythonOperator(
    task_id="spark_batch_reprocess",
    python_callable=_reprocess,
    dag=dag,
)

verify = PythonOperator(
    task_id="verify_es_index",
    python_callable=_verify_es,
    dag=dag,
)

reprocess >> verify