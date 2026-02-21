# Transformations Documentation — SIEM ETL Pipeline

This document describes the four transformation steps (T1–T4) applied to raw
security logs as they flow through the pipeline.

---

## Overview

Each raw log passes through the following transformation chain:

```
Raw Log (CEF / Apache / JSON / Eve JSON)
    │
    ▼  T1 — Parsing & Normalisation
ECS Event (normalised schema)
    │
    ▼  T2 — Enrichissement GeoIP
ECS Event + geo fields
    │
    ▼  T3 — Severity Scoring
ECS Event + event.severity
    │
    ▼  T4 — Deduplication & Quality Validation
Unique, validated ECS Event → Elasticsearch / MinIO
```

---

## T1 — Parsing & Normalisation vers ECS

**Module:** `spark_jobs/parsers/`

**Goal:** Convert heterogeneous raw log formats into the unified
[Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html).

### Parsers

| Parser | Input Format | Module |
|---|---|---|
| `firewall_parser.py` | Syslog/CEF (e.g., `CEF:0\|Vendor\|Product\|...`) | `parse_firewall_log()` |
| `webserver_parser.py` | Apache/Nginx combined access log | `parse_webserver_log()` |
| `windows_parser.py` | Windows Security Event (JSON) | `parse_windows_log()` |
| `ids_parser.py` | Suricata Eve JSON | `parse_ids_log()` |

### Key ECS Fields Extracted

| ECS Field | Description |
|---|---|
| `@timestamp` | Event timestamp in UTC ISO-8601 |
| `source.ip` | Source/client IP address |
| `destination.ip` | Destination IP address |
| `event.action` | Action performed (allow, deny, GET, etc.) |
| `event.dataset` | Source type (firewall, webserver, windows, ids) |
| `event.severity` | Initial severity (0–10) |
| `event.outcome` | success / failure |
| `source_type` | Metadata tag matching event.dataset |

### Error Handling

- Logs that fail to parse return `None` and are routed to the **dead-letter queue** (`siem-errors-*`).
- Each parser function is pure (no side effects) to allow unit testing without Spark.

---

## T2 — Enrichissement GeoIP & Threat Intelligence

**Module:** `spark_jobs/enrichment/geoip_enricher.py`

**Goal:** Add geographic location metadata to `source.geo` and `destination.geo` fields
using the [MaxMind GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database.

### Fields Added

| ECS Field | Description |
|---|---|
| `source.geo.country_iso_code` | 2-letter country code (e.g., `US`) |
| `source.geo.country_name` | Full country name |
| `source.geo.city_name` | City name |
| `source.geo.location.lat` | Latitude |
| `source.geo.location.lon` | Longitude |

The same fields are added under `destination.geo` when applicable.

### Fallback Behaviour

If the MaxMind database is unavailable or the IP cannot be resolved, the enrichment
step is skipped silently (the event passes through without geo fields).

---

## T3 — Calcul de Score de Sévérité

**Module:** `spark_jobs/enrichment/severity_scorer.py`

**Goal:** Compute a unified integer severity score (1–10) for each event, regardless of
the original source's severity representation.

### Scoring Algorithm

```
score = base_score[dataset]
      ± action_modifier
      blended with existing event.severity (if present)
      + http_status_penalty (webserver events)
```

| Dataset | Base Score |
|---|---|
| IDS (Suricata) | 7 |
| Windows Events | 5 |
| Firewall | 4 |
| Web Server | 3 |

**Action Modifiers:**
- `+2` for `failure`
- `+1` for `blocked`, `deny`, `drop`, `reject`
- `-1` for `allow`, `success`

**HTTP Status Penalty:** +2 for status codes in `{401, 403, 404, 500, 503}`.

The final score is clamped to [1, 10].

---

## T4 — Déduplication & Validation Qualité

**Module:** `spark_jobs/quality/deduplicator.py`

**Goal:** Prevent duplicate events from being indexed in Elasticsearch and validate
mandatory field constraints.

### Deduplication Strategy

A SHA-256 hash is computed over the stable fields:
- `@timestamp`
- `source_type`
- `event` (full sub-document)

The `ingest_timestamp` and metadata fields are deliberately excluded so that
re-ingested copies of the same log event are correctly identified as duplicates.

The hash is stored in the `_id` field and used as the Elasticsearch document ID,
ensuring idempotent indexing via `op_type=index`.

### Quality Validation

The following mandatory fields are validated before indexing:
- `@timestamp` — must be non-null
- `source_type` — must be one of `{firewall, webserver, windows, ids}`
- `event.dataset` — must be non-null
- `event.kind` — must be non-null

Events that fail validation are written to the `siem-errors-*` Elasticsearch index
with an `error.message` field explaining the failure.
