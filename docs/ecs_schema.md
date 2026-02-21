# ECS Schema Documentation — SIEM ETL Pipeline

This document describes the [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
fields used by this pipeline, along with the mapping from raw log formats to ECS.

---

## Top-Level ECS Fields Used

| Field | Type | Description | Required |
|---|---|---|---|
| `@timestamp` | `date` | Event time in UTC ISO-8601 | ✅ |
| `source_type` | `keyword` | Log source: `firewall`, `webserver`, `windows`, `ids` | ✅ |
| `ingest_timestamp` | `date` | Time the event was received by the pipeline | ✅ |
| `tags` | `keyword[]` | Pipeline tags (e.g., `["firewall", "cef"]`) | ✅ |
| `_id` | `keyword` | SHA-256 deduplication hash | ✅ |

---

## `event.*` Fields

| Field | Type | Description |
|---|---|---|
| `event.kind` | `keyword` | `event`, `alert`, `metric` |
| `event.category` | `keyword` | `network`, `web`, `authentication`, `intrusion_detection` |
| `event.type` | `keyword` | `connection`, `access`, `start`, `denied`, `allowed` |
| `event.action` | `keyword` | Normalised action (lowercase): `allow`, `deny`, `get`, `post`, etc. |
| `event.dataset` | `keyword` | Source dataset: `firewall`, `webserver`, `windows`, `ids` |
| `event.severity` | `integer` | Unified severity score 1–10 |
| `event.outcome` | `keyword` | `success` or `failure` |
| `event.original` | `text` | Original raw log line (not indexed) |
| `event.code` | `keyword` | Windows Event ID or rule ID |

---

## `source.*` and `destination.*` Fields

| Field | Type | Description |
|---|---|---|
| `source.ip` | `ip` | Source IP address (IPv4 or IPv6) |
| `source.port` | `integer` | Source TCP/UDP port |
| `source.geo.country_iso_code` | `keyword` | 2-letter ISO country code |
| `source.geo.country_name` | `keyword` | Country name |
| `source.geo.city_name` | `keyword` | City name |
| `source.geo.location` | `geo_point` | `{lat, lon}` coordinates |
| `destination.ip` | `ip` | Destination IP address |
| `destination.port` | `integer` | Destination TCP/UDP port |
| `destination.geo.*` | — | Same structure as `source.geo.*` |

---

## `http.*` Fields (Web Server logs)

| Field | Type | Description |
|---|---|---|
| `http.request.method` | `keyword` | HTTP method: `GET`, `POST`, etc. |
| `http.request.referrer` | `keyword` | HTTP Referer header |
| `http.response.status_code` | `integer` | HTTP response status code |
| `http.response.bytes` | `long` | Response body size in bytes |
| `http.version` | `keyword` | HTTP version: `1.0`, `1.1`, `2` |

---

## `url.*` Fields (Web Server logs)

| Field | Type | Description |
|---|---|---|
| `url.path` | `keyword` | URL path component |
| `url.original` | `keyword` | Full original URL |

---

## `user_agent.*` Fields (Web Server logs)

| Field | Type | Description |
|---|---|---|
| `user_agent.original` | `keyword` | Raw User-Agent string |

---

## `network.*` Fields (Firewall / IDS)

| Field | Type | Description |
|---|---|---|
| `network.transport` | `keyword` | Transport protocol: `tcp`, `udp`, `icmp` |

---

## `observer.*` Fields (Firewall / IDS)

| Field | Type | Description |
|---|---|---|
| `observer.vendor` | `keyword` | Device vendor name |
| `observer.product` | `keyword` | Device product name |
| `observer.type` | `keyword` | Device type: `ids`, `firewall` |
| `observer.ingress.interface.name` | `keyword` | Inbound interface name |

---

## `rule.*` Fields (IDS)

| Field | Type | Description |
|---|---|---|
| `rule.id` | `keyword` | Suricata signature ID (SID) |
| `rule.name` | `keyword` | Signature description |
| `rule.category` | `keyword` | Alert category |

---

## `winlog.*` Fields (Windows Events)

| Field | Type | Description |
|---|---|---|
| `winlog.event_id` | `integer` | Windows Event ID |
| `winlog.channel` | `keyword` | Event log channel (e.g., `Security`) |
| `winlog.logon.type` | `keyword` | Logon type: `interactive`, `network`, etc. |

---

## `host.*` Fields (Windows Events)

| Field | Type | Description |
|---|---|---|
| `host.hostname` | `keyword` | Computer hostname |
| `host.domain` | `keyword` | Active Directory domain |

---

## `user.*` Fields (Windows Events)

| Field | Type | Description |
|---|---|---|
| `user.name` | `keyword` | Target username |
| `user.domain` | `keyword` | User domain |

---

## `process.*` Fields (Windows Events)

| Field | Type | Description |
|---|---|---|
| `process.name` | `keyword` | Process executable name |

---

## Mapping Summary by Source

| Raw Format | Parser | Key ECS Sections |
|---|---|---|
| Syslog/CEF (Firewall) | `firewall_parser.py` | `event`, `source`, `destination`, `network`, `observer` |
| Apache/Nginx (Web) | `webserver_parser.py` | `event`, `source`, `http`, `url`, `user_agent` |
| Windows Event JSON | `windows_parser.py` | `event`, `host`, `user`, `source`, `process`, `winlog` |
| Suricata Eve JSON | `ids_parser.py` | `event`, `source`, `destination`, `network`, `rule`, `observer` |
