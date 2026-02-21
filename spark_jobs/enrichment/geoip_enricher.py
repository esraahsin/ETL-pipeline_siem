"""GeoIP enricher — adds geographic location data to ECS events using MaxMind
GeoIP2."""

import os
from typing import Optional

import structlog

log = structlog.get_logger(component="geoip_enricher")

_MAXMIND_DB_PATH = os.getenv("MAXMIND_DB_PATH", "/opt/geoip/GeoLite2-City.mmdb")
_reader = None


def _get_reader():
    """Lazily initialize the MaxMind database reader."""
    global _reader
    if _reader is None:
        try:
            import geoip2.database
            _reader = geoip2.database.Reader(_MAXMIND_DB_PATH)
            log.info("geoip_db_loaded", path=_MAXMIND_DB_PATH)
        except Exception as exc:
            log.warning("geoip_db_unavailable", error=str(exc))
            _reader = None
    return _reader


def enrich_with_geoip(event: dict) -> dict:
    """Add GeoIP metadata to the ``source.geo`` and ``destination.geo`` fields
    of an ECS event.

    Args:
        event: ECS-compliant event dict (mutated in-place and returned).

    Returns:
        The enriched event dict.
    """
    reader = _get_reader()
    if reader is None:
        return event

    for field in ("source", "destination"):
        ip = (event.get(field) or {}).get("ip")
        if ip:
            geo = _lookup_ip(reader, ip)
            if geo:
                event.setdefault(field, {})["geo"] = geo

    return event


def _lookup_ip(reader, ip: str) -> Optional[dict]:
    """Look up GeoIP data for a single IP address.

    Args:
        reader: MaxMind database reader instance.
        ip: IPv4 or IPv6 address string.

    Returns:
        Dict with country/city/location info, or None on lookup failure.
    """
    try:
        response = reader.city(ip)
        return {
            "country_iso_code": response.country.iso_code,
            "country_name": response.country.name,
            "city_name": response.city.name,
            "location": {
                "lat": response.location.latitude,
                "lon": response.location.longitude,
            },
        }
    except Exception:
        return None
