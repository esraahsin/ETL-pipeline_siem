"""Deduplicator — removes duplicate ECS events using a content hash computed
from key fields plus the event timestamp."""

import hashlib
import json
from typing import Iterable, Iterator


_HASH_FIELDS = ("@timestamp", "source_type", "event")


def compute_event_hash(event: dict) -> str:
    """Compute a stable SHA-256 hash for an ECS event.

    Only the fields listed in ``_HASH_FIELDS`` are included so that
    metadata-only differences (e.g. ``ingest_timestamp``) do not create
    false negatives.

    Args:
        event: ECS-compliant event dict.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    fingerprint = {k: event.get(k) for k in _HASH_FIELDS if k in event}
    serialized = json.dumps(fingerprint, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def deduplicate(events: Iterable[dict]) -> Iterator[dict]:
    """Yield unique events from an iterable, discarding duplicates.

    Deduplication is based on the hash produced by :func:`compute_event_hash`.
    The first occurrence of each event is kept; subsequent duplicates are
    silently dropped.

    Args:
        events: Iterable of ECS-compliant event dicts.

    Yields:
        Unique event dicts, each annotated with an ``_id`` field containing
        the computed hash.
    """
    seen: set = set()
    for event in events:
        h = compute_event_hash(event)
        if h not in seen:
            seen.add(h)
            event["_id"] = h
            yield event


def is_duplicate(event: dict, seen_hashes: set) -> bool:
    """Check whether an event is a duplicate given a set of previously seen
    hashes.

    Args:
        event: ECS-compliant event dict.
        seen_hashes: Mutable set of already-seen hash strings (updated in-place
            when the event is new).

    Returns:
        True if the event is a duplicate, False otherwise.
    """
    h = compute_event_hash(event)
    if h in seen_hashes:
        return True
    seen_hashes.add(h)
    return False
