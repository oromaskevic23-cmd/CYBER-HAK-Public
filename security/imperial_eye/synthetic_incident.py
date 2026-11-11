"""Synthetic, permission-scoped IMPERIAL EYE event correlation (no video or people).

This module accepts only sealed-shape synthetic event envelopes and aggregates
environmental/camera-health incident types. It does not connect to cameras,
infer personal identity or authorize publication or production execution.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import re

FIELDS = frozenset({"tenant_id", "source_id", "event_id", "event_type",
                    "occurred_at", "source_mode"})
EVENT_TYPES = frozenset({"camera_offline", "camera_tamper",
                         "perimeter_intrusion", "environmental_hazard"})
IDENTIFIER = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]{2,63}$")


class SyntheticEventDenied(ValueError):
    pass


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise SyntheticEventDenied("INVALID_TIMESTAMP")
    try:
        x = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SyntheticEventDenied("INVALID_TIMESTAMP") from exc
    if x.tzinfo is None:
        raise SyntheticEventDenied("TIMEZONE_REQUIRED")
    return x.astimezone(timezone.utc)


def summarize_synthetic_events(events: object, *, tenant_id: str, now: str) -> dict:
    """Bounded, reproducible aggregate for local test fixtures.

    Events are untrusted, even when they have valid syntax. No tenant
    identifiers, coordinates, face embeddings or camera URLs are output.
    """
    if not isinstance(tenant_id, str) or not IDENTIFIER.fullmatch(tenant_id):
        raise SyntheticEventDenied("INVALID_TENANT_ID")
    if not isinstance(events, list) or len(events) > 256:
        raise SyntheticEventDenied("EVENT_BATCH_EXCEEDS_LIMIT")
    instant = _timestamp(now)
    seen = {}
    counts = Counter()
    ordered = []
    for event in events:
        if not isinstance(event, dict) or set(event) != FIELDS:
            raise SyntheticEventDenied("INVALID_EVENT_SCHEMA")
        for key in ("tenant_id", "source_id", "event_id"):
            if not isinstance(event[key], str) or not IDENTIFIER.fullmatch(event[key]):
                raise SyntheticEventDenied("INVALID_IDENTITY")
        if event["tenant_id"] != tenant_id:
            raise SyntheticEventDenied("CROSS_TENANT_EVENT")
        if event["source_mode"] != "SYNTHETIC":
            raise SyntheticEventDenied("NO_PRODUCTION_VIDEO_OR_REAL_SENSORS")
        if not isinstance(event["event_type"], str) or event["event_type"] not in EVENT_TYPES:
            raise SyntheticEventDenied("UNAPPROVED_EVENT_CLASS")
        when = _timestamp(event["occurred_at"])
        delta = (instant - when).total_seconds()
        if delta < 0 or delta > 3600:
            raise SyntheticEventDenied("STALE_OR_FUTURE_EVENT")
        key = event["event_id"]
        digest = hashlib.sha256(json.dumps(event, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=False).encode("utf-8")).hexdigest()
        if key in seen:
            if seen[key] != digest:
                raise SyntheticEventDenied("CONFLICTING_EVENT_ID")
            continue
        seen[key] = digest
        counts[event["event_type"]] += 1
        ordered.append(digest)
    receipt = hashlib.sha256("".join(sorted(ordered)).encode("ascii")).hexdigest()
    return {
        "schema": "imperial.eye.synthetic.incident.v1",
        "source_mode": "SYNTHETIC_ONLY",
        "event_counts": dict(sorted(counts.items())),
        "accepted_unique_events": len(seen),
        "deduplicated": len(events) - len(seen),
        "evidence_sha256": receipt,
        "privacy_class": "NON_IDENTIFYING_LAB_EVENTS",
        "individual_tracking": False,
        "camera_connections": 0,
        "model_calls": 0,
        "production_authorized": False,
        "independent_qa_verified": False,
        "spending_usd": 0,
    }
