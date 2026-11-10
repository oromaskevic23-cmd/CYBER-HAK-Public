"""IMPERIAL EYE Evidence Fusion v0.1 — offline, bounded defensive triage.

Events are typed, anonymized observations about systems owned or authorized by
the tenant. No personal search, video, face identification, network requests,
agent dispatch, or remediation actions. A hash is not a signature or a QA proof.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re

IDENT = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
SCHEMA = "imperial.eye.system-event.v1"
FIELDS = frozenset({
    "schema", "event_id", "tenant_id", "orchestrator_id", "component_id",
    "component_kind", "kind", "occurred_at", "evidence_sha256"
})
COMPONENTS = frozenset({
    "render_service", "nca_worker", "approval_gateway",
    "webauthn_backend", "official_source"
})
# Only events about infrastructure, not people or externally identified devices.
EVENT_KINDS = {
    "render_oom": "CRITICAL",
    "render_restart": "WARNING",
    "model_worker_absent": "CRITICAL",
    "owner_permit_expired": "CRITICAL",
    "approval_rejected": "WARNING",
    "signature_invalid": "CRITICAL",
    "backend_unavailable": "MAJOR",
    "public_snapshot_stale": "WARNING",
    "provider_rate_limited": "WARNING",
    "audit_integrity_failed": "CRITICAL"
}
ALLOWED_PAIRS = {
    "render_service": {"render_oom", "render_restart", "backend_unavailable", "provider_rate_limited"},
    "nca_worker": {"model_worker_absent", "owner_permit_expired", "approval_rejected"},
    "approval_gateway": {"owner_permit_expired", "approval_rejected", "signature_invalid", "audit_integrity_failed"},
    "webauthn_backend": {"backend_unavailable", "signature_invalid", "provider_rate_limited"},
    "official_source": {"public_snapshot_stale", "provider_rate_limited", "backend_unavailable"}
}
MAX_EVENTS = 200
MAX_JSON_BYTES = 65536


class FusionDenied(ValueError):
    """Closed-schema refusal; no event data copied to errors."""


def _utc(value: object) -> datetime:
    if type(value) is not str or len(value) > 40:
        raise FusionDenied("INVALID_EVENT_TIME")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise FusionDenied("INVALID_EVENT_TIME") from None
    if dt.tzinfo is None:
        raise FusionDenied("TIMEZONE_REQUIRED")
    return dt.astimezone(timezone.utc)


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        raise FusionDenied("INVALID_EVENT_ENCODING") from None
    if len(encoded) > MAX_JSON_BYTES:
        raise FusionDenied("EVENT_BATCH_TOO_LARGE")
    return encoded


def validate_system_event(item: object, *, tenant_id: str,
                          now: datetime, max_age_hours: int) -> dict:
    if type(item) is not dict or set(item) != FIELDS:
        raise FusionDenied("EVENT_SCHEMA_DENIED")
    if item["schema"] != SCHEMA:
        raise FusionDenied("EVENT_VERSION_DENIED")
    for field in ("event_id", "tenant_id", "orchestrator_id", "component_id"):
        if type(item[field]) is not str or not IDENT.fullmatch(item[field]):
            raise FusionDenied("EVENT_IDENTIFIER_DENIED")
    if item["tenant_id"] != tenant_id:
        raise FusionDenied("CROSS_TENANT_EVENT_DENIED")
    component, kind = item["component_kind"], item["kind"]
    if (type(component) is not str or component not in COMPONENTS
            or type(kind) is not str or kind not in ALLOWED_PAIRS[component]):
        raise FusionDenied("EVENT_CAPABILITY_DENIED")
    if type(item["evidence_sha256"]) is not str or not HASH.fullmatch(item["evidence_sha256"]):
        raise FusionDenied("INVALID_EVIDENCE_HASH")
    occurred = _utc(item["occurred_at"])
    if occurred > now + timedelta(minutes=2):
        raise FusionDenied("FUTURE_EVENT_DENIED")
    if occurred < now - timedelta(hours=max_age_hours):
        raise FusionDenied("STALE_EVENT_DENIED")
    return {**item, "occurred_at": occurred.isoformat()}


def fuse_system_events(events: object, *, tenant_id: str, now: str,
                       max_age_hours: int = 24, kill_switch: bool = True) -> dict:
    """Summarize supplied records for review. No monitoring or authority granted.

    Event hashes bind untrusted observations, not their provenance. Collector
    authorization and independent QA must be checked by a separate private
    authority service. The kill switch is always respected in recommendations.
    """
    if type(tenant_id) is not str or not IDENT.fullmatch(tenant_id):
        raise FusionDenied("TENANT_REQUIRED")
    if type(max_age_hours) is not int or not 1 <= max_age_hours <= 72:
        raise FusionDenied("INVALID_WINDOW")
    if type(kill_switch) is not bool:
        raise FusionDenied("INVALID_KILL_SWITCH")
    if type(events) is not list or len(events) > MAX_EVENTS:
        raise FusionDenied("INVALID_EVENT_BATCH")
    instant = _utc(now)
    _canonical(events)
    seen: dict[str, bytes] = {}
    unique: list[dict] = []
    for raw in events:
        event = validate_system_event(raw, tenant_id=tenant_id, now=instant,
                                      max_age_hours=max_age_hours)
        digest = _canonical(event)
        previous = seen.get(event["event_id"])
        if previous is not None:
            if previous != digest:
                raise FusionDenied("CONFLICTING_EVENT_REPLAY_DENIED")
            continue
        seen[event["event_id"]] = digest
        unique.append(event)
    unique.sort(key=lambda e: (e["occurred_at"], e["event_id"]))
    grouped: dict[tuple[str, str], list[dict]] = {}
    for event in unique:
        key = (event["orchestrator_id"], event["component_id"])
        grouped.setdefault(key, []).append(event)
    incidents = []
    for (orchestrator, component), items in sorted(grouped.items()):
        categories = sorted({e["kind"] for e in items})
        severe = sorted({EVENT_KINDS[e["kind"]] for e in items},
                        key=lambda v: {"CRITICAL": 0, "MAJOR": 1, "WARNING": 2}[v])
        incident = {
            "orchestrator_id": orchestrator,
            "component_id": component,
            "component_kind": items[0]["component_kind"],
            "severity": severe[0],
            "event_count": len(items),
            "kinds": categories,
            "first_observed_at": items[0]["occurred_at"],
            "last_observed_at": items[-1]["occurred_at"],
            "repeated_oom": sum(x["kind"] == "render_oom" for x in items) >= 2,
            "input_evidence_sha256": hashlib.sha256(_canonical(items)).hexdigest(),
        }
        # Same component_id must not silently stand for different component types.
        if any(item["component_kind"] != incident["component_kind"] for item in items):
            raise FusionDenied("CONFLICTING_COMPONENT_IDENTITY_DENIED")
        incidents.append(incident)
    return {
        "schema": "imperial.eye.system-fusion.v1",
        "tenant_id": tenant_id,
        "window_hours": max_age_hours,
        "snapshot_at": instant.isoformat(),
        "input_count": len(events),
        "deduplicated_count": len(unique),
        "incident_count": len(incidents),
        "incidents": incidents,
        "batch_sha256": hashlib.sha256(_canonical(unique)).hexdigest(),
        "owner_kill_switch_active": kill_switch,
        "data_scope": "STRUCTURED_SYSTEM_EVENTS_ONLY",
        "source_authenticity_verified": False,
        "independent_qa_verified": False,
        "execution_authorized": False,
        "production_monitoring_verified": False,
        "external_effects": False,
        "spend_usd": 0
    }
