"""Offline, default-deny inspection of authorized IMPERIAL EYE deployments.

No provider access, camera connection, credential handling, or automatic repair.
Input is a locally redacted observation; passing inspection cannot prove safety.
"""
from __future__ import annotations
from datetime import datetime, timezone
import re

MODES = frozenset({"vite_dev", "vite_preview", "static_site", "hardened_server", "unknown"})
FIELDS = frozenset({
    "deployment_id", "public_network", "server_mode", "edge_auth_verified",
    "signed_owner_approval_verified", "publisher_rights_verified",
    "provider_quota_verified", "oom_failures_24h", "memory_limit_mib",
    "dependency_reviewed", "recorded_at",
})
ID = re.compile(r"^[a-z][a-z0-9_-]{2,63}$")


def _date(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("INVALID_TIMESTAMP")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("INVALID_TIMESTAMP") from exc
    if result.tzinfo is None:
        raise ValueError("TIMESTAMP_MUST_INCLUDE_OFFSET")
    return result.astimezone(timezone.utc)


def inspect_deployment(snapshot: object, *, now: str) -> dict:
    """Classify known-risk configurations; never grant runtime access."""
    failed = {"schema": "imperial.eye.deployment.guard.v1",
              "production_verified": False, "action_authorized": False,
              "provider_access": False, "camera_access": False,
              "spending_usd": 0}
    if not isinstance(snapshot, dict) or set(snapshot) != FIELDS:
        return {**failed, "decision": "DENY", "reasons": ["INVALID_SCHEMA"]}
    if not isinstance(snapshot["deployment_id"], str) or not ID.fullmatch(snapshot["deployment_id"]):
        return {**failed, "decision": "DENY", "reasons": ["INVALID_DEPLOYMENT_ID"]}
    if not isinstance(snapshot["server_mode"], str) or snapshot["server_mode"] not in MODES:
        return {**failed, "decision": "DENY", "reasons": ["UNKNOWN_SERVER_MODE"]}
    for key in ("public_network", "edge_auth_verified", "signed_owner_approval_verified",
                "publisher_rights_verified", "provider_quota_verified",
                "dependency_reviewed"):
        if type(snapshot[key]) is not bool:
            return {**failed, "decision": "DENY", "reasons": ["INVALID_" + key.upper()]}
    for key in ("oom_failures_24h", "memory_limit_mib"):
        if type(snapshot[key]) is not int or snapshot[key] < 0 or snapshot[key] > 100000:
            return {**failed, "decision": "DENY", "reasons": ["INVALID_" + key.upper()]}
    try:
        observed = _date(snapshot["recorded_at"])
        instant = _date(now)
    except ValueError:
        return {**failed, "decision": "DENY", "reasons": ["INVALID_OBSERVATION_TIME"]}
    reasons = []
    if observed > instant:
        reasons.append("FUTURE_OBSERVATION")
    if (instant - observed).total_seconds() > 3600:
        reasons.append("STALE_OBSERVATION")
    if snapshot["public_network"] and snapshot["server_mode"] in {"vite_dev", "vite_preview"}:
        reasons.append("PUBLIC_DEVELOPMENT_OR_PREVIEW_SERVER")
    if snapshot["public_network"] and not snapshot["edge_auth_verified"]:
        reasons.append("PUBLIC_EDGE_AUTH_NOT_VERIFIED")
    if not snapshot["signed_owner_approval_verified"]:
        reasons.append("OWNER_PERMIT_NOT_VERIFIED")
    if not snapshot["publisher_rights_verified"]:
        reasons.append("SOURCE_RIGHTS_NOT_VERIFIED")
    if not snapshot["provider_quota_verified"]:
        reasons.append("PROVIDER_QUOTA_NOT_VERIFIED")
    if not snapshot["dependency_reviewed"]:
        reasons.append("DEPENDENCIES_NOT_REVIEWED")
    if snapshot["oom_failures_24h"] > 1:
        reasons.append("REPEATED_OOM")
    elif snapshot["oom_failures_24h"]:
        reasons.append("OOM_OBSERVED")
    if snapshot["memory_limit_mib"] < 512:
        reasons.append("LOW_MEMORY_BUDGET_REQUIRES_PROFILING")
    if snapshot["server_mode"] == "unknown":
        reasons.append("UNKNOWN_SERVER_MODE")
    return {**failed, "decision": "BLOCKED" if reasons else "INDEPENDENT_REVIEW_REQUIRED",
            "reasons": sorted(set(reasons)), "deployment_id": snapshot["deployment_id"],
            "observation_fresh": "STALE_OBSERVATION" not in reasons and "FUTURE_OBSERVATION" not in reasons}
