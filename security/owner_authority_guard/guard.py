"""IMPERIAL Owner Authority Guard — fail-closed cryptographic LAB reference.

Never self-issues Owner keys or trusts keys embedded in an approval.
External protected Owner enrollment, runtime hook coverage and GitHub rulesets
are mandatory before any production authority claim.
Copyright (c) 2026 Alexander Nikolaevich Romaskevich (RomaskevicH).
Individual code contributors retain Git history attribution.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

OWNER_NAME = "Alexander Nikolaevich Romaskevich"
OWNER_GITHUB = "oromaskevic23-cmd"
OWNER_ROLES = ["Founder", "Owner", "CEO"]
# Retired labels remain blocked for agent self-elevation, not as current Owner roles.
LEGACY_ROOT_ROLE_CLAIMS = frozenset({"Chief Systems Architect"})
DOMAIN = b"IMPERIAL-OWNER-AUTHORITY-GUARD-V1\x00"
PERMITTED_ACTIONS = frozenset({
    "APPROVE_ARCHITECTURE_CHANGE", "AUTHORIZE_NCA_DEPLOYMENT",
    "APPROVE_PRIVILEGED_CHANGE", "REVOKE_NCA", "FREEZE_EXECUTION"
})
FORBIDDEN_IN_CODE = frozenset({
    "CHANGE_OWNER", "GRANT_OWNER", "TRANSFER_ROOT_AUTHORITY",
    "REPLACE_ARCHITECT", "ROTATE_ROOT_TRUST", "DISABLE_OWNER_GUARD",
    "REMOVE_OWNER_KILL_SWITCH"
})
FIELDS = frozenset({
    "schema", "issuer", "owner_name", "owner_github", "owner_roles",
    "actor_type", "action", "target", "nonce", "issued_at",
    "expires_at", "policy_epoch"
})
ENVELOPE = frozenset({"payload", "key_id", "signature"})
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
KID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")


class AuthorityDenied(PermissionError):
    """A sensitive action was rejected by the policy."""


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, ensure_ascii=True,
                      allow_nan=False, separators=(",", ":")).encode("ascii")


def signed_bytes(payload: dict, key_id: str) -> bytes:
    if type(payload) is not dict or type(key_id) is not str or not KID.fullmatch(key_id):
        raise AuthorityDenied("BAD_SIGNED_MESSAGE")
    return DOMAIN + key_id.encode("ascii") + b"\x00" + canonical(payload)


def check_no_agent_takeover(actor_type: str, requested_role: str) -> None:
    """Never accept human-root roles from an AI worker or policy mutation."""
    if (requested_role in OWNER_ROLES or requested_role in LEGACY_ROOT_ROLE_CLAIMS
            or requested_role in FORBIDDEN_IN_CODE):
        raise AuthorityDenied("ROOT_AUTHORITY_IMMUTABLE_IN_CODE")
    if actor_type not in {"NCA", "ORCHESTRATOR", "HANTER", "HUMAN_OPERATOR"}:
        raise AuthorityDenied("UNRECOGNIZED_ACTOR_TYPE")


def verify_approval(envelope: object, trusted_public_keys: Mapping[str, bytes],
                    *, now: int, minimum_epoch: int) -> dict:
    """Verify with a trust anchor supplied OUTSIDE the signed artifact/repo.

    A valid cryptographic signature proves possession of the corresponding key,
    not by itself the civil identity of the Owner or legally binding corporate
    authority. Out-of-band key enrollment is a separate REQUIRED gate.
    """
    if type(now) is not int or now < 0 or type(minimum_epoch) is not int or minimum_epoch < 1:
        raise AuthorityDenied("INVALID_VERIFICATION_CONTEXT")
    if type(envelope) is not dict or set(envelope) != ENVELOPE:
        raise AuthorityDenied("BAD_ENVELOPE")
    payload, kid, signature = envelope["payload"], envelope["key_id"], envelope["signature"]
    if (type(payload) is not dict or set(payload) != FIELDS
            or type(kid) is not str or not KID.fullmatch(kid)
            or type(signature) is not str or not HEX128.fullmatch(signature)):
        raise AuthorityDenied("BAD_SIGNATURE_SCHEMA")
    if (payload["schema"] != "imperial.owner.authority.v1"
            or payload["issuer"] != "OWNER_OFFLINE_ENROLLMENT_REQUIRED"
            or payload["actor_type"] != "HUMAN_OWNER"
            or payload["owner_name"] != OWNER_NAME
            or payload["owner_github"] != OWNER_GITHUB
            or type(payload["owner_roles"]) is not list
            or payload["owner_roles"] != OWNER_ROLES):
        raise AuthorityDenied("CANONICAL_OWNER_MISMATCH")
    action = payload["action"]
    if type(action) is not str or action not in PERMITTED_ACTIONS:
        raise AuthorityDenied("ROOT_CHANGE_OR_UNKNOWN_ACTION_DENIED")
    target, nonce = payload["target"], payload["nonce"]
    if (type(target) is not str or not NAME.fullmatch(target)
            or type(nonce) is not str or not HEX32.fullmatch(nonce)):
        raise AuthorityDenied("INVALID_TARGET_OR_NONCE")
    issued, expires, epoch = (payload[x] for x in ("issued_at", "expires_at", "policy_epoch"))
    if (type(issued) is not int or type(expires) is not int
            or issued < 0 or not issued <= now < expires or expires-issued > 300):
        raise AuthorityDenied("EXPIRED_OR_OVERSCOPED_PERMIT")
    if type(epoch) is not int or epoch < minimum_epoch:
        raise AuthorityDenied("REVOKED_OR_OLD_POLICY_EPOCH")
    if not isinstance(trusted_public_keys, Mapping):
        raise AuthorityDenied("MISSING_EXTERNAL_TRUST")
    public_key = trusted_public_keys.get(kid)
    if type(public_key) is not bytes or len(public_key) != 32:
        raise AuthorityDenied("UNKNOWN_TRUST_ANCHOR")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(signature), signed_bytes(payload, kid)
        )
    except (InvalidSignature, ValueError, TypeError):
        raise AuthorityDenied("SIGNATURE_INVALID") from None
    return dict(payload)


class LocalAuthorityLedger:
    """Atomic, replay-resistant local demonstration. NOT production Audit Ledger."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE IF NOT EXISTS approvals("
                       "nonce TEXT PRIMARY KEY, payload_sha256 TEXT NOT NULL, "
                       "action TEXT NOT NULL, target TEXT NOT NULL, accepted_at INTEGER NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS controls("
                       "subject TEXT PRIMARY KEY, state TEXT NOT NULL)")

    def freeze(self) -> None:
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR REPLACE INTO controls VALUES ('owner_authority','FROZEN')")

    def consume(self, envelope: object, trusted_keys: Mapping[str, bytes],
                *, now: int, minimum_epoch: int) -> dict:
        p = verify_approval(envelope, trusted_keys, now=now, minimum_epoch=minimum_epoch)
        digest = hashlib.sha256(signed_bytes(p, envelope["key_id"])).hexdigest()
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            frozen = db.execute("SELECT 1 FROM controls WHERE subject='owner_authority' "
                                "AND state='FROZEN'").fetchone()
            if frozen:
                raise AuthorityDenied("GUARD_FROZEN")
            try:
                db.execute("INSERT INTO approvals VALUES(?,?,?,?,?)",
                           (p["nonce"], digest, p["action"], p["target"], now))
            except sqlite3.IntegrityError:
                raise AuthorityDenied("APPROVAL_REPLAY_DENIED") from None
        return {
            "action": p["action"], "target": p["target"],
            "permit_sha256": digest, "signature_cryptographically_verified": True,
            "owner_identity_enrollment_verified": False,
            "production_authorized": False,
            "audit_type": "LOCAL_LAB_ONLY"
        }
