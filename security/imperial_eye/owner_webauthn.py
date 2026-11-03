"""IMPERIAL EYE — local-only WebAuthn Owner device verification reference.

Uses py_webauthn to validate authenticator signatures, challenge, rpId,
origin, UP/UV and sign counters. NO server endpoints or Owner enrollment are
deployed; supplied credentials are lab fixtures until separately enrolled.
Never accepts face images, face templates or passwords.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import secrets
import sqlite3
from pathlib import Path

from webauthn import verify_authentication_response
from webauthn.helpers.exceptions import InvalidAuthenticationResponse


class DeviceDenied(PermissionError):
    """Reject a passkey verification or lack of external trust."""


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class TrustedPasskey:
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int = 0

    def __post_init__(self):
        if (type(self.credential_id) is not bytes or not 16 <= len(self.credential_id) <= 1024
                or type(self.credential_public_key) is not bytes or
                not 20 <= len(self.credential_public_key) <= 2048
                or type(self.sign_count) is not int or self.sign_count < 0):
            raise DeviceDenied("INVALID_TRUSTED_CREDENTIAL")


class LocalOwnerDeviceVerifier:
    """Verifies passkey possession using an externally supplied public key.

    The caller must provision and secure enrolled credentials OUTSIDE this
    class. A successful lab assertion never unlocks actual Owner authority.
    """
    def __init__(self, db_path: str | Path, *, rp_id: str, origin: str,
                 trusted: TrustedPasskey | None):
        if (type(rp_id) is not str or not rp_id or type(origin) is not str
                or not origin.endswith(rp_id) or
                not (origin.startswith("https://") or origin=="http://localhost")):
            raise DeviceDenied("INVALID_RP_OR_ORIGIN")
        self.rp_id, self.origin, self.trusted = rp_id, origin, trusted
        self.path=Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS challenges(
                id TEXT PRIMARY KEY, bytes BLOB NOT NULL, expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0)""")
            db.execute("""CREATE TABLE IF NOT EXISTS credential_counters(
                id TEXT PRIMARY KEY, sign_count INTEGER NOT NULL)""")
            if trusted is not None:
                record = db.execute("SELECT sign_count FROM credential_counters WHERE id=?",
                                    (b64url(trusted.credential_id),)).fetchone()
                if record is None:
                    db.execute("INSERT INTO credential_counters VALUES (?,?)",
                               (b64url(trusted.credential_id),trusted.sign_count))
                elif record[0] < trusted.sign_count:
                    db.execute("UPDATE credential_counters SET sign_count=? WHERE id=?",
                               (trusted.sign_count,b64url(trusted.credential_id)))

    def new_challenge(self, *, now: int) -> dict:
        if self.trusted is None:
            raise DeviceDenied("NO_OWNER_CREDENTIAL_EXTERNALLY_ENROLLED")
        if type(now) is not int or now < 0:
            raise DeviceDenied("INVALID_TIME")
        challenge, challenge_id = secrets.token_bytes(32), secrets.token_hex(24)
        with sqlite3.connect(self.path,timeout=10) as db:
            db.execute("INSERT INTO challenges VALUES (?,?,?,0)",
                       (challenge_id,challenge,now+90))
        return {"schema_version":1,"challenge_id":challenge_id,
                "challenge":b64url(challenge),"rp_id":self.rp_id,
                "allow_credentials":[{"id":b64url(self.trusted.credential_id)}],
                "user_verification":"required","expires_at":now+90}

    def verify_assertion(self, proof: object, *, now: int) -> dict:
        if self.trusted is None:
            raise DeviceDenied("NO_OWNER_CREDENTIAL_EXTERNALLY_ENROLLED")
        if type(now) is not int or now < 0:
            raise DeviceDenied("INVALID_TIME")
        if (type(proof) is not dict or
                set(proof)!={"schema_version","challenge_id","id","raw_id","type","response"}
                or proof.get("schema_version")!=1 or proof.get("type")!="public-key"
                or type(proof.get("response")) is not dict):
            raise DeviceDenied("BAD_ASSERTION_SCHEMA")
        rid = proof["challenge_id"]
        if type(rid) is not str or len(rid)!=48:
            raise DeviceDenied("INVALID_CHALLENGE_REFERENCE")
        credential_id = b64url(self.trusted.credential_id)
        if proof["id"]!=credential_id or proof["raw_id"]!=credential_id:
            raise DeviceDenied("UNREGISTERED_OWNER_CREDENTIAL")
        response = proof["response"]
        if set(response)!={"authenticator_data","client_data_json","signature","user_handle"}:
            raise DeviceDenied("BAD_AUTHENTICATOR_RESPONSE_SCHEMA")
        credential={
            "id":proof["id"],"rawId":proof["raw_id"],"type":"public-key",
            "response":{
                "authenticatorData":response["authenticator_data"],
                "clientDataJSON":response["client_data_json"],
                "signature":response["signature"],
                "userHandle":response["user_handle"]
            },
            "clientExtensionResults":{}
        }
        # Burn challenge BEFORE cryptographic verification. Concurrent attempts
        # and failures cannot reuse an old challenge, even across restarts.
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT bytes,expires_at,used FROM challenges WHERE id=?",
                           (rid,)).fetchone()
            if row is None or row[2] or not now < row[1]:
                raise DeviceDenied("CHALLENGE_REPLAY_OR_EXPIRED")
            updated=db.execute("UPDATE challenges SET used=1 WHERE id=? AND used=0",(rid,))
            if updated.rowcount != 1:
                raise DeviceDenied("CHALLENGE_ALREADY_USED")
            challenge=row[0]
        with sqlite3.connect(self.path, timeout=10) as db:
            row=db.execute("SELECT sign_count FROM credential_counters WHERE id=?",
                           (credential_id,)).fetchone()
            if row is None:
                raise DeviceDenied("TRUST_RECORD_NOT_FOUND")
            sign_count=row[0]
        try:
            result=verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.rp_id,
                expected_origin=self.origin,
                credential_public_key=self.trusted.credential_public_key,
                credential_current_sign_count=sign_count,
                require_user_verification=True
            )
        except (InvalidAuthenticationResponse,ValueError,TypeError,KeyError):
            raise DeviceDenied("WEBAUTHN_SIGNATURE_OR_CONTEXT_REJECTED") from None
        if result.user_verified is not True:
            raise DeviceDenied("USER_VERIFICATION_REQUIRED")
        with sqlite3.connect(self.path, timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT sign_count FROM credential_counters WHERE id=?",
                           (credential_id,)).fetchone()
            if row is None or row[0] != sign_count:
                raise DeviceDenied("COUNTER_CONCURRENT_CHANGE")
            db.execute("UPDATE credential_counters SET sign_count=? WHERE id=?",
                       (result.new_sign_count,credential_id))
        return {
            "schema_version":1,
            "device_signature_verified":True,
            "user_verified":True,
            "challenge_consumed":True,
            "rp_id":self.rp_id,
            "owner_identity_enrollment_proven":False,
            "owner_authority_session":False,
            "production_authorized":False,
            "biometric_template_received":False,
            "approval_gateway_verified":False,
            "next_step":"EXTERNALLY_ENROLLED_OWNER_AND_PROTECTED_APPROVAL_REQUIRED"
        }
