"""True ES256 WebAuthn assertion tests with synthetic test device credentials.

No real Owner passkey is enrolled. Generated keys are lab-only. This tests
the backend verifier and its exact origin/RP/challenge requirements.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

from security.imperial_eye.owner_webauthn import (
    DeviceDenied, LocalOwnerDeviceVerifier, TrustedPasskey, b64url
)


class DeviceVerifierTests(unittest.TestCase):
    def setUp(self):
        self.dir = TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.db=Path(self.dir.name)/"passkeys.sqlite"
        self.rp_id="localhost"
        self.origin="http://localhost"
        self.device=ec.generate_private_key(ec.SECP256R1())
        coords=self.device.public_key().public_numbers()
        # COSE: EC2 / ES256 / P-256 public key, not a biometric template.
        cose=cbor2.dumps({
            1:2,3:-7,-1:1,
            -2:coords.x.to_bytes(32,"big"),
            -3:coords.y.to_bytes(32,"big")
        })
        self.trusted=TrustedPasskey(b"synthetic-credential-id-0001",cose)
        self.verifier=LocalOwnerDeviceVerifier(
            self.db,rp_id=self.rp_id,origin=self.origin,trusted=self.trusted)

    def assertion(self,challenge,*,user_verified=True,origin=None,sign_count=1,
                  signing_key=None):
        flags=0x05 if user_verified else 0x01
        authenticator_data=hashlib.sha256(self.rp_id.encode()).digest() + bytes([flags]) + sign_count.to_bytes(4,"big")
        client_data=json.dumps({
            "type":"webauthn.get",
            "challenge":challenge["challenge"],
            "origin":origin or self.origin,
            "crossOrigin":False
        },separators=(",",":")).encode()
        signature=(signing_key or self.device).sign(
            authenticator_data+hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()))
        return {
            "schema_version":1,"challenge_id":challenge["challenge_id"],
            "id":b64url(self.trusted.credential_id),
            "raw_id":b64url(self.trusted.credential_id),
            "type":"public-key",
            "response":{
                "authenticator_data":b64url(authenticator_data),
                "client_data_json":b64url(client_data),
                "signature":b64url(signature),
                "user_handle":None
            }
        }

    def test_actual_signed_assertion_verifies_but_never_grants_owner_authority(self):
        challenge=self.verifier.new_challenge(now=100)
        response=self.verifier.verify_assertion(self.assertion(challenge),now=101)
        self.assertTrue(response["device_signature_verified"])
        self.assertTrue(response["user_verified"])
        self.assertFalse(response["owner_identity_enrollment_proven"])
        self.assertFalse(response["owner_authority_session"])
        self.assertFalse(response["production_authorized"])
        self.assertFalse(response["biometric_template_received"])

    def test_signature_from_other_device_is_denied(self):
        challenge=self.verifier.new_challenge(now=100)
        other=ec.generate_private_key(ec.SECP256R1())
        with self.assertRaisesRegex(DeviceDenied,"WEBAUTHN_SIGNATURE_OR_CONTEXT_REJECTED"):
            self.verifier.verify_assertion(
                self.assertion(challenge,signing_key=other),now=101)

    def test_origin_mismatch_denied(self):
        challenge=self.verifier.new_challenge(now=100)
        with self.assertRaisesRegex(DeviceDenied,"WEBAUTHN_SIGNATURE_OR_CONTEXT_REJECTED"):
            self.verifier.verify_assertion(
                self.assertion(challenge,origin="https://attacker.example"),now=101)

    def test_user_verification_is_required(self):
        challenge=self.verifier.new_challenge(now=100)
        with self.assertRaisesRegex(DeviceDenied,"WEBAUTHN_SIGNATURE_OR_CONTEXT_REJECTED"):
            self.verifier.verify_assertion(
                self.assertion(challenge,user_verified=False),now=101)

    def test_challenge_is_single_use_after_restart(self):
        challenge=self.verifier.new_challenge(now=100)
        signed=self.assertion(challenge)
        self.verifier.verify_assertion(signed,now=101)
        restarted=LocalOwnerDeviceVerifier(self.db,rp_id=self.rp_id,
                                           origin=self.origin,trusted=self.trusted)
        with self.assertRaisesRegex(DeviceDenied,"CHALLENGE_REPLAY_OR_EXPIRED"):
            restarted.verify_assertion(signed,now=102)

    def test_invalid_signature_also_burns_challenge(self):
        challenge=self.verifier.new_challenge(now=100)
        signed=self.assertion(challenge,signing_key=ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(DeviceDenied):
            self.verifier.verify_assertion(signed,now=101)
        with self.assertRaisesRegex(DeviceDenied,"CHALLENGE_REPLAY_OR_EXPIRED"):
            self.verifier.verify_assertion(self.assertion(challenge),now=102)

    def test_expiry_exact_boundary_denies(self):
        challenge=self.verifier.new_challenge(now=100)
        with self.assertRaisesRegex(DeviceDenied,"CHALLENGE_REPLAY_OR_EXPIRED"):
            self.verifier.verify_assertion(self.assertion(challenge),now=190)

    def test_missing_external_owner_credential_denied(self):
        fresh=LocalOwnerDeviceVerifier(
            Path(self.dir.name)/"empty.sqlite",
            rp_id=self.rp_id,origin=self.origin,trusted=None)
        with self.assertRaisesRegex(DeviceDenied,"NO_OWNER_CREDENTIAL_EXTERNALLY_ENROLLED"):
            fresh.new_challenge(now=100)

    def test_wrong_credential_id_denied(self):
        challenge=self.verifier.new_challenge(now=100)
        forged=self.assertion(challenge)
        forged["raw_id"]=b64url(b"another-credential-id")
        with self.assertRaisesRegex(DeviceDenied,"UNREGISTERED_OWNER_CREDENTIAL"):
            self.verifier.verify_assertion(forged,now=101)

    def test_counter_replay_on_new_challenge_denied(self):
        first=self.verifier.new_challenge(now=100)
        self.verifier.verify_assertion(self.assertion(first,sign_count=1),now=101)
        second=self.verifier.new_challenge(now=102)
        with self.assertRaisesRegex(DeviceDenied,"WEBAUTHN_SIGNATURE_OR_CONTEXT_REJECTED"):
            self.verifier.verify_assertion(self.assertion(second,sign_count=1),now=103)

    def test_new_counter_can_reauthenticate_same_lab_key(self):
        first=self.verifier.new_challenge(now=100)
        self.verifier.verify_assertion(self.assertion(first,sign_count=1),now=101)
        second=self.verifier.new_challenge(now=102)
        result=self.verifier.verify_assertion(self.assertion(second,sign_count=2),now=103)
        self.assertTrue(result["device_signature_verified"])
        self.assertFalse(result["owner_authority_session"])

    def test_no_face_images_accepted_as_credential(self):
        with self.assertRaises(DeviceDenied):
            TrustedPasskey(b"face",b"\x00"*32)

    def test_invalid_origin_context_rejected(self):
        with self.assertRaises(DeviceDenied):
            LocalOwnerDeviceVerifier(
                Path(self.dir.name)/"x.sqlite",
                rp_id="example.com",origin="https://attacker.invalid",trusted=self.trusted)


if __name__=="__main__":
    unittest.main()
