"""Real Ed25519 negative tests for IMPERIAL Owner Authority Guard (LAB keys).

Generated keys are deliberately synthetic: tests do NOT establish that a
real Owner enrolled any signer or that GitHub branch protection is active.
"""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from security.owner_authority_guard.verify_cli import verify_from_external_env
from security.owner_authority_guard.guard import (
    AuthorityDenied, LocalAuthorityLedger, OWNER_NAME, OWNER_GITHUB,
    OWNER_ROLES, check_no_agent_takeover, signed_bytes, verify_approval
)


class OwnerAuthorityGuardTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "guard.sqlite"
        self.key = Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.trust = {"DEMO-OWNER-KEY": self.public}

    def signed(self, **updates):
        payload = {
            "schema": "imperial.owner.authority.v1",
            "issuer": "OWNER_OFFLINE_ENROLLMENT_REQUIRED",
            "owner_name": OWNER_NAME,
            "owner_github": OWNER_GITHUB,
            "owner_roles": list(OWNER_ROLES),
            "actor_type": "HUMAN_OWNER",
            "action": "APPROVE_ARCHITECTURE_CHANGE",
            "target": "IMP-Architecture-v1",
            "nonce": "a"*32,
            "issued_at": 100,
            "expires_at": 200,
            "policy_epoch": 7
        }
        payload.update(updates)
        kid = "DEMO-OWNER-KEY"
        return {
            "payload":payload,
            "key_id":kid,
            "signature":self.key.sign(signed_bytes(payload,kid)).hex()
        }

    def verify(self, envelope, **changes):
        inputs = {"now":120, "minimum_epoch":7}
        inputs.update(changes)
        return verify_approval(envelope, self.trust, **inputs)

    def test_valid_ephemeral_signature_with_exact_identity(self):
        result=self.verify(self.signed())
        self.assertEqual(result["owner_name"], OWNER_NAME)
        self.assertEqual(result["owner_roles"], OWNER_ROLES)

    def test_tampered_owner_name_is_denied(self):
        env=self.signed()
        env["payload"]["owner_name"]="Mallory"
        with self.assertRaises(AuthorityDenied):
            self.verify(env)

    def test_tampered_signature_is_denied(self):
        env=self.signed()
        env["signature"]="0"*128
        with self.assertRaisesRegex(AuthorityDenied,"SIGNATURE_INVALID"):
            self.verify(env)

    def test_foreign_signer_is_denied(self):
        with self.assertRaisesRegex(AuthorityDenied,"UNKNOWN_TRUST_ANCHOR"):
            verify_approval(self.signed(), {}, now=120, minimum_epoch=7)

    def test_false_owner_roles_are_denied_even_if_signed(self):
        with self.assertRaisesRegex(AuthorityDenied,"CANONICAL_OWNER_MISMATCH"):
            self.verify(self.signed(owner_roles=["Owner"]))

    def test_hanter_and_nca_cannot_claim_human_owner(self):
        for actor in ("HANTER", "NCA", "ORCHESTRATOR"):
            with self.subTest(actor=actor):
                with self.assertRaisesRegex(AuthorityDenied,"CANONICAL_OWNER_MISMATCH"):
                    self.verify(self.signed(actor_type=actor))

    def test_root_transfer_denied_even_if_signed(self):
        for action in ("TRANSFER_ROOT_AUTHORITY","CHANGE_OWNER","DISABLE_OWNER_GUARD",
                       "ROTATE_ROOT_TRUST","REMOVE_OWNER_KILL_SWITCH"):
            with self.subTest(action=action):
                with self.assertRaisesRegex(AuthorityDenied,"ROOT_CHANGE_OR_UNKNOWN"):
                    self.verify(self.signed(action=action))

    def test_agent_self_elevation_never_allowed(self):
        for role in ("Owner","Founder","CEO","Chief Systems Architect","CHANGE_OWNER"):
            with self.subTest(role=role):
                with self.assertRaisesRegex(AuthorityDenied,"ROOT_AUTHORITY_IMMUTABLE_IN_CODE"):
                    check_no_agent_takeover("NCA", role)

    def test_old_or_expired_permit_denied(self):
        with self.assertRaisesRegex(AuthorityDenied,"EXPIRED_OR_OVERSCOPED"):
            self.verify(self.signed(), now=200)
        with self.assertRaisesRegex(AuthorityDenied,"REVOKED_OR_OLD"):
            self.verify(self.signed(policy_epoch=6))
        with self.assertRaisesRegex(AuthorityDenied,"EXPIRED_OR_OVERSCOPED"):
            self.verify(self.signed(expires_at=500))

    def test_bogus_owner_github_rejected(self):
        with self.assertRaisesRegex(AuthorityDenied,"CANONICAL_OWNER_MISMATCH"):
            self.verify(self.signed(owner_github="another-account"))

    def test_untrusted_embedded_key_field_rejected(self):
        env=self.signed()
        env["public_key"]=self.public.hex()
        with self.assertRaisesRegex(AuthorityDenied,"BAD_ENVELOPE"):
            self.verify(env)

    def test_unknown_fields_rejected(self):
        env=self.signed()
        env["payload"]["skip_review"]=True
        with self.assertRaisesRegex(AuthorityDenied,"BAD_SIGNATURE_SCHEMA"):
            self.verify(env)

    def test_unvalidated_epoch_type_rejected(self):
        with self.assertRaisesRegex(AuthorityDenied,"REVOKED_OR_OLD"):
            self.verify(self.signed(policy_epoch=True))

    def test_missing_external_trust_denied(self):
        with self.assertRaisesRegex(AuthorityDenied,"MISSING_EXTERNAL_TRUST"):
            verify_approval(self.signed(), None, now=120, minimum_epoch=7)

    def test_permit_can_only_be_consumed_once_even_after_restart(self):
        ledger=LocalAuthorityLedger(self.path)
        env=self.signed()
        receipt=ledger.consume(env,self.trust,now=120,minimum_epoch=7)
        self.assertTrue(receipt["signature_cryptographically_verified"])
        self.assertFalse(receipt["owner_identity_enrollment_verified"])
        self.assertFalse(receipt["production_authorized"])
        with self.assertRaisesRegex(AuthorityDenied,"APPROVAL_REPLAY_DENIED"):
            LocalAuthorityLedger(self.path).consume(env,self.trust,now=121,minimum_epoch=7)

    def test_freeze_prevents_new_signed_actions(self):
        ledger=LocalAuthorityLedger(self.path)
        ledger.freeze()
        with self.assertRaisesRegex(AuthorityDenied,"GUARD_FROZEN"):
            LocalAuthorityLedger(self.path).consume(
                self.signed(),self.trust,now=120,minimum_epoch=7)

    def test_positive_scoped_actions_are_not_owner_transfer(self):
        for i,action in enumerate(("APPROVE_ARCHITECTURE_CHANGE",
                                   "AUTHORIZE_NCA_DEPLOYMENT","REVOKE_NCA",
                                   "FREEZE_EXECUTION","APPROVE_PRIVILEGED_CHANGE")):
            with self.subTest(action=action):
                env=self.signed(action=action,nonce=f"{i:032x}")
                self.assertEqual(self.verify(env)["action"],action)

    def test_refuse_unsigned_manifest(self):
        with self.assertRaisesRegex(AuthorityDenied,"BAD_ENVELOPE"):
            self.verify({"payload":self.signed()["payload"]})

    def test_wrong_key_signature_rejected(self):
        other=Ed25519PrivateKey.generate()
        env=self.signed()
        env["signature"]=other.sign(signed_bytes(env["payload"],env["key_id"])).hex()
        with self.assertRaisesRegex(AuthorityDenied,"SIGNATURE_INVALID"):
            self.verify(env)

    def test_external_trust_missing_is_denied(self):
        with self.assertRaisesRegex(AuthorityDenied, "EXTERNAL_OWNER_TRUST_NOT_ENROLLED"):
            verify_from_external_env(self.signed(), {}, now=120)

    def test_external_public_key_pin_accepts_cryptography_only(self):
        env = {
            "IMPERIAL_OWNER_TRUST_KEY_ID": "DEMO-OWNER-KEY",
            "IMPERIAL_OWNER_TRUSTED_PUBLIC_KEY_HEX": self.public.hex(),
            "IMPERIAL_OWNER_MIN_POLICY_EPOCH": "7"
        }
        verified = verify_from_external_env(self.signed(), env, now=120)
        self.assertEqual(verified["action"], "APPROVE_ARCHITECTURE_CHANGE")

    def test_external_trust_pin_rejects_foreign_key(self):
        foreign = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        env = {
            "IMPERIAL_OWNER_TRUST_KEY_ID": "DEMO-OWNER-KEY",
            "IMPERIAL_OWNER_TRUSTED_PUBLIC_KEY_HEX": foreign.hex(),
            "IMPERIAL_OWNER_MIN_POLICY_EPOCH": "7"
        }
        with self.assertRaisesRegex(AuthorityDenied, "SIGNATURE_INVALID"):
            verify_from_external_env(self.signed(), env, now=120)



if __name__=="__main__":
    unittest.main()
