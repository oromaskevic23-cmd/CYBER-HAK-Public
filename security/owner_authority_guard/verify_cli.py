"""Optional offline Owner permit verifier with EXTERNAL trust-anchor configuration.

No owner key is generated/stored here. Missing trust configuration fails closed.
Not an automated GitHub ruleset or proof that the actual owner has enrolled.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .guard import AuthorityDenied, verify_approval


def verify_from_external_env(envelope, env, *, now):
    """Trust anchor must be injected from a protected operator environment."""
    kid = env.get("IMPERIAL_OWNER_TRUST_KEY_ID", "")
    hex_public = env.get("IMPERIAL_OWNER_TRUSTED_PUBLIC_KEY_HEX", "")
    epoch = env.get("IMPERIAL_OWNER_MIN_POLICY_EPOCH", "")
    if (type(kid) is not str or not kid
            or type(hex_public) is not str or len(hex_public) != 64
            or type(epoch) is not str or not epoch.isdecimal()):
        raise AuthorityDenied("EXTERNAL_OWNER_TRUST_NOT_ENROLLED")
    try:
        public_key = bytes.fromhex(hex_public)
        minimum = int(epoch)
    except (ValueError, TypeError):
        raise AuthorityDenied("INVALID_EXTERNAL_TRUST_CONFIGURATION") from None
    return verify_approval(envelope, {kid:public_key},
                           now=now, minimum_epoch=minimum)


def main():
    parser = argparse.ArgumentParser(
        description="Verify one scoped Ed25519 owner permit against an externally pinned public key")
    parser.add_argument("--envelope", type=Path, required=True)
    parser.add_argument("--now", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.envelope.is_symlink() or args.envelope.stat().st_size > 8192:
            raise AuthorityDenied("ENVELOPE_FILE_REJECTED")
        envelope = json.loads(args.envelope.read_text(encoding="utf-8"))
        result = verify_from_external_env(envelope, os.environ, now=args.now)
        print(json.dumps({
            "verified_action":result["action"],
            "target":result["target"],
            "owner_signature_verified_with_supplied_trust_anchor":True,
            "real_owner_enrollment_independently_proven":False,
            "production_authorized":False
        },sort_keys=True))
    except (AuthorityDenied, FileNotFoundError, OSError, ValueError) as exc:
        parser.exit(status=2,message="DENIED: "+type(exc).__name__+"\n")


if __name__=="__main__":
    main()
