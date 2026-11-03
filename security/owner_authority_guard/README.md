# IMPERIAL OWNER AUTHORITY GUARD — v1.0

**Product:** CYBER HAK / IMPERIAL Core sovereign authorization boundary.  
**Founder • Owner • CEO • Chief Systems Architect:** Alexander Nikolaevich Romaskevich (RomaskevicH).  
**Architecture:** Architect → HANTER → federated domain orchestrators → NCA; Root authority is **never delegated to an agent**.  
**Budget:** FREE_ONLY. No paid products, domains, account upgrades or server deployments authorized.  
**Verified implementation:** Ed25519 signature validation, strict canonical identity/roles, tamper rejection, fail-closed external public-key trust, signed scoped action checks, local atomic replay prevention and freeze. **This is a LAB security implementation, not an activated organization-wide lock.**

## What the mechanism prevents when actually enforced

A normal NCA, HANTER route, orchestrator, skill/plugin update, model output, document or Git commit MUST NOT be accepted as proof that the author became **Founder, Owner, CEO or Chief Systems Architect**. An agent may execute a narrow authorized task but cannot amend the root authority, declare a new Owner, disable the owner's emergency stop or rotate the trust anchor.

A valid signed scoped *task authorization* cannot change the canonical root identity: attempts such as `CHANGE_OWNER`, `TRANSFER_ROOT_AUTHORITY`, `REPLACE_ARCHITECT`, `ROTATE_ROOT_TRUST`, `DISABLE_OWNER_GUARD` and `REMOVE_OWNER_KILL_SWITCH` are structurally rejected. Root transfer and trust recovery are out-of-band governance/legal operations, never background agent operations.

### Canonical role record

- **Name:** Alexander Nikolaevich Romaskevich
- **GitHub account:** `oromaskevic23-cmd` (account label, NOT identity proof)
- **Roles:** `Founder`, `Owner`, `CEO`, `Chief Systems Architect`
- **Final Architectural Decision Authority:** the Architect.
- **AI authorization:** all NCA, HANTER, ASTRA and other orchestrators are subordinate; no system-wide sudo-equivalent identity is created for an AI.

This is a technical authorization rule and authorship record, **not proof of company incorporation, legal ownership or a claim to third-party contributors' code**. Git commit history, third-party licenses and contributor attribution remain intact.

## Four independent defense layers

1. **Owner proof-of-control:** actual Owner enrolls a protected Ed25519 public-key trust anchor on an independent trusted device. Private signing key stays outside the GitHub repo, browser, chat, server logs and NCA tooling. Enroll through a documented ownership-verification process; never auto-generate a key in a CI runner and call it Owner enrollment.
2. **Runtime signed authorization:** each sensitive request includes immutable action, exact target, 32-hex nonce, external policy epoch, max 300-second lifetime, Owner metadata and detached signature. Only an externally pinned public key can verify the permit. An agent cannot choose its own verifier key or edit permission checks through task data.
3. **Code and configuration integrity:** protect `main` with active branch ruleset, required status checks and no bypasses; route protected files through CODEOWNERS. Cross-repo CI and signed audit evidence must be verified by an independent protected policy service. Merely adding CODEOWNERS or CI files does **not** make a branch protected.
4. **Incident recovery:** protected Owner Kill Switch at the private control plane revokes permits/leases and aborts workers, and independent Audit Ledger records every attempted root-role change. Private master key recovery requires out-of-band authenticated Owner procedure and key rotation, with measured propagation and verification. Do not reveal key material or recovery secrets to NCA or public GitHub.

## API and source boundaries

- [guard.py](guard.py) — `verify_approval`, `check_no_agent_takeover`, `LocalAuthorityLedger`. For demonstration only; no actual Owner key enrolled.
- [verify_cli.py](verify_cli.py) — optional offline verification against a public-key trust anchor injected from the operator's protected environment; missing configuration fails closed.
- [tests/test_guard.py](tests/test_guard.py) — real Ed25519 tests, including forgeries, identity changes, foreign key, false agent role, root transfer, expired policy, replay after process restart and local freeze.
- [CI workflow](../../.github/workflows/owner-authority-guard.yml) — read-only GitHub Actions. This verifies the algorithm but does not activate a repository ruleset.

### Local test

```bash
python3 -m pip install -r security/owner_authority_guard/requirements.txt
python3 -m unittest discover -s security/owner_authority_guard/tests -p 'test_guard.py' -v
```

### External trust anchor — design, not activated

The CLI requires these variables on an **authorized owner's trusted computer or properly managed private runtime**, never a public browser or untrusted NCA process:

```text
IMPERIAL_OWNER_TRUST_KEY_ID
IMPERIAL_OWNER_TRUSTED_PUBLIC_KEY_HEX
IMPERIAL_OWNER_MIN_POLICY_EPOCH
```

No real values are committed. The public key is non-secret but **its authoritative binding must be protected outside the code and signed artifacts**. The private key must never be pasted into a chat or copied into GitHub. A signature proves possession of the corresponding private key; it is not, by itself, evidence of the civil identity or legal rights of the keyholder.

Invoke the verifier only after a trust-anchor enrollment exists:

```bash
python3 -m security.owner_authority_guard.verify_cli \
  --envelope /path/to/owner-approved-envelope.json \
  --now 1793700000
```

The command rejects missing trust, unapproved action or invalid signature. It **never executes** the signed action; this is deliberate separation of decision and execution. The time above is an example, not a valid active permit or evidence of approval.

## HANTER / NCA integration contract

**Future required sequence (not wired into production):**

`IntentLock → Owner Scope Verification → AI Passport → Guardian Core → Approval Gateway → scoped federated Orchestrator → NCA worker → Independent QA → Audit Ledger → ProofGraph`.

Owner metadata in a prompt is not an authority credential. A signed Owner approval does not bypass independent safety/compliance review; it can only authorize a narrowly permitted operation. Owner Kill Switch must remain higher priority than all ordinary work tickets. Customer data, public/private boundary and CRYPTO IMPERIAL Ecosystem Boundary stay independent.

## Hard limitations

- Repo administrators or compromised GitHub accounts may edit, disable or bypass CI/rulesets unless enforcement is independently configured and monitored. An on-repo verification script **cannot** defend against a platform administrator who can replace the script and the required checks.
- The existing GitHub Ruleset inventory in private IMPERIAL Core dated 2026-11-01 found **enforcement NOT VERIFIED** across 30 repositories; 7 private repo queries faced plan/access restrictions. Do **not** claim an unbypassable branch policy or purchase GitHub Enterprise under FREE_ONLY.
- A local SQLite replay ledger has no cross-region consistency, durable attested signatures or protection from local database administrator tampering. The actual Owner Kill Switch is not connected here.
- No user private key is created, stored or enrolled by this code. A test's ephemeral key is a lab fixture, not the Owner's identity.
- Legal control of shares/entities and true intellectual-property rights depend on valid documents and applicable law, not text in a repo. This module protects technical authorization after activation, not legal title.

## Acceptance gates before saying 'Owner Authority Locked'

1. Actual Owner out-of-band identity check and protected public-key enrollment, with approved key-recovery and revocation plan.
2. Canonical policy stored in a trusted protected location, bound to the enrolled Owner key; verify both signature and trusted epoch.
3. Verified active ruleset on the exact repository, no bypasses, negative test showing an unauthorized edit to the guard **cannot merge**.
4. All HANTER, NCA Factory, CRM, cloud connectors, Guardian and Approval Gateway call the protected verifier before any root-sensitive effect; independent audit of call sites and escape paths.
5. Independent proof of real remote worker revocation / Owner Kill Switch propagation.
6. Signed cross-repo audit evidence and penetration tests by independent reviewers.

**Never mark these gates PASS from the existence of this README or code alone.**

Architecture Before Implementation → Implementation Before Evidence → Evidence Before Authority.
