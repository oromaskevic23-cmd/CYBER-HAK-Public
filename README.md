# CYBER HAK

Defensive security and digital immune-system architecture for IMPERIAL Core.

**Status: TESTED — bounded defensive references; AuditShield v0.2 evidence is open PR #1.**  
Evidence checkpoint: **25 October 2026**.

## Founder and architectural authority

**Alexander Romaskevich — RomaskevicH**  
Founder • Owner • CEO of IMPERIAL Core  
Architect / Final Architectural Decision Authority · Ukraine

**HANTER — AI Command Center / Chief Systems** operates under the founder's architectural decisions. This role does not imply a single unrestricted global orchestrator.

## Public technical evidence

[Commit `d683379`](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/commit/d68337938f3bba6d81bc2419b884cd893e8262d3) · [Open PR](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/pull/1) · [CI job](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/40131894877/job/120985165334)

**99/99 PASS.** Defensive AuditShield reference tests and scoped anonymous audits of immutable public revisions. No deployed continuous protection established.

This is tested reference scope, not a merged release or verified production deployment.

## ORION Guardian Review Gate — experimental branch

A new [defensive Guardian Review Gate](src/orion-guardian-gate.mjs) has been implemented as a nonproduction increment of the existing [AuditShield PR #1](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/pull/1). It checks real Ed25519-signed advisory envelopes against immutable public [ORION code](https://github.com/oromaskevic23-cmd/ORION-Public/pull/3), a separately supplied public-key allowlist, claimed evidence digests, and the report's self-consistency. An explicit owner HALT status is mandatory and unknown status fails closed.

- [Verified CI #40213964562](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/40213964562): **99/99** AuditShield reference tests and **17/17** ORION Guardian pinned-source tests PASS.
- [Threat model and limitations](docs/ORION_GUARDIAN_REVIEW_v0.1.md).
- All successful decisions require **human review**. No source statement is accepted as evidence of actual truth, human ownership, production approval, or a deployed Guardian Core runtime. Private HANTER and LEGION source is not imported.

**Current status:** TESTED REFERENCE IN DRAFT PR; Guardian Core production admission, verified owner halt attestation, revocation, durable Audit Ledger and real Approval Gateway are not connected.

## Existing main-branch reference

The defensive v0.1 source is in [src](src), with tests in [test](test) and the reproducible command `npm run verify`. [Main-branch CI](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/40128335692) succeeded for revision `52241cf70ae5e9b8abd55c854b6aaedd52a6864d`. Registry sizes describe files and design scope, not deployed agent counts. [Security policy](SECURITY.md).

## Architecture and governance

Preserve the Federated Multi-Orchestrator Architecture, multiple organizational structures, professional teams and dynamic Nano Core Agents. AI Passport, Enterprise Skills, Guardian Core, Approval Gateway and Audit Ledger remain architectural requirements. Identity ≠ Authority; Capability ≠ Approval. Zero Trust, Deny by Default and Fail Closed apply across the Public / Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary.

## Documentation and continuity

- [Current ecosystem architecture](https://github.com/oromaskevic23-cmd/IMPERIAL-Core-Public/blob/main/ARCHITECTURE.md).
- [Founder identity — EN / UK / RU](https://github.com/oromaskevic23-cmd/IMPERIAL-Core-Public/blob/main/docs/FOUNDER_IDENTITY.md).
- [Public portfolio and status definitions](https://github.com/oromaskevic23-cmd/IMPERIAL-Core-Public/blob/main/docs/PORTFOLIO.md).
- [Verified milestones](https://github.com/oromaskevic23-cmd/IMPERIAL-Core-Public/blob/main/docs/EVIDENCE.md) and [engineering roadmap](https://github.com/oromaskevic23-cmd/IMPERIAL-Core-Public/blob/main/ROADMAP.md).
- [Historical public specification notes](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/blob/52241cf70ae5e9b8abd55c854b6aaedd52a6864d/README.md) — retained in Git history; earlier role wording is superseded and design narratives do not establish runtime operation.

## Collaboration, security and attribution

Start non-confidential collaboration through the [founder profile](https://github.com/oromaskevic23-cmd). Follow the [responsible-disclosure guidance](https://github.com/oromaskevic23-cmd/IMPERIAL-Core-Public/blob/main/SECURITY.md) before sharing sensitive security information. Contributions should cite revisions, meaningful tests and limitations.

**Authorship: Alexander Romaskevich — RomaskevicH.** Third-party rights, existing notices and licenses remain unchanged. Public visibility does not grant an additional license. No private source or private test logs are imported here.

**Build software. Verify everything.**
