# CYBER HAK Capability Registry

## Purpose

The CYBER HAK Capability Registry describes the public, defensive capability model and routing surface for governed security activities. It documents the public-facing structure and governance metadata for the capability families that comprise the CYBER HAK defensive architecture. The registry represents defensive coverage and does not grant execution authority or production authorization.

## Governance

Permanent laws:

- CAPABILITY != AUTHORITY
- CAPABILITY != APPROVAL
- KNOWLEDGE != PERMISSION
- DISCOVERY != AUTHORIZATION

Governance chain:

AI Passport
-> Enterprise IMPERIAL Skills (EIS)
-> Guardian Core
-> Approval Gateway
-> Runtime Domain
-> Audit Ledger

Command authority: HANTER

Final architectural authority: Architect

Default policy: DENY
Security NCA: 10
Governed Security Skills (declared scale): 512
Capability Families: 59

## Capability Scale

This registry declares the defensive capability-model scale:

- 512 governed security skills (declared, not published individually)
- 59 capability families
- 10 Security Nano Core Agents

This PUBLIC repository does not publish or claim runtime verification of individual PRIVATE skills.

## 59 Capability Families

The registry indexes 59 defensive capability families. Each family entry in the machine-readable registry contains metadata and a deny-by-default governance posture. The public registry enumerates family coverage and one-line defensive purposes; it does not expose private skill implementations.

(See registry/CAPABILITY-FAMILIES.json for the canonical machine-readable list of families.)

## Authorization Boundary

The registry describes defensive-security coverage and routing.

It does not grant unrestricted execution authority. Active execution requires explicit governance, evidence, and binding to runtime controls via the Governance Chain above.

## Public / Private Truth Boundary

This PUBLIC registry documents architecture and coverage. It does NOT publish PRIVATE HANTER runtime source, private skill implementations, credentials, keys, or any offensive procedures.

512 governed security skills is a declared capability-model scale; individual skills remain private and subject to governance, verification, and production authorization outside this PUBLIC surface.

## Validation Rules

- Registry metadata must report: total_capability_families = 59, governed_security_skills = 512, security_nca = 10, default_policy = DENY, T3 policy = ALWAYS DENY.
- Every family ID must be unique and conform to CF-001..CF-059.
- Every family default_policy must be DENY_UNLESS_GOVERNED.
- The registry is CLASSIFICATION: PUBLIC and execution_authority = NONE_BY_REGISTRY.
- The registry is descriptive only; it does not imply execution rights or runtime exposure.

