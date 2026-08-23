# CYBER HAK Threat Model

## Purpose

Define a governance-first defensive threat model for CYBER HAK. This document identifies protected boundaries, enumerates threat categories, and prescribes defensive objectives, prevention controls, detection expectations, and default governance responses.

## Protected Boundaries

- Architect authority
- HANTER command integrity
- SECURITY-ORCHESTRATOR-01 governance
- Security Nano Core Agent boundaries
- AI Passport identity integrity
- Enterprise IMPERIAL Skills capability boundaries
- Guardian Core policy enforcement
- Approval Gateway authorization
- Runtime Domain isolation
- Audit Ledger integrity
- PUBLIC / PRIVATE classification boundary
- credentials and secrets
- security evidence
- software supply chain
- external integrations
- economic and wallet boundaries

## Default Governance Response

For governance violations and high-risk threats the default response is:

- DENY
- ISOLATE
- RECORD
- ESCALATE_FOR_AUTHORIZED_REVIEW

## Threat Categories

Each category below includes:
- ID
- Name
- Protected boundary
- Defensive risk description
- Prevention controls
- Detection & evidence expectations
- Default response

### TM-01 Identity Spoofing
- Protected boundary: AI Passport and identity infrastructure
- Defensive risk: Unauthorized impersonation of agents or users leading to illicit actions.
- Prevention controls: Strong identity verification, multi-factor attestations, signed passports.
- Detection & evidence: Anomalous identity assertions, mismatched signatures, authentication anomalies logged in Audit Ledger.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-02 Authentication Bypass
- Protected boundary: Authentication systems
- Defensive risk: Unauthorized access when authentication is bypassed or compromised.
- Prevention controls: Hardened authentication, rate limits, anomaly detection, expired credential revocation.
- Detection & evidence: Failed/forged authentication attempts, unexpected token issuances in Audit Ledger.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-03 Authorization Bypass
- Protected boundary: Authorization gates and policies
- Defensive risk: Actions executed without required approvals or policies.
- Prevention controls: Policy-as-code, approval gateway enforcement, least-privilege checks.
- Detection & evidence: Policy decision overrides, missing approvals, Audit Ledger entries showing bypass attempts.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-04 Privilege Escalation
- Protected boundary: Privileged roles and access controls
- Defensive risk: Elevation to higher privileges enabling broader impact.
- Prevention controls: Privileged access reviews, session controls, just-in-time elevations, monitoring.
- Detection & evidence: Unexpected privilege grants, elevated sessions without approval.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-05 Capability Abuse
- Protected boundary: EIS capability registry and skill routing
- Defensive risk: Capabilities used beyond intended governance or scope.
- Prevention controls: Capability assignment controls, governance audits, capability attestation.
- Detection & evidence: Unusual capability invocation patterns, mismatched target scopes.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-06 Approval Gateway Bypass
- Protected boundary: Approval Gateway
- Defensive risk: Unauthorized execution due to bypassed approvals.
- Prevention controls: Immutable approval logs, multi-party endorsement, runtime verification.
- Detection & evidence: Missing approval entries, tampered gateway logs.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-07 Guardian Core Bypass
- Protected boundary: Guardian Core policy enforcement
- Defensive risk: Policy enforcement circumvented allowing ungoverned actions.
- Prevention controls: Guardian Core attestation, independent monitors, policy enforcement testing.
- Detection & evidence: Discrepant enforcement telemetry, governance mismatches in Audit Ledger.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-08 Runtime Domain Escape
- Protected boundary: Runtime Domain isolation
- Defensive risk: Processes or agents escaping isolated runtime boundaries.
- Prevention controls: Containerization, process sandboxing, network egress controls.
- Detection & evidence: Unexpected network flows, cross-domain process communication.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-09 Cross-Domain Contamination
- Protected boundary: Data and classification boundaries (PUBLIC/PRIVATE/SECRET)
- Defensive risk: Leakage or contamination of sensitive data across trust zones.
- Prevention controls: Data labeling, cross-domain guards, DLP controls.
- Detection & evidence: Data transfers across boundaries, DLP alerts, Audit Ledger records.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-10 Prompt / Instruction Injection
- Protected boundary: Input processing and instruction handling
- Defensive risk: Malicious instructions embedded in inputs causing unintended behavior.
- Prevention controls: Input sanitization, instruction whitelisting, robust parsing.
- Detection & evidence: Anomalous instruction patterns, chained inputs leading to unexpected outputs.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-11 Malicious Tool Invocation
- Protected boundary: Tooling invocation and runtime tool registries
- Defensive risk: Invocation of tools that perform unauthorized or harmful actions.
- Prevention controls: Tool vetting, invocation policies, runtime gating.
- Detection & evidence: Invocation logs without governance, mismatched tool signatures.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-12 Data Exfiltration
- Protected boundary: Data stores and egress paths
- Defensive risk: Unauthorized extraction of sensitive data.
- Prevention controls: Egress filtering, encryption at rest and in transit, DLP.
- Detection & evidence: Large or anomalous data transfers, suspicious egress destinations.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-13 Secret Exposure
- Protected boundary: Secrets stores and key management
- Defensive risk: Exposure or leakage of credentials, keys or secrets.
- Prevention controls: Secrets management, rotation, limited exposure, scanning.
- Detection & evidence: Secrets in logs, unexpected access to secret stores.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-14 Audit Ledger Tampering
- Protected boundary: Audit Ledger integrity and ordering
- Defensive risk: Tampering or reordering of audit records to erase evidence.
- Prevention controls: Append-only ledgers, signed entries, external attestations.
- Detection & evidence: Gaps in sequences, signature validation failures.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-15 Evidence Tampering
- Protected boundary: Evidence stores and forensic data
- Defensive risk: Alteration or removal of forensic evidence.
- Prevention controls: WORM storage, checksums, independent backups.
- Detection & evidence: Checksum mismatches, missing artifacts.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-16 Replay Attacks
- Protected boundary: Message ordering and uniqueness guards
- Defensive risk: Replayed requests causing unintended actions.
- Prevention controls: Nonces, timestamps, idempotency checks.
- Detection & evidence: Duplicate transaction signatures, repeated nonces.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-17 TOCTOU / Decision Drift
- Protected boundary: Decision pipelines and time-of-check/time-of-use
- Defensive risk: Race conditions leading to inconsistent checks and uses.
- Prevention controls: Atomic operations, re-validation at execution, monitoring.
- Detection & evidence: Timing anomalies, mismatched pre/post state.
- Default response: DENY, ISOLATE, RECORD, ESCALATE_FOR_AUTHORIZED_REVIEW

### TM-18 Supply Chain Compromise
{