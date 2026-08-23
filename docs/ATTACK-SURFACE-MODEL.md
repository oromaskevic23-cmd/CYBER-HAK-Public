# CYBER HAK Attack Surface Model

This document describes high-level defensive attack surfaces for CYBER HAK and defines protected assets, trust boundaries, primary defensive risks, required controls, and expected evidence for each surface.

1. Identity Surface
- Protected assets: AI Passport, authentication tokens, identity metadata
- Trust boundary: Identity providers and verification services
- Primary defensive risks: Identity spoofing, credential compromise, unauthorized impersonation
- Required controls: Strong identity verification, MFA, signed passports, identity lifecycle management
- Expected evidence: Authentication logs, passport signatures, identity attestation records

2. Capability Surface
- Protected assets: EIS capability registry, skill routing tables, capability assignments
- Trust boundary: Capability registration and assignment interfaces
- Primary defensive risks: Capability abuse, unauthorized capability assignment, routing tampering
- Required controls: Capability attestation, assignment approval workflows, access controls
- Expected evidence: Capability registry change logs, approval records, invocation telemetry

3. Governance Surface
- Protected assets: Guardian Core, Approval Gateway, policy decision artifacts
- Trust boundary: Governance control plane and policy stores
- Primary defensive risks: Governance bypass, policy tampering, unauthorized approvals
- Required controls: Immutable policy logs, multi-party approvals, independent monitors
- Expected evidence: Policy version history, approval gateway records, guardian audit logs

4. Runtime Surface
- Protected assets: Runtime Domains, execution environments, process boundaries
- Trust boundary: Runtime isolation and network egress controls
- Primary defensive risks: Runtime domain escape, unauthorized process communication, uncontrolled egress
- Required controls: Container sandboxing, network policy, process isolation, egress filtering
- Expected evidence: Runtime telemetry, network flows, container audit logs

5. Agent Surface
- Protected assets: Security Nano Core Agents, agent-to-agent communication channels
- Trust boundary: Agent orchestration and delegation plane (SECURITY-ORCHESTRATOR-01)
- Primary defensive risks: Malicious agent behavior, unauthorized delegation, agent compromise
- Required controls: Agent vetting, secure communication, delegation approval, least-privilege assignment
- Expected evidence: Agent interaction logs, delegation approvals, agent attestation records

6. Data Surface
- Protected assets: PUBLIC, PRIVATE, SECRET, RESTRICTED data; logs; evidence; configuration; security metadata
- Trust boundary: Data classification and storage controls
- Primary defensive risks: Cross-domain contamination, data exfiltration, accidental exposure
- Required controls: Data labeling, DLP, encryption, access controls
- Expected evidence: Data access logs, DLP alerts, encryption key access records

7. Audit Surface
- Protected assets: Audit Ledger, ordered event records, evidence chains
- Trust boundary: Audit storage, signing and attestation services
- Primary defensive risks: Audit ledger tampering, evidence loss, replay attacks
- Required controls: Append-only ledgers, signed entries, external attestations, redundancy
- Expected evidence: Ledger sequence proofs, signed entries, backup records

8. Software Supply Chain Surface
- Protected assets: Dependencies, packages, containers, build artifacts, CI/CD pipelines
- Trust boundary: Build systems and artifact registries
- Primary defensive risks: Supply chain compromise, malicious dependency injection, CI/CD tampering
- Required controls: SBOMs, signed artifacts, build integrity verification, dependency scanning
- Expected evidence: SBOM records, build signatures, dependency scan reports

9. API / Integration Surface
- Protected assets: APIs, webhooks, external connectors, repository integrations
- Trust boundary: Integration points and API gateways
- Primary defensive risks: Unauthorized access, injection via integrations, data leakage through connectors
- Required controls: API authentication and authorization, rate limiting, input validation
- Expected evidence: API gateway logs, integration audit trails, webhook delivery records

10. Economic Boundary Surface
- Protected assets: Payment intents, wallet references, financial metadata, authorization boundaries
- Trust boundary: Financial interfaces and wallet access controls
- Primary defensive risks: Unauthorized financial actions, private-key exposure, unauthorized transfers
- Required controls: No autonomous wallet authority, separation of duties, offline signing, strict approval governance
- Expected evidence: Payment approval records, signed transaction artifacts, external settlement logs

State clearly:

CYBER HAK has no autonomous wallet authority. Security capability does not grant financial execution authority.

No security capability may independently:
- read wallet private keys
- sign financial transactions
- transfer cryptocurrency
- bypass payment authorization
- authorize settlement
