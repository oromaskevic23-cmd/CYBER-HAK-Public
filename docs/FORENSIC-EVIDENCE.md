# CYBER HAK Forensic Evidence Model

Define governed defensive evidence rules and preservation practices used by CYBER HAK.

## Evidence Record Fields

Material evidence records should include, when applicable:
- evidence_id
- incident_id
- timestamp (UTC, ISO 8601)
- source (system, sensor, agent)
- collector (tool or human collector identifier)
- asset (affected asset or resource)
- classification (PUBLIC / PRIVATE / SECRET / RESTRICTED)
- hash (cryptographic digest when applicable)
- provenance (origin and acquisition method)
- integrity_status (e.g., VERIFIED / SUSPECT / CORRUPTED)
- chain_of_custody (who handled the evidence and when)
- related_policy_decision (approval or denial references)
- related_runtime_domain (runtime binding or environment)

## Evidence Types

Evidence may include, but is not limited to:
- logs (system, application, access)
- configuration snapshots
- security alerts and detector outputs
- policy decisions and approval records
- authorization records and AI Passport attestations
- runtime events and traces
- build and CI evidence (signed artifacts, build logs)
- dependency evidence and SBOM entries
- file hashes and binary samples (defensively handled)
- incident timelines and correlation artifacts
- forensic notes and analyst annotations

## Evidence Principles

- ORIGINAL != INTERPRETATION — preserve original artifacts separate from analyst interpretations.
- OBSERVATION != CONCLUSION — record raw observations and label derived conclusions.
- TIMESTAMP != EVENT PROOF WITHOUT CONTEXT — timestamps require provenance and supporting context.
- HASH != TRUST WITHOUT PROVENANCE — a hash requires provenance and known acquisition method to be meaningful.
- PUBLIC != SAFE TO DISCLOSE — classification constraints govern disclosure.

## Evidence Handling Requirements

- Record provenance and acquisition method for every evidence item.
- Apply integrity protection (signed or hashed storage) where feasible.
- Maintain an auditable chain-of-custody with timestamps and actor identifiers.
- Use classification markings and enforce disclosure controls before publishing any evidence.
- Preserve original artifacts; perform analysis on copies whenever possible.
- Where legal or regulatory obligations exist, follow preservation and notification requirements.

## Allowed Forensic Actions (Defensive Only)

- Acquire and preserve read-only copies of logs, snapshots, and artifacts.
- Capture hashes and metadata for verification.
- Export redacted or appropriately classified artifacts for authorized review.
- Transfer evidence to secure, integrity-protected storage with documented custody.

## Prohibitions and Safeguards

Explicitly forbid:
- silent evidence deletion
- retroactive evidence rewriting or fabrication
- untracked evidence mutation
- disclosure of PRIVATE, SECRET, or RESTRICTED evidence into the PUBLIC repository
- embedding sensitive secrets (credentials, keys, private material) into public artifacts

Do not include investigative techniques that would themselves violate policy, privacy, or applicable law.

## Validation and Audit

- Evidence stores should support append-only or versioned storage and cryptographic verification where practical.
- Periodically validate evidence integrity and chain-of-custody records.
- Audit evidence access and modifications; record rationale for each material access.
- Ensure evidence handling operations are themselves recorded in the Audit Ledger.

## Relationship to Incident Response

Evidence preservation is a required phase (IR-04) of the incident-response lifecycle. Preservation actions must precede non-reversible remediation that could alter or destroy evidence, except where immediate containment demands otherwise and is explicitly authorized and recorded.
