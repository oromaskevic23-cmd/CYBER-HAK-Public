# CYBER HAK Public

CYBER HAK is the governed defensive-security architecture of IMPERIAL Core.

Author: Alexander Romaskevich  
Founder • Owner • CEO • Chief Systems Architect of IMPERIAL Core  
Parent Architecture: HANTER  
Classification: PUBLIC

## Purpose

CYBER HAK defines a governed defensive-security domain operating under Zero Trust, deny-by-default policy, explicit authorization, bounded execution and evidence-first verification.

## Architecture

Architect  
→ HANTER  
→ SECURITY-ORCHESTRATOR-01  
→ 10 Security Nano Core Agents  
→ Governed Security Capabilities

## Security Scale

- Security Nano Core Agents: 10  
- Governed Security Skills: 512  
- Capability Families: 59  
- Default Policy: DENY  
- T3 Autonomous Activity: ALWAYS DENY

## Governance Chain

AI Passport  
→ Enterprise IMPERIAL Skills (EIS)  
→ Guardian Core  
→ Approval Gateway  
→ Runtime Domain  
→ Audit Ledger

## Zero-Trust Laws

- Identity != Authority  
- Capability != Approval  
- Intelligence != Privilege  
- Knowledge != Permission  
- Discovery != Authorization

## Public / Private Boundary

This repository is a PUBLIC architecture and documentation surface. It must not contain PRIVATE HANTER runtime source, credentials, API keys, tokens, passwords, private keys, seed phrases, private Audit Ledger records, or sensitive incident evidence.

## Truth Boundary

Architecture != Specification  
Specification != Implementation  
Implementation != Testing  
Testing != Runtime Verification  
Runtime Verification != Production Authorization

Current status:

PUBLIC ARCHITECTURE = DEFINED  
PRIVATE HANTER RUNTIME WIRING = NOT VERIFIED BY THIS PUBLIC REPOSITORY  
LIVE PRODUCTION RUNTIME = NOT VERIFIED  
PRODUCTION AUTHORIZATION = NOT AUTHORIZED

## 10 Security Nano Core Agents

1. [SENTINEL](agents/01-SENTINEL.md)  
2. [VULCAN](agents/02-VULCAN.md)  
3. [CERBERUS](agents/03-CERBERUS.md)  
4. [AEGIS](agents/04-AEGIS.md)  
5. [BASTION](agents/05-BASTION.md)  
6. [ARGUS](agents/06-ARGUS.md)  
7. [MINERVA](agents/07-MINERVA.md)  
8. [FORENSIC](agents/08-FORENSIC.md)  
9. [REDSHIELD](agents/09-REDSHIELD.md)  
10. [GUARDIAN-SEC](agents/10-GUARDIAN-SEC.md)

[Security NCA Fleet Index](agents/README.md)

## Governed Capability Registry

CYBER HAK defines 512 governed security skills across 59 capability families and 10 specialized Security Nano Core Agents.

The registry represents defensive-security coverage and routing, not unrestricted execution authority.

- [Capability Registry](docs/CAPABILITY-REGISTRY.md)  
- [Capability Families JSON](registry/CAPABILITY-FAMILIES.json)  
- [Security Activity Tiers](docs/SECURITY-TIERS.md)

## Threat Model & Attack Surface

- [Threat Model](docs/THREAT-MODEL.md)  
- [Attack Surface Model](docs/ATTACK-SURFACE-MODEL.md)  
- [Threat Categories JSON](registry/THREAT-CATEGORIES.json)

## Incident Response & Forensic Evidence

CYBER HAK defines a governed incident-response lifecycle from detection through containment, evidence preservation, analysis, remediation, verification and audited closure.

- [Incident Response](docs/INCIDENT-RESPONSE.md)  
- [Forensic Evidence Model](docs/FORENSIC-EVIDENCE.md)  
- [Incident Severity JSON](registry/INCIDENT-SEVERITY.json)

Architecture Before Implementation.
Evidence Before Claims.
CREATE:

docs/CONTINUOUS-SECURITY-ASSURANCE.md
docs/SECURITY-OBSERVABILITY.md
registry/ASSURANCE-CONTROLS.json

UPDATE:

README.md
PUBLIC-MANIFEST.json


========================================
docs/CONTINUOUS-SECURITY-ASSURANCE.md
========================================

# CYBER HAK Continuous Security Assurance

CYBER HAK defines a governed defensive assurance model for continuously evaluating security controls, governance integrity, evidence quality and configuration drift.

Classification: PUBLIC

This document defines architecture and verification requirements only.

LIVE PRODUCTION MONITORING = NOT VERIFIED
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED

## Assurance Principles

- Evidence Before Claims
- Unknown Is Not Pass
- Detection Is Not Authorization
- Observation Is Not Authority
- Capability Is Not Approval
- Failure Must Be Recorded
- Privileged Remediation Requires Governance

## Assurance States

PASS — sufficient evidence supports the required control.

WARN — partial degradation or incomplete non-critical evidence exists.

FAIL — required protection is violated or cannot satisfy policy.

UNKNOWN — available evidence is insufficient for a valid conclusion.

UNKNOWN != PASS

## Assurance Control Domains

### AS-01 — Governance Integrity

Objective:
Verify that security actions remain bound to canonical governance.

Expected evidence:
policy decisions, approval references, governance state and audit records.

Failure condition:
execution or authorization occurs outside the governed chain.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-02 — Identity & Authorization Integrity

Objective:
Verify identity, authentication and authorization boundaries.

Expected evidence:
AI Passport state, authorization decisions and identity assertions.

Failure condition:
missing, invalid, expired or unauthorized identity/authority state.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-03 — Capability Boundary Integrity

Objective:
Ensure capabilities cannot exceed explicitly governed scope.

Expected evidence:
capability identifiers, scope bindings and policy decisions.

Failure condition:
capability use exceeds authorized boundaries.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-04 — Approval Path Integrity

Objective:
Verify active privileged operations pass through required approval controls.

Expected evidence:
Approval Gateway decisions and associated policy references.

Failure condition:
required approval is missing, bypassed or invalid.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-05 — Runtime Domain Isolation

Objective:
Verify security workloads remain inside assigned Runtime Domains.

Expected evidence:
runtime identity, domain binding and isolation state.

Failure condition:
cross-domain execution or unauthorized boundary expansion.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-06 — Security NCA Fleet Integrity

Objective:
Verify Security Nano Core Agents operate under assigned roles and governed authority.

Expected evidence:
agent identity, assigned capability set, runtime state and policy results.

Failure condition:
agent identity drift, privilege expansion or unauthorized role change.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-07 — Audit Ledger Integrity

Objective:
Verify evidence and decision records remain traceable and integrity-protected.

Expected evidence:
audit event identifiers, hashes, timestamps and provenance.

Failure condition:
missing, corrupted, rewritten or unverifiable audit evidence.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-08 — Secret & Classification Protection

Objective:
Protect credentials, sensitive information and classified material.

Expected evidence:
classification state, access decisions and secret-scan results.

Failure condition:
unauthorized disclosure, access or classification-boundary violation.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-09 — Software Supply Chain Integrity

Objective:
Verify dependencies and source inputs remain controlled and attributable.

Expected evidence:
dependency metadata, hashes, provenance and integrity results.

Failure condition:
untrusted, unverifiable or policy-violating software input.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-10 — Detection & Telemetry Health

Objective:
Verify security telemetry remains sufficiently available for defensive assessment.

Expected evidence:
telemetry freshness, source identity and collection health state.

Failure condition:
required defensive visibility is missing or materially degraded.

Governed response:
WARN_OR_FAIL → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-11 — Incident Response Readiness

Objective:
Verify incident-response controls and evidence paths remain available.

Expected evidence:
response procedures, severity registry and evidence-handling controls.

Failure condition:
required response capability or evidence-preservation control is unavailable.

Governed response:
FAIL → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-12 — Evidence Integrity & Security Drift

Objective:
Detect material deviation from expected security and governance state.

Expected evidence:
baseline state, current state, hashes, policy version and evidence provenance.

Failure condition:
unapproved drift, missing evidence or unverifiable state transition.

Governed response:
DENY_WHERE_REQUIRED → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

## Assurance Cycle

OBSERVE
→ COLLECT EVIDENCE
→ VALIDATE
→ COMPARE AGAINST POLICY
→ DETECT DRIFT
→ CLASSIFY
→ RESPOND
→ RECORD
→ REVERIFY

## Security Drift Categories

DRIFT-01 — Governance Drift  
DRIFT-02 — Identity Drift  
DRIFT-03 — Authorization Drift  
DRIFT-04 — Capability Drift  
DRIFT-05 — Policy Drift  
DRIFT-06 — Runtime Configuration Drift  
DRIFT-07 — Agent Configuration Drift  
DRIFT-08 — Dependency Drift  
DRIFT-09 — Detection Drift  
DRIFT-10 — Evidence Drift

Drift detection does not grant autonomous privileged remediation authority.

Privileged remediation remains governed by:

AI Passport
→ Enterprise IMPERIAL Skills (EIS)
→ Guardian Core
→ Approval Gateway
→ Runtime Domain
→ Audit Ledger


========================================
docs/SECURITY-OBSERVABILITY.md
========================================

# CYBER HAK Security Observability

CYBER HAK defines security observability as governed defensive visibility into system security state.

Classification: PUBLIC

## Signal Classes

### SIG-01 — Identity Signals

Purpose:
Observe identity, authentication and authorization state.

Safe evidence:
timestamps, identity-state transitions, authorization results and policy references.

### SIG-02 — Policy & Approval Signals

Purpose:
Observe governance and approval decisions.

Safe evidence:
decision identifiers, allow/deny outcomes and approval state.

### SIG-03 — Capability Signals

Purpose:
Observe governed capability assignment and use.

Safe evidence:
capability identifiers, bounded scope and policy outcomes.

### SIG-04 — Runtime Domain Signals

Purpose:
Observe Runtime Domain health and isolation state.

Safe evidence:
runtime state, domain identity and configuration hashes.

### SIG-05 — Agent Fleet Signals

Purpose:
Observe Security NCA identity, assignment and governed operational state.

Safe evidence:
agent identifiers, role state, lifecycle transitions and policy decisions.

### SIG-06 — Audit & Evidence Signals

Purpose:
Observe evidence integrity and audit continuity.

Safe evidence:
audit identifiers, timestamps, hashes and provenance status.

### SIG-07 — Supply Chain Signals

Purpose:
Observe software dependency and provenance state.

Safe evidence:
dependency metadata, package hashes, provenance and validation state.

### SIG-08 — Incident Response Signals

Purpose:
Observe defensive incident lifecycle state.

Safe evidence:
incident identifier, severity transition, containment state and evidence status.

## Protected Information

Observability data must not expose:

- credentials
- access tokens
- API keys
- private keys
- seed phrases
- PRIVATE HANTER runtime source
- private infrastructure topology
- sensitive incident payloads
- private Audit Ledger contents

## Truth Boundary

PUBLIC OBSERVABILITY MODEL = DEFINED

LIVE TELEMETRY PIPELINE = NOT_VERIFIED

LIVE SOC / SIEM INTEGRATION = NOT_VERIFIED

PRODUCTION MONITORING = NOT_VERIFIED

PRODUCTION AUTHORIZATION = NOT_AUTHORIZED


========================================
registry/ASSURANCE-CONTROLS.json
========================================

{
  "registry": "CYBER HAK Assurance Controls",
  "classification": "PUBLIC",
  "version": "1.0.0",
  "total_assurance_controls": 12,
  "total_signal_classes": 8,
  "total_drift_categories": 10,
  "default_policy": "DENY",
  "unknown_is_pass": false,
  "production_monitoring": "NOT_VERIFIED",
  "controls": [
    {"id":"AS-01","name":"Governance Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-02","name":"Identity & Authorization Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-03","name":"Capability Boundary Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-04","name":"Approval Path Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-05","name":"Runtime Domain Isolation","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-06","name":"Security NCA Fleet Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-07","name":"Audit Ledger Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-08","name":"Secret & Classification Protection","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-09","name":"Software Supply Chain Integrity","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-10","name":"Detection & Telemetry Health","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-11","name":"Incident Response Readiness","default_response":"DENY_RECORD_ESCALATE"},
    {"id":"AS-12","name":"Evidence Integrity & Security Drift","default_response":"DENY_RECORD_ESCALATE"}
  ],
  "signal_classes": [
    {"id":"SIG-01","name":"Identity Signals"},
    {"id":"SIG-02","name":"Policy & Approval Signals"},
    {"id":"SIG-03","name":"Capability Signals"},
    {"id":"SIG-04","name":"Runtime Domain Signals"},
    {"id":"SIG-05","name":"Agent Fleet Signals"},
    {"id":"SIG-06","name":"Audit & Evidence Signals"},
    {"id":"SIG-07","name":"Supply Chain Signals"},
    {"id":"SIG-08","name":"Incident Response Signals"}
  ],
  "drift_categories": [
    {"id":"DRIFT-01","name":"Governance Drift"},
    {"id":"DRIFT-02","name":"Identity Drift"},
    {"id":"DRIFT-03","name":"Authorization Drift"},
    {"id":"DRIFT-04","name":"Capability Drift"},
    {"id":"DRIFT-05","name":"Policy Drift"},
    {"id":"DRIFT-06","name":"Runtime Configuration Drift"},
    {"id":"DRIFT-07","name":"Agent Configuration Drift"},
    {"id":"DRIFT-08","name":"Dependency Drift"},
    {"id":"DRIFT-09","name":"Detection Drift"},
    {"id":"DRIFT-10","name":"Evidence Drift"}
  ]
}


========================================
README.md — ADD
========================================

## Continuous Security Assurance & Observability

CYBER HAK defines a continuous defensive assurance architecture for validating governance controls, evidence integrity, telemetry health and security drift without granting autonomous privileged remediation authority.

- [Continuous Security Assurance](docs/CONTINUOUS-SECURITY-ASSURANCE.md)
- [Security Observability](docs/SECURITY-OBSERVABILITY.md)
- [Assurance Controls JSON](registry/ASSURANCE-CONTROLS.json)


========================================
PUBLIC-MANIFEST.json — ADD
========================================

"continuous_security_assurance": "DEFINED",
"security_observability": "DEFINED",
"assurance_controls": 12,
"observability_signal_classes": 8,
"security_drift_categories": 10,
"unknown_is_pass": false,
"live_telemetry_pipeline": "NOT_VERIFIED",
"production_monitoring": "NOT_VERIFIED"
---
CREATE:

docs/CONTINUOUS-SECURITY-ASSURANCE.md
docs/SECURITY-OBSERVABILITY.md
registry/ASSURANCE-CONTROLS.json

UPDATE:

README.md
PUBLIC-MANIFEST.json

========================================
docs/CONTINUOUS-SECURITY-ASSURANCE.md
========================================

# CYBER HAK Continuous Security Assurance

CYBER HAK defines a governed defensive assurance model for continuously evaluating governance controls, evidence quality, control integrity and security drift.

Classification: PUBLIC

This document defines architecture and verification requirements only.

LIVE PRODUCTION MONITORING = NOT VERIFIED
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED

## Assurance Principles

- Evidence Before Claims
- Unknown Is Not Pass
- Observation Is Not Authority
- Detection Is Not Authorization
- Capability Is Not Approval
- Missing Evidence Is Not Pass
- Privileged Remediation Requires Governance
- Failure Must Be Recorded

## Assurance States

PASS — sufficient evidence supports the required control.

WARN — partial degradation or incomplete non-critical evidence exists.

FAIL — required protection is violated or cannot satisfy policy.

UNKNOWN — available evidence is insufficient for a valid conclusion.

UNKNOWN != PASS

## Assurance Control Domains

### AS-01 — Governance Integrity

Objective:
Verify that security actions remain bound to canonical governance.

Expected evidence:
policy decisions, approval references, governance state and audit records.

Failure condition:
execution or authorization occurs outside the governed chain.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-02 — Identity & Authorization Integrity

Objective:
Verify identity, authentication and authorization boundaries.

Expected evidence:
AI Passport state, authorization decisions and identity assertions.

Failure condition:
missing, invalid, expired or unauthorized identity/authority state.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-03 — Capability Boundary Integrity

Objective:
Ensure capabilities cannot exceed explicitly governed scope.

Expected evidence:
capability identifiers, scope bindings and policy decisions.

Failure condition:
capability use exceeds authorized boundaries.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-04 — Approval Path Integrity

Objective:
Verify privileged operations pass through required approval controls.

Expected evidence:
Approval Gateway decisions and associated policy references.

Failure condition:
required approval is missing, bypassed or invalid.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-05 — Runtime Domain Isolation

Objective:
Verify security workloads remain inside assigned Runtime Domains.

Expected evidence:
runtime identity, domain binding and isolation state.

Failure condition:
cross-domain execution or unauthorized boundary expansion.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-06 — Security NCA Fleet Integrity

Objective:
Verify Security Nano Core Agents operate under assigned roles and governed authority.

Expected evidence:
agent identity, assigned capability set, runtime state and policy results.

Failure condition:
agent identity drift, privilege expansion or unauthorized role change.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-07 — Audit Ledger Integrity

Objective:
Verify evidence and decision records remain traceable and integrity-protected.

Expected evidence:
audit event identifiers, hashes, timestamps and provenance.

Failure condition:
missing, corrupted, rewritten or unverifiable audit evidence.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-08 — Secret & Classification Protection

Objective:
Protect credentials, sensitive information and classified material.

Expected evidence:
classification state, access decisions and secret-scan results.

Failure condition:
unauthorized disclosure, access or classification-boundary violation.

Governed response:
DENY → ISOLATE_WHERE_APPLICABLE → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-09 — Software Supply Chain Integrity

Objective:
Verify dependencies and source inputs remain controlled and attributable.

Expected evidence:
dependency metadata, hashes, provenance and integrity results.

Failure condition:
untrusted, unverifiable or policy-violating software input.

Governed response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-10 — Detection & Telemetry Health

Objective:
Verify defensive telemetry remains sufficiently available for assessment.

Expected evidence:
telemetry freshness, source identity and collection health state.

Failure condition:
required defensive visibility is missing or materially degraded.

Governed response:
WARN_OR_FAIL → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-11 — Incident Response Readiness

Objective:
Verify incident-response controls and evidence paths remain available.

Expected evidence:
response procedures, severity registry and evidence-handling controls.

Failure condition:
required response capability or evidence-preservation control is unavailable.

Governed response:
FAIL → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### AS-12 — Evidence Integrity & Security Drift

Objective:
Detect material deviation from expected security and governance state.

Expected evidence:
baseline state, current state, hashes, policy version and evidence provenance.

Failure condition:
unapproved drift, missing evidence or unverifiable state transition.

Governed response:
DENY_WHERE_REQUIRED → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

## Assurance Cycle

OBSERVE
→ COLLECT EVIDENCE
→ VALIDATE
→ COMPARE AGAINST POLICY
→ DETECT DRIFT
→ CLASSIFY
→ RESPOND
→ RECORD
→ REVERIFY

## Security Drift Categories

DRIFT-01 — Governance Drift  
DRIFT-02 — Identity Drift  
DRIFT-03 — Authorization Drift  
DRIFT-04 — Capability Drift  
DRIFT-05 — Policy Drift  
DRIFT-06 — Runtime Configuration Drift  
DRIFT-07 — Agent Configuration Drift  
DRIFT-08 — Dependency Drift  
DRIFT-09 — Detection Drift  
DRIFT-10 — Evidence Drift

Drift detection does not grant autonomous privileged remediation authority.

Privileged remediation remains governed by:

AI Passport
→ Enterprise IMPERIAL Skills (EIS)
→ Guardian Core
→ Approval Gateway
→ Runtime Domain
→ Audit Ledger

========================================
docs/SECURITY-OBSERVABILITY.md
========================================

# CYBER HAK Security Observability

CYBER HAK defines security observability as governed defensive visibility into system security state.

Classification: PUBLIC

## Signal Classes

### SIG-01 — Identity Signals
Purpose: Observe identity, authentication and authorization state.  
Safe evidence: timestamps, identity-state transitions, authorization results and policy references.

### SIG-02 — Policy & Approval Signals
Purpose: Observe governance and approval decisions.  
Safe evidence: decision identifiers, allow/deny outcomes and approval state.

### SIG-03 — Capability Signals
Purpose: Observe governed capability assignment and use.  
Safe evidence: capability identifiers, bounded scope and policy outcomes.

### SIG-04 — Runtime Domain Signals
Purpose: Observe Runtime Domain health and isolation state.  
Safe evidence: runtime state, domain identity and configuration hashes.

### SIG-05 — Agent Fleet Signals
Purpose: Observe Security NCA identity, assignment and governed operational state.  
Safe evidence: agent identifiers, role state, lifecycle transitions and policy decisions.

### SIG-06 — Audit & Evidence Signals
Purpose: Observe evidence integrity and audit continuity.  
Safe evidence: audit identifiers, timestamps, hashes and provenance status.

### SIG-07 — Supply Chain Signals
Purpose: Observe software dependency and provenance state.  
Safe evidence: dependency metadata, package hashes, provenance and validation state.

### SIG-08 — Incident Response Signals
Purpose: Observe defensive incident lifecycle state.  
Safe evidence: incident identifier, severity transition, containment state and evidence status.

## Protected Information

Observability data must not expose:

- credentials
- access tokens
- API keys
- private keys
- seed phrases
- PRIVATE HANTER runtime source
- private infrastructure topology
- sensitive incident payloads
- private Audit Ledger contents

## Truth Boundary

PUBLIC OBSERVABILITY MODEL = DEFINED
LIVE TELEMETRY PIPELINE = NOT_VERIFIED
LIVE SOC / SIEM INTEGRATION = NOT_VERIFIED
PRODUCTION MONITORING = NOT_VERIFIED
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED

========================================
registry/ASSURANCE-CONTROLS.json
========================================

{
  "registry": "CYBER HAK Assurance Controls",
  "classification": "PUBLIC",
  "version": "1.0.0",
  "total_assurance_controls": 12,
  "total_signal_classes": 8,
  "total_drift_categories": 10,
  "default_policy": "DENY",
  "unknown_is_pass": false,
  "production_monitoring": "NOT_VERIFIED",
  "controls": [
    {
      "id": "AS-01",
      "name": "Governance Integrity",
      "objective": "Verify that security actions remain bound to canonical governance.",
      "expected_evidence": "Policy decisions, approval references, governance state and audit records.",
      "failure_condition": "Execution or authorization occurs outside the governed chain.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-02",
      "name": "Identity & Authorization Integrity",
      "objective": "Verify identity, authentication and authorization boundaries.",
      "expected_evidence": "AI Passport state, authorization decisions and identity assertions.",
      "failure_condition": "Identity or authority state is missing, invalid, expired or unauthorized.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-03",
      "name": "Capability Boundary Integrity",
      "objective": "Ensure capabilities cannot exceed explicitly governed scope.",
      "expected_evidence": "Capability identifiers, scope bindings and policy decisions.",
      "failure_condition": "Capability use exceeds authorized boundaries.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-04",
      "name": "Approval Path Integrity",
      "objective": "Verify privileged operations pass through required approval controls.",
      "expected_evidence": "Approval Gateway decisions and policy references.",
      "failure_condition": "Required approval is missing, bypassed or invalid.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-05",
      "name": "Runtime Domain Isolation",
      "objective": "Verify security workloads remain inside assigned Runtime Domains.",
      "expected_evidence": "Runtime identity, domain binding and isolation state.",
      "failure_condition": "Cross-domain execution or unauthorized boundary expansion occurs.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-06",
      "name": "Security NCA Fleet Integrity",
      "objective": "Verify Security Nano Core Agents operate under assigned roles and governed authority.",
      "expected_evidence": "Agent identity, capability assignment, runtime state and policy results.",
      "failure_condition": "Agent identity drift, privilege expansion or unauthorized role change occurs.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-07",
      "name": "Audit Ledger Integrity",
      "objective": "Verify evidence and decision records remain traceable and integrity-protected.",
      "expected_evidence": "Audit event identifiers, hashes, timestamps and provenance.",
      "failure_condition": "Audit evidence is missing, corrupted, rewritten or unverifiable.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-08",
      "name": "Secret & Classification Protection",
      "objective": "Protect credentials, sensitive information and classified material.",
      "expected_evidence": "Classification state, access decisions and secret-scan results.",
      "failure_condition": "Unauthorized disclosure, access or classification-boundary violation occurs.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-09",
      "name": "Software Supply Chain Integrity",
      "objective": "Verify dependencies and source inputs remain controlled and attributable.",
      "expected_evidence": "Dependency metadata, hashes, provenance and integrity results.",
      "failure_condition": "A software input is untrusted, unverifiable or policy-violating.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-10",
      "name": "Detection & Telemetry Health",
      "objective": "Verify defensive telemetry remains sufficiently available for assessment.",
      "expected_evidence": "Telemetry freshness, source identity and collection health state.",
      "failure_condition": "Required defensive visibility is missing or materially degraded.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-11",
      "name": "Incident Response Readiness",
      "objective": "Verify incident-response controls and evidence paths remain available.",
      "expected_evidence": "Response procedures, severity registry and evidence-handling controls.",
      "failure_condition": "Required response capability or evidence-preservation control is unavailable.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "AS-12",
      "name": "Evidence Integrity & Security Drift",
      "objective": "Detect material deviation from expected security and governance state.",
      "expected_evidence": "Baseline state, current state, hashes, policy version and evidence provenance.",
      "failure_condition": "Unapproved drift, missing evidence or unverifiable state transition occurs.",
      "default_response": "DENY_RECORD_ESCALATE"
    }
  ],
  "signal_classes": [
    {"id": "SIG-01", "name": "Identity Signals", "purpose": "Observe identity, authentication and authorization state."},
    {"id": "SIG-02", "name": "Policy & Approval Signals", "purpose": "Observe governance and approval decisions."},
    {"id": "SIG-03", "name": "Capability Signals", "purpose": "Observe governed capability assignment and use."},
    {"id": "SIG-04", "name": "Runtime Domain Signals", "purpose": "Observe Runtime Domain health and isolation state."},
    {"id": "SIG-05", "name": "Agent Fleet Signals", "purpose": "Observe Security NCA identity, assignment and governed operational state."},
    {"id": "SIG-06", "name": "Audit & Evidence Signals", "purpose": "Observe evidence integrity and audit continuity."},
    {"id": "SIG-07", "name": "Supply Chain Signals", "purpose": "Observe software dependency and provenance state."},
    {"id": "SIG-08", "name": "Incident Response Signals", "purpose": "Observe defensive incident lifecycle state."}
  ],
  "drift_categories": [
    {"id": "DRIFT-01", "name": "Governance Drift"},
    {"id": "DRIFT-02", "name": "Identity Drift"},
    {"id": "DRIFT-03", "name": "Authorization Drift"},
    {"id": "DRIFT-04", "name": "Capability Drift"},
    {"id": "DRIFT-05", "name": "Policy Drift"},
    {"id": "DRIFT-06", "name": "Runtime Configuration Drift"},
    {"id": "DRIFT-07", "name": "Agent Configuration Drift"},
    {"id": "DRIFT-08", "name": "Dependency Drift"},
    {"id": "DRIFT-09", "name": "Detection Drift"},
    {"id": "DRIFT-10", "name": "Evidence Drift"}
  ]
}

========================================
README.md — ADD
========================================

## Continuous Security Assurance & Observability

CYBER HAK defines a continuous defensive assurance architecture for validating governance controls, evidence integrity, telemetry health and security drift without granting autonomous privileged remediation authority.

- [Continuous Security Assurance](docs/CONTINUOUS-SECURITY-ASSURANCE.md)
- [Security Observability](docs/SECURITY-OBSERVABILITY.md)
- [Assurance Controls JSON](registry/ASSURANCE-CONTROLS.json)

========================================
PUBLIC-MANIFEST.json — ADD
========================================

"continuous_security_assurance": "DEFINED",
"security_observability": "DEFINED",
"assurance_controls": 12,
"observability_signal_classes": 8,
"security_drift_categories": 10,
"unknown_is_pass": false,
"live_telemetry_pipeline": "NOT_VERIFIED",
"production_monitoring": "NOT_VERIFIED"

CREATE:

docs/SOFTWARE-SUPPLY-CHAIN-SECURITY.md
docs/DEPENDENCY-PROVENANCE.md
registry/SUPPLY-CHAIN-CONTROLS.json

UPDATE:

README.md
PUBLIC-MANIFEST.json

========================================
docs/SOFTWARE-SUPPLY-CHAIN-SECURITY.md
========================================

# CYBER HAK Software Supply Chain Security

CYBER HAK defines a governed defensive model for protecting source inputs, dependencies, build artifacts and software provenance.

Classification: PUBLIC

This document defines architecture and verification requirements only.

LIVE PRODUCTION SUPPLY-CHAIN ENFORCEMENT = NOT_VERIFIED
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED

## Core Principles

- Source Is Not Trust
- Dependency Is Not Authorization
- Signature Is Not Provenance By Itself
- Hash Is Not Trust By Itself
- Public Source Is Not Trusted Executable
- Unknown Provenance Is Not Pass
- Dependency Change Requires Evidence
- Build Evidence Must Be Attributable
- Verification Precedes Promotion

## Governed Supply Chain

SOURCE
→ IDENTIFY
→ CLASSIFY
→ VERIFY PROVENANCE
→ VERIFY INTEGRITY
→ EVALUATE POLICY
→ BUILD
→ VERIFY ARTIFACT
→ RECORD EVIDENCE
→ PROMOTE OR DENY

## Supply Chain Control Domains

### SC-01 — Source Provenance

Objective:
Verify the declared origin and attribution of source material.

Required evidence:
repository identity, source reference, version or commit identity, provenance metadata.

Failure condition:
source origin cannot be established or conflicts with declared authority.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-02 — Source Integrity

Objective:
Verify source material has not changed outside the expected controlled state.

Required evidence:
content hashes, immutable source references and comparison evidence.

Failure condition:
unexpected source mutation or integrity mismatch.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-03 — Dependency Inventory

Objective:
Maintain an attributable inventory of direct and transitive dependencies.

Required evidence:
dependency names, versions, source origin and relationship metadata.

Failure condition:
unidentified or untracked dependency enters governed scope.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-04 — Dependency Provenance

Objective:
Verify dependency origin before governed acceptance.

Required evidence:
package source, repository or registry origin, version identity and provenance metadata.

Failure condition:
dependency provenance is unknown, conflicting or unverifiable.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-05 — Dependency Integrity

Objective:
Verify dependency bytes against expected integrity evidence.

Required evidence:
cryptographic hash or equivalent integrity metadata.

Failure condition:
integrity mismatch or unavailable required verification evidence.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-06 — License & Attribution Assurance

Objective:
Ensure third-party material is used with appropriate attribution and license awareness.

Required evidence:
license metadata, attribution requirements and review state.

Failure condition:
license status is unknown or incompatible with intended use.

Default response:
DENY_PROMOTION → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-07 — Vulnerability Evidence

Objective:
Evaluate known defensive vulnerability evidence associated with dependencies.

Required evidence:
scanner results, advisory identifiers, affected version information and review state.

Failure condition:
unresolved policy-blocking vulnerability evidence exists.

Default response:
DENY_PROMOTION → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-08 — Build Input Integrity

Objective:
Ensure governed builds consume only expected inputs.

Required evidence:
source identity, dependency lock state, configuration hashes and build input manifest.

Failure condition:
unexpected build input or uncontrolled dependency resolution occurs.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-09 — Build Reproducibility Evidence

Objective:
Provide evidence sufficient to compare governed build outputs when reproducibility is expected.

Required evidence:
build parameters, source reference, dependency state and output hashes.

Failure condition:
required build evidence is absent or outputs materially diverge without explanation.

Default response:
FAIL → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-10 — Artifact Integrity

Objective:
Verify produced artifacts remain bound to expected build output.

Required evidence:
artifact identity, hash, build reference and provenance record.

Failure condition:
artifact integrity cannot be established.

Default response:
DENY_PROMOTION → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-11 — Artifact Provenance

Objective:
Bind artifacts to the source and governed process that produced them.

Required evidence:
source reference, build identity, artifact hash and provenance chain.

Failure condition:
artifact cannot be attributed to an approved source/build context.

Default response:
DENY_PROMOTION → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-12 — Configuration Integrity

Objective:
Detect unauthorized changes to build and dependency configuration.

Required evidence:
configuration hashes, versioned configuration and change attribution.

Failure condition:
unapproved or unattributed configuration drift occurs.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-13 — Promotion Gate Integrity

Objective:
Ensure software promotion occurs only after required verification gates.

Required evidence:
policy result, verification state, evidence references and approval state.

Failure condition:
artifact promotion bypasses a required gate.

Default response:
DENY → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

### SC-14 — Supply Chain Evidence Integrity

Objective:
Ensure supply-chain verification evidence remains attributable and integrity-protected.

Required evidence:
timestamps, hashes, provenance, source identifiers and Audit Ledger references where applicable.

Failure condition:
evidence is missing, corrupted, unverifiable or contradictory.

Default response:
UNKNOWN_OR_FAIL → DENY_PROMOTION → RECORD → ESCALATE_FOR_AUTHORIZED_REVIEW

## Third-Party Source Boundary

Public ecosystems may be referenced for defensive taxonomy, research and verification.

Examples include:

MITRE ATT&CK
OWASP
SigmaHQ
ProjectDiscovery / Nuclei
Atomic Red Team
Trivy
Kubescape
Gitleaks
OSV
Semgrep

Permanent rule:

PUBLIC SOURCE != TRUSTED EXECUTABLE

External code, rules or templates require license, attribution, integrity and governance review before adoption.

## Truth Boundary

PUBLIC SUPPLY CHAIN MODEL = DEFINED
LIVE DEPENDENCY ENFORCEMENT = NOT_VERIFIED
LIVE BUILD PROVENANCE PIPELINE = NOT_VERIFIED
PRODUCTION SUPPLY CHAIN ENFORCEMENT = NOT_VERIFIED
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED


========================================
docs/DEPENDENCY-PROVENANCE.md
========================================

# CYBER HAK Dependency Provenance

Dependency provenance establishes attributable evidence about where a software dependency originated, which version was evaluated and how its integrity was verified.

Classification: PUBLIC

## Minimum Provenance Record

A governed dependency record should contain:

- dependency identifier
- dependency name
- version
- source type
- source location identifier
- source reference or release identifier
- integrity hash where available
- license metadata
- verification timestamp
- verification state
- vulnerability-review state
- provenance status
- evidence references

## Provenance States

VERIFIED — required provenance evidence is available and consistent.

PARTIAL — some required evidence exists but is incomplete.

FAILED — evidence contradicts policy or integrity expectations.

UNKNOWN — sufficient provenance evidence is unavailable.

UNKNOWN != VERIFIED

PARTIAL != VERIFIED

## Dependency Decision

DISCOVER
→ IDENTIFY
→ VERIFY SOURCE
→ VERIFY VERSION
→ VERIFY INTEGRITY
→ REVIEW LICENSE
→ REVIEW VULNERABILITY EVIDENCE
→ APPLY POLICY
→ RECORD
→ ACCEPT OR DENY

## Prohibited Assumptions

- popularity does not imply trust
- public availability does not imply authorization
- package-manager presence does not imply provenance
- signature presence alone does not prove trust
- a matching name does not prove package identity
- latest version does not automatically mean safest version

## Sensitive Information Boundary

Public provenance records must not expose:

- credentials
- access tokens
- private registry credentials
- private repository tokens
- private infrastructure topology
- private package endpoints
- PRIVATE HANTER runtime source

## Truth Boundary

DEPENDENCY PROVENANCE MODEL = DEFINED
LIVE DEPENDENCY INVENTORY = NOT_VERIFIED
LIVE SBOM PIPELINE = NOT_VERIFIED
LIVE PROVENANCE SERVICE = NOT_VERIFIED
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED


========================================
registry/SUPPLY-CHAIN-CONTROLS.json
========================================

{
  "registry": "CYBER HAK Supply Chain Controls",
  "classification": "PUBLIC",
  "version": "1.0.0",
  "total_supply_chain_controls": 14,
  "default_policy": "DENY",
  "unknown_provenance_is_pass": false,
  "public_source_is_trusted_executable": false,
  "production_enforcement": "NOT_VERIFIED",
  "controls": [
    {
      "id": "SC-01",
      "name": "Source Provenance",
      "purpose": "Verify the declared origin and attribution of source material.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-02",
      "name": "Source Integrity",
      "purpose": "Verify source material against expected integrity evidence.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-03",
      "name": "Dependency Inventory",
      "purpose": "Maintain an attributable inventory of governed dependencies.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-04",
      "name": "Dependency Provenance",
      "purpose": "Verify dependency origin before governed acceptance.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-05",
      "name": "Dependency Integrity",
      "purpose": "Verify dependency bytes against expected integrity evidence.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-06",
      "name": "License & Attribution Assurance",
      "purpose": "Require appropriate license awareness and attribution review.",
      "default_response": "DENY_PROMOTION_RECORD_ESCALATE"
    },
    {
      "id": "SC-07",
      "name": "Vulnerability Evidence",
      "purpose": "Evaluate known defensive vulnerability evidence associated with dependencies.",
      "default_response": "DENY_PROMOTION_RECORD_ESCALATE"
    },
    {
      "id": "SC-08",
      "name": "Build Input Integrity",
      "purpose": "Ensure governed builds consume only expected inputs.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-09",
      "name": "Build Reproducibility Evidence",
      "purpose": "Preserve evidence needed to compare governed build outputs.",
      "default_response": "FAIL_RECORD_ESCALATE"
    },
    {
      "id": "SC-10",
      "name": "Artifact Integrity",
      "purpose": "Verify produced artifacts remain bound to expected build output.",
      "default_response": "DENY_PROMOTION_RECORD_ESCALATE"
    },
    {
      "id": "SC-11",
      "name": "Artifact Provenance",
      "purpose": "Bind artifacts to the source and governed process that produced them.",
      "default_response": "DENY_PROMOTION_RECORD_ESCALATE"
    },
    {
      "id": "SC-12",
      "name": "Configuration Integrity",
      "purpose": "Detect unauthorized changes to build and dependency configuration.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-13",
      "name": "Promotion Gate Integrity",
      "purpose": "Ensure software promotion occurs only after required verification gates.",
      "default_response": "DENY_RECORD_ESCALATE"
    },
    {
      "id": "SC-14",
      "name": "Supply Chain Evidence Integrity",
      "purpose": "Protect provenance and verification evidence from missing or unverifiable state.",
      "default_response": "DENY_PROMOTION_RECORD_ESCALATE"
    }
  ],
  "provenance_states": [
    "VERIFIED",
    "PARTIAL",
    "FAILED",
    "UNKNOWN"
  ]
}


========================================
README.md — ADD
========================================

## Software Supply Chain Integrity

CYBER HAK defines a governed defensive supply-chain model for source provenance, dependency integrity, build evidence and artifact promotion.

- [Software Supply Chain Security](docs/SOFTWARE-SUPPLY-CHAIN-SECURITY.md)
- [Dependency Provenance](docs/DEPENDENCY-PROVENANCE.md)
- [Supply Chain Controls JSON](registry/SUPPLY-CHAIN-CONTROLS.json)

PUBLIC SOURCE != TRUSTED EXECUTABLE


========================================
PUBLIC-MANIFEST.json — ADD
========================================

"software_supply_chain_security": "DEFINED",
"dependency_provenance": "DEFINED",
"supply_chain_controls": 14,
"unknown_provenance_is_pass": false,
"public_source_is_trusted_executable": false,
"live_dependency_enforcement": "NOT_VERIFIED",
"live_build_provenance_pipeline": "NOT_VERIFIED",
"production_supply_chain_enforcement": "NOT_VERIFIED"

