# CYBER HAK Public

CYBER HAK is the governed defensive-security architecture of IMPERIAL Core.

**Author:** Alexander Romaskevich  
**Role:** Founder • Owner • CEO • Chief Systems Architect of IMPERIAL Core  
**Parent Architecture:** HANTER — AI Command Center / Deputy to the Architect  
**Classification:** PUBLIC

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

Identity ≠ Authority  
Capability ≠ Approval  
Intelligence ≠ Privilege

## Public / Private Boundary

This repository is a PUBLIC architecture and documentation surface.

Do not publish:
- PRIVATE HANTER runtime source
- credentials
- API keys
- tokens
- passwords
- private keys
- seed phrases
- private Audit Ledger records
- private authorization material
- sensitive incident evidence

## Truth Boundary

Architecture ≠ Implementation  
Implementation ≠ Testing  
Testing ≠ Runtime Verification  
Runtime Verification ≠ Production Authorization

Current status:

PUBLIC ARCHITECTURE = DEFINED  
PRIVATE HANTER RUNTIME WIRING = NOT VERIFIED BY THIS PUBLIC REPOSITORY  
LIVE PRODUCTION RUNTIME = NOT VERIFIED  
PRODUCTION AUTHORIZATION = NOT AUTHORIZED

---

**Architecture Before Implementation.**  
**Evidence Before Claims.**

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

CYBER HAK uses ten specialized Security Nano Core Agents governed by SECURITY-ORCHESTRATOR-01 under HANTER authority.
REPOSITORY:
oromaskevic23-cmd/CYBER-HAK-Public

BRANCH:
main

EXECUTE A REAL GITHUB WRITE.

Do NOT paste this task into README.md.
Use GitHub write tools to create actual repository files.

PRESERVE ALL EXISTING FILES.

CREATE:

docs/CAPABILITY-REGISTRY.md
registry/CAPABILITY-FAMILIES.json
docs/SECURITY-TIERS.md

UPDATE:

README.md
PUBLIC-MANIFEST.json

==================================================
PUBLIC CAPABILITY MODEL
==================================================

CYBER HAK public architecture scale:

Security Nano Core Agents = 10
Governed Security Skills = 512
Capability Families = 59
Default Policy = DENY
T3 Autonomous Activity = ALWAYS DENY

IMPORTANT TRUTH BOUNDARY:

The public repository documents the governed capability model.

It does NOT claim that 512 unrestricted executable tools are exposed publicly.

It does NOT grant execution authority.

It does NOT publish PRIVATE HANTER runtime wiring.

Permanent laws:

CAPABILITY ≠ AUTHORITY
CAPABILITY ≠ APPROVAL
KNOWLEDGE ≠ PERMISSION
DISCOVERY ≠ AUTHORIZATION

==================================================
docs/CAPABILITY-REGISTRY.md
==================================================

Create:

# CYBER HAK Capability Registry

Explain that CYBER HAK defines a governed defensive-security capability model consisting of:

- 512 governed security skills
- 59 capability families
- 10 specialized Security Nano Core Agents
- one SECURITY-ORCHESTRATOR-01
- HANTER as command authority
- Architect as final architectural authority

State clearly:

The registry describes defensive-security coverage and routing.

It does not grant unrestricted execution authority.

Every active capability remains subject to:

AI Passport
→ Enterprise IMPERIAL Skills (EIS)
→ Guardian Core
→ Approval Gateway
→ Runtime Domain
→ Audit Ledger

Document all 59 capability families exactly:

01. Asset Inventory
02. Attack Surface Management
03. Exposure Management
04. Vulnerability Management
05. Patch & Remediation Assurance
06. Configuration Security
07. Secure Baseline Management
08. Application Security
09. API Security
10. Web Security Assurance
11. Mobile Application Security
12. Secure Code Review
13. Software Composition Analysis
14. Dependency Security
15. Software Supply Chain Security
16. SBOM Assurance
17. Secrets Detection
18. Credential Hygiene
19. Identity Security
20. Authentication Security
21. Authorization Security
22. Privileged Access Security
23. Directory & IAM Assurance
24. Cloud Security Posture
25. Cloud Identity Security
26. Container Security
27. Kubernetes Security
28. Infrastructure-as-Code Security
29. Host Hardening
30. Endpoint Security
31. Network Security
32. DNS & Domain Security
33. Email Security
34. Data Protection
35. Encryption & Key-Management Assurance
36. Backup & Recovery Security
37. Logging & Audit Integrity
38. Security Telemetry
39. Detection Engineering
40. Alert Quality Assurance
41. Threat Intelligence
42. Threat Hunting
43. Incident Response
44. Digital Forensics
45. Evidence Preservation
46. Malware Analysis — Defensive
47. Phishing Defense
48. Security Awareness Assurance
49. Security Control Validation
50. Purple-Team Validation
51. Authorized Adversarial Validation
52. Security Regression Testing
53. Policy Verification
54. Governance Assurance
55. Compliance Control Mapping
56. Third-Party Risk
57. Security Architecture Review
58. Resilience & Continuity Security
59. Security Metrics & Risk Reporting

For every family provide a concise one-line defensive purpose.

Do NOT include exploitation payloads, malware code, credential theft procedures, destructive instructions or unauthorized intrusion procedures.

==================================================
registry/CAPABILITY-FAMILIES.json
==================================================

Create valid machine-readable JSON.

Required structure:

{
  "registry": "CYBER HAK Capability Families",
  "classification": "PUBLIC",
  "version": "1.0.0",
  "total_capability_families": 59,
  "governed_security_skills": 512,
  "security_nca": 10,
  "default_policy": "DENY",
  "execution_authority": "NONE_BY_REGISTRY",
  "families": [
    ...
  ]
}

Each family entry must contain:

"id"
"name"
"purpose"
"default_policy"

IDs:

CF-001 through CF-059

Every default_policy:

"DENY_UNLESS_GOVERNED"

Ensure there are exactly 59 unique entries.

Do not claim individual skill runtime deployment.

==================================================
docs/SECURITY-TIERS.md
==================================================

Create:

# CYBER HAK Security Activity Tiers

Define:

## T0 — Defensive / Passive

Examples:
- static analysis
- inventory
- configuration review
- evidence review
- defensive research
- telemetry analysis
- detection analysis

No active target interaction required.

## T1 — Authorized Active Validation

Requires ALL:

- valid AI Passport
- appropriate EIS capability
- Guardian Core ALLOW
- explicit Approval Gateway authorization
- exact target scope
- Runtime Domain binding
- Audit Ledger evidence

Authorization must be explicit and bounded.

## T2 — Isolated Lab / CTF / Sandbox

Requires:

- isolated environment
- explicit scope
- sandbox boundary
- no uncontrolled external effects
- no production target assumptions

## T3 — Prohibited Autonomous Activity

T3 = ALWAYS DENY

Includes autonomous or unauthorized:

- real-world compromise
- credential theft
- destructive actions
- persistence
- uncontrolled target expansion
- approval bypass
- governance bypass
- autonomous financial/wallet actions

==================================================
README.md UPDATE
==================================================

Add a concise section:

## Governed Capability Registry

State:

CYBER HAK defines 512 governed security skills across 59 capability families and 10 specialized Security Nano Core Agents.

The registry represents defensive-security coverage, not unrestricted execution authority.

Add links:

[Capability Registry](docs/CAPABILITY-REGISTRY.md)
[Capability Families JSON](registry/CAPABILITY-FAMILIES.json)
[Security Activity Tiers](docs/SECURITY-TIERS.md)

Do not duplicate the full list of 59 families in the root README.

Do not paste this task into README.md.

==================================================
PUBLIC-MANIFEST.json UPDATE
==================================================

Preserve all existing fields.

Ensure these remain present and correct:

"governed_security_skills": 512,
"capability_families": 59,
"security_nca": 10,
"default_policy": "DENY",
"t3_policy": "ALWAYS_DENY",
"capability_registry": "DEFINED",
"capability_family_registry": "DEFINED",
"security_tiers": "DEFINED",
"private_hanter_runtime_published": false,
"production_authorization": "NOT_AUTHORIZED"

Keep valid JSON.

==================================================
VERIFY BEFORE COMMIT
==================================================

Verify remotely:

docs/CAPABILITY-REGISTRY.md exists
registry/CAPABILITY-FAMILIES.json exists
docs/SECURITY-TIERS.md exists

Validate:

CAPABILITY FAMILIES = exactly 59
FAMILY IDs = CF-001 through CF-059
DUPLICATE FAMILY IDs = NONE
DUPLICATE FAMILY NAMES = NONE
GOVERNED SECURITY SKILLS = 512
SECURITY NCA = 10
DEFAULT POLICY = DENY
T3 = ALWAYS DENY

Validate both JSON files parse successfully.

Fetch all created/updated files back from GitHub main.

Verify:

README LINKS = PASS
PROMPT POLLUTION = NONE
PRIVATE MATERIAL = NONE
OFFENSIVE PAYLOADS = NONE
UNRESTRICTED EXECUTION AUTHORITY = NONE
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED

Create exactly ONE commit.

COMMIT MESSAGE:

docs(capabilities): establish governed 512-skill capability registry

AFTER PUSH:

Fetch repository root.
Fetch docs directory.
Fetch registry directory.
Fetch PUBLIC-MANIFEST.json.
Fetch README.md.

RETURN ONLY:

COMMIT 04 = <SHA>
CAPABILITY FAMILIES = 59/59
FAMILY JSON = PASS / FAIL
MANIFEST JSON = PASS / FAIL
SECURITY TIERS = PASS / FAIL
README LINKS = PASS / FAIL
FETCH-BACK = PASS / FAIL
PROMPT POLLUTION = NONE / FOUND
PRIVATE MATERIAL = NONE / FOUND
REGISTRY FILES = <list>
REPOSITORY:
oromaskevic23-cmd/CYBER-HAK-Public

BRANCH:
main

EXECUTE A REAL GITHUB WRITE.

Do NOT paste this task into README.md.
Use GitHub write tools to create actual repository files.

PRESERVE ALL EXISTING FILES.

==================================================
PRECONDITION GATE
==================================================

Before changing anything, verify that COMMIT 04 artifacts exist:

docs/CAPABILITY-REGISTRY.md
registry/CAPABILITY-FAMILIES.json
docs/SECURITY-TIERS.md

Verify:

CAPABILITY FAMILIES = 59
GOVERNED SECURITY SKILLS = 512
SECURITY NCA = 10

If any required COMMIT 04 artifact is missing or invalid:

DO NOT COMMIT.

Return only:

COMMIT 05 = BLOCKED
REASON = COMMIT_04_PRECONDITION_FAILED

If the precondition passes, continue.

==================================================
CREATE
==================================================

docs/THREAT-MODEL.md
docs/ATTACK-SURFACE-MODEL.md
registry/THREAT-CATEGORIES.json

UPDATE:

README.md
PUBLIC-MANIFEST.json

==================================================
THREAT MODEL PRINCIPLES
==================================================

CYBER HAK uses a defensive, governance-first threat model.

The threat model must protect:

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
- PUBLIC / PRIVATE classification boundaries
- secrets and credentials
- software supply chain
- production infrastructure
- security evidence
- economic and wallet boundaries

Permanent laws:

IDENTITY ≠ AUTHORITY
CAPABILITY ≠ APPROVAL
INTELLIGENCE ≠ PRIVILEGE
DISCOVERY ≠ AUTHORIZATION
PUBLIC ≠ TRUSTED
COMMIT ≠ PRODUCTION DEPLOYMENT

Default Policy = DENY

==================================================
docs/THREAT-MODEL.md
==================================================

Create:

# CYBER HAK Threat Model

Explain the defensive threat-model purpose.

Document these threat categories:

TM-01 Identity Spoofing
TM-02 Authentication Bypass
TM-03 Authorization Bypass
TM-04 Privilege Escalation
TM-05 Capability Abuse
TM-06 Approval Gateway Bypass
TM-07 Guardian Core Bypass
TM-08 Runtime Domain Escape
TM-09 Cross-Domain Contamination
TM-10 Prompt / Instruction Injection
TM-11 Malicious Tool Invocation
TM-12 Data Exfiltration
TM-13 Secret Exposure
TM-14 Audit Ledger Tampering
TM-15 Evidence Tampering
TM-16 Replay Attacks
TM-17 TOCTOU / Decision Drift
TM-18 Supply Chain Compromise
TM-19 Dependency Compromise
TM-20 CI/CD Pipeline Compromise
TM-21 Malicious Configuration Change
TM-22 Public / Private Boundary Violation
TM-23 Unauthorized Target Expansion
TM-24 Autonomous Persistence
TM-25 Destructive Execution
TM-26 Credential Theft
TM-27 Unauthorized Network Interaction
TM-28 Unauthorized Financial Action
TM-29 Private-Key / Wallet Material Exposure
TM-30 Governance Override Attempt

For every threat category include only:

- threat name
- protected boundary
- defensive risk description
- prevention controls
- detection / evidence expectations
- default response

Do NOT include:

- exploit payloads
- malware code
- persistence instructions
- credential theft procedures
- destructive commands
- unauthorized intrusion instructions
- bypass recipes

Default defensive response for governance violations:

DENY
ISOLATE
RECORD
ESCALATE FOR AUTHORIZED REVIEW

==================================================
docs/ATTACK-SURFACE-MODEL.md
==================================================

Create:

# CYBER HAK Attack Surface Model

Document high-level defensive attack surfaces only.

Include:

## 1. Identity Surface

AI Passport
authentication
authorization
roles
privileges

## 2. Capability Surface

EIS capability registry
skill routing
capability assignment
capability revocation

## 3. Governance Surface

Guardian Core
Approval Gateway
policy decisions
decision binding

## 4. Runtime Surface

Runtime Domains
agent isolation
process boundaries
container / cloud boundaries

## 5. Agent Surface

Security NCA
SECURITY-ORCHESTRATOR-01
agent-to-agent communication
task delegation

## 6. Data Surface

PUBLIC
PRIVATE
SECRET
RESTRICTED
logs
evidence
configuration
security metadata

## 7. Audit Surface

Audit Ledger
evidence integrity
event ordering
replay protection

## 8. Software Supply Chain Surface

dependencies
packages
containers
build artifacts
CI/CD
third-party security sources

## 9. API / Integration Surface

APIs
webhooks
external services
connectors
repository integrations

## 10. Economic Boundary Surface

payment intents
wallet references
financial metadata
authorization boundaries

State clearly:

CYBER HAK has no autonomous wallet authority.

Security capability must never imply financial execution authority.

For every attack surface provide:

- assets
- trust boundary
- primary defensive risks
- required controls
- expected evidence

==================================================
registry/THREAT-CATEGORIES.json
==================================================

Create valid machine-readable JSON.

Required structure:

{
  "registry": "CYBER HAK Threat Categories",
  "classification": "PUBLIC",
  "version": "1.0.0",
  "total_threat_categories": 30,
  "default_policy": "DENY",
  "default_governance_response": [
    "DENY",
    "ISOLATE",
    "RECORD",
    "ESCALATE_FOR_AUTHORIZED_REVIEW"
  ],
  "categories": [
    ...
  ]
}

Create exactly 30 unique entries.

IDs:

TM-01 through TM-30

Each entry must contain:

"id"
"name"
"protected_boundary"
"defensive_objective"
"default_response"

Every default_response must be:

"DENY_UNLESS_EXPLICITLY_GOVERNED"

No offensive procedures.

==================================================
README.md UPDATE
==================================================

Add a concise section:

## Threat Model & Attack Surface

State:

CYBER HAK uses a governance-first defensive threat model covering identity, capability, approval, runtime, agent, data, audit, software supply-chain, integration and economic boundaries.

Add links:

[Threat Model](docs/THREAT-MODEL.md)
[Attack Surface Model](docs/ATTACK-SURFACE-MODEL.md)
[Threat Categories JSON](registry/THREAT-CATEGORIES.json)

Do not duplicate the full threat model in README.md.

Do not paste this task into README.md.

==================================================
PUBLIC-MANIFEST.json UPDATE
==================================================

Preserve all existing fields.

Ensure these fields exist and remain correct:

"threat_model": "DEFINED",
"attack_surface_model": "DEFINED",
"threat_categories": 30,
"default_policy": "DENY",
"security_nca": 10,
"governed_security_skills": 512,
"capability_families": 59,
"private_hanter_runtime_published": false,
"production_authorization": "NOT_AUTHORIZED"

Keep valid JSON.

==================================================
VERIFY BEFORE COMMIT
==================================================

Verify remotely:

docs/THREAT-MODEL.md exists
docs/ATTACK-SURFACE-MODEL.md exists
registry/THREAT-CATEGORIES.json exists

Validate:

THREAT CATEGORIES = exactly 30
THREAT IDs = TM-01 through TM-30
DUPLICATE THREAT IDs = NONE
DUPLICATE THREAT NAMES = NONE
DEFAULT POLICY = DENY

Validate:

registry/THREAT-CATEGORIES.json = valid JSON
PUBLIC-MANIFEST.json = valid JSON

Verify:

README LINKS = PASS
PROMPT POLLUTION = NONE
PRIVATE MATERIAL = NONE
OFFENSIVE PAYLOADS = NONE
MALWARE CODE = NONE
CREDENTIAL THEFT PROCEDURES = NONE
DESTRUCTIVE INSTRUCTIONS = NONE
UNRESTRICTED EXECUTION AUTHORITY = NONE
AUTONOMOUS WALLET AUTHORITY = NONE
PRODUCTION AUTHORIZATION = NOT_AUTHORIZED

Fetch all created and updated files back from GitHub main.

Create exactly ONE commit.

COMMIT MESSAGE:

docs(threat-model): establish defensive threat and attack-surface model

AFTER PUSH:

Fetch repository root.
Fetch docs directory.
Fetch registry directory.
Fetch README.md.
Fetch PUBLIC-MANIFEST.json.
Fetch all three COMMIT 05 files.

RETURN ONLY:

COMMIT 05 = <SHA>
THREAT CATEGORIES = 30/30
THREAT JSON = PASS / FAIL
ATTACK SURFACE MODEL = PASS / FAIL
MANIFEST JSON = PASS / FAIL
README LINKS = PASS / FAIL
FETCH-BACK = PASS / FAIL
PROMPT POLLUTION = NONE / FOUND
PRIVATE MATERIAL = NONE / FOUND
OFFENSIVE PAYLOADS = NONE / FOUND
REGISTRY FILES = <list>
