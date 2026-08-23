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
