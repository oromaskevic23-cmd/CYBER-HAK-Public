# CYBER HAK Express — AI Code & CI/CD Policy Review

**An inspectable, fixed-scope source review for AI/automation studios and software delivery teams.**

## What we check

A read-only scan of one authorized Git repository at an agreed commit, using the original CYBER HAK source-policy scanner. Six checks cover:

- Private-key-shaped material and likely access-token patterns.
- Overbroad GitHub Actions permissions (`write-all`).
- GitHub Actions references that are not pinned to immutable revisions.
- `pull_request_target` trust-boundary signals.
- External downloader scripts piped directly into a shell.

## What you receive

- SHA-256-bound JSON report: source revision, scanned file inventory, policy indicators, excluded scope and report digest.
- Short human-readable summary of findings, limitations and suggested next steps; indicators are not automatically confirmed vulnerabilities.
- A 30-minute discussion of the report and remediation priorities.

The target code is not executed, built or deployed. Do not send production credentials, customer data or private source in a public issue or email attachment. Any private repository requires an agreed, access-controlled review environment before work starts.

**This is not a penetration test, comprehensive security audit, independent certification, compliance attestation, dependency scan or guarantee that software is secure.** It does not cover runtime systems, commit history, all secret formats or unscanned files. No changes to the customer's repository are authorized by this service.

## Introductory evaluation

**Proposed introductory price: USD 500 for one repository**, for the first two mutually accepted engagements, subject to written scope and confirmed availability. The proposed turnaround is **2–3 business days** after scope, safe access, and commercial arrangements are agreed. No payment or contract is established by this page. Feedback is welcome; a public case study or testimonial requires separate voluntary consent. No positive review is required.

Before any paid work, both parties must agree on the target revision, access and data handling, deliverables, acceptance, price, invoicing/payment terms and applicable rights. No legal or financial commitments are made without owner approval.

## Example: prior internal portfolio inspection (2 November 2026)

Aggregate demonstration of a real project-controlled run, not a customer case study or new scan.

| Measure | Reported result |
| --- | ---: |
| Completed public repository scan jobs | 23 / 23 |
| Tracked files scanned | 917 |
| Other tracked files skipped by source-type selection | 72 |
| Static policy indicators | 19 |
| Mutable action-reference indicators | 13 |
| Credential-marker indicators | 6 |
| Private repositories not scanned | 7 |

The six credential-marker matches were reported as fixtures or defensive assertions after source-context review; no active credential was established. The 19 indicators are not 19 confirmed vulnerabilities. Successful jobs establish execution of a limited scan, not a clean security certification. This historical sample does not represent current repository state or independent external validation.

[Recorded workflow execution](https://github.com/oromaskevic23-cmd/CYBER-HAK-Public/actions/runs/41502289194) · [Scanner scope and reproducibility](../security/skills/source-audit/SKILL.md)

## Request a 20-minute scope discussion

Email [oromaskevic23@gmail.com](mailto:oromaskevic23@gmail.com?subject=CYBER%20HAK%20Express%20scope%20discussion) with your organization, a non-confidential description of the repository and the checks you care about. Do not share secrets or private customer information.

Alexander Romaskevich (RomaskevicH) — Founder, Owner and CEO, IMPERIAL Core.

Build software. Verify everything.
