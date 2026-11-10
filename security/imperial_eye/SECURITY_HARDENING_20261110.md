# IMPERIAL EYE — Evidence-Fusion Security Hardening

**Date:** 2026-11-10  
**Project:** IMPERIAL Core / CYBER HAK / IMPERIAL EYE  
**Architect:** Alexander Nikolaevich Romaskevich (RomaskevicH)  
**Branch:** `security/imperial-eye-evidence-fusion-20261110`  
**Budget:** FREE_ONLY / USD 0  
**Maturity:** Local source-code engineering; independent production acceptance remains outstanding.

## Purpose

Extend existing **IMPERIAL EYE** without copying third-party GOD'S EYE infrastructure or adding indiscriminate people surveillance. The security domain is **infrastructure and authorized source intelligence**. No private camera host, credentials, location/person trace, video frames or personally identifiable data are collected.

## Changes in this review

1. **Evidence-fusion module:** `evidence_fusion.py` accepts only bounded, typed incident records for infrastructure services, HANTER/approval resources, NCA workers and official publisher metadata. It denies extra fields, unrecognized event types, cross-tenant events, future/stale timestamps, inconsistent component identity and conflicting idempotent replays.
2. **Deterministic operational incidents:** Groups observations by federated orchestrator and component, reports repeated OOM occurrences and SHA-256 content digests. Hashes establish input integrity only; they do not establish provenance or independent QA.
3. **Official API hardening:** `digitraffic.py` rejects trailing gzip members or appended junk instead of ignoring excess bytes in a returned response. This addresses an identifiable response-envelope validation weakness; it is NOT evidence of exploitation of Fintraffic or any other external service.
4. **Coordinate hardening:** The same metadata parser now rejects NaN and Infinity values, preventing non-finite station coordinates from passing schema validation.
5. **Adversarial regression tests:** `tests/test_evidence_fusion.py` contains synthetic fixtures for replay, cross-tenant boundaries, denied person lookup, bounded resource use, gzip members, and non-finite coordinates.

## Exact security boundaries

- `fuse_system_events` performs NO network operations and never dispatches an agent or video stream.
- All incoming events must be supplied by an **independently authorized read-only collector**, with private source authenticity verified elsewhere.
- `source_authenticity_verified`, `independent_qa_verified`, `execution_authorized`, and `production_monitoring_verified` remain false in the module's output.
- The Owner Kill Switch is surfaced as status only; this component cannot turn it off.
- The public `catalog.py` continues to link only to reviewed publisher portals. Do not relax the private-camera or person-tracking denials.
- Preserve Federated Multi-Orchestrator Architecture, HANTER, CYBER HAK, Nano Core Agents, AI Passport, Enterprise Skills, Guardian Core, Approval Gateway, Audit Ledger, Zero Trust, Public/Private Boundary and CRYPTO IMPERIAL Ecosystem Boundary.
- Third-party source code, marks, CCTV streams and hosted environments are not incorporated without license, consent, contract and security reviews.

## Reproducible tests

From the repository root, using its pinned runtime dependencies:

```sh
python -m unittest discover -s security/imperial_eye/tests -p 'test_*.py' -v
python -m compileall -q security/imperial_eye
node --check security/imperial_eye/web/assets/eye.js
```

GitHub Actions workflow: [imperial-eye.yml](../../.github/workflows/imperial-eye.yml), which runs Python 3.11/3.12 tests. Review the exact SHA and workflow result before calling a change PASS.

## Remaining P0 issues

1. Stop recurring Render 512MiB OOM failures with independently scoped service resource analysis, optimized build/start commands, and free-tier measurements. No blind restarts or paid upgrades.
2. Establish actual Owner passkey enrollment and protected same-origin backend after cryptographic controls, without storing raw biometrics.
3. Implement a separately governed PRIVATE video adapter only for owner-operated or contractually licensed feeds, with revocation and retention controls. No production camera ingress exists in this change.
4. Connect HANTER to evidence triage through authenticated read-only transport, operator segregation, independent QA and Audit Ledger.
5. Validate real UI/mobile accessibility in a hosted authorized test environment; static atlas UI does not prove live video monitoring.

**Architecture Before Implementation. Evidence Before PASS.**
