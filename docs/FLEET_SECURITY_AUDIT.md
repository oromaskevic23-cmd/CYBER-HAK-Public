# CYBER HAK Fleet Audit — Defensive Reference

**Not an exploit scanner.** `src/fleet-security-audit.mjs` is a pure, deterministic policy engine for repository file-tree metadata and explicitly provided GitHub Actions text.

It identifies mutable action references, missing explicit token permissions, write tokens on externally influenced events, dangerous shell interpolations, remote pipe-to-shell patterns, tracked credential-like paths, and missing workflow evidence. It cannot prove absence of vulnerabilities, inspect unprovided private source or test an external service.

`auditRepo({name,visibility,paths,workflows,alertCoverage,inventoryComplete})` returns a SHA-256 evidence digest for the precise observed inputs and a fail-closed decision. `auditFleet(reports,{expectedRepos:30,expectedRepoNames})` refuses a full-coverage claim unless exactly 30 distinct repository reports match an **independently supplied exact-name inventory** and their tree and GitHub Security alerts coverage are complete. Omitting `expectedRepoNames` is permitted for partial analysis, but **always prevents `POLICY_GATE_PASS`**, even when 30 reports are provided.

An upstream scanner missing permissions must report `INCOMPLETE` or `ACCESS_DENIED`; an empty alert response is only meaningful when the appropriate API returned an authorized 200 with all pages accounted for.

## Architecture

The public CYBER HAK repository hosts the scanner and self-contained unit tests. **Private** repo inventory, read-only access token, internal server findings and evidence are handled only in IMPERIAL Core's existing private governance repository. Do not copy the private manifest into this public repository.

The scanner does not run remote code, log raw secrets, create issues, alter repositories, grant permissions or deploy. It supports security operations under Architect → HANTER → federated orchestrators → professional NCA/CYBER HAK teams, with AI Passport, Guardian Core, Approval Gateway, Audit Ledger, Owner Kill Switch, Zero Trust and Public/Private/CRYPTO IMPERIAL boundaries.

## Local test

```sh
npm run verify
```

Run negative cases with `node --test test/fleet-security-audit.test.mjs`. A green unit test establishes only that the policies behave as tested. It does not establish that 30/30 repositories are clean. Every supplied report is schema-and-checksum-validated before aggregation. MEDIUM findings and missing workflow evidence prevent a fleet PASS. SHA-256 is **not** an Ed25519 signature; source provenance still requires trusted collection and independent signing. See [Strix lab integration](../security/strix/README.md), which is not a substitute for the static audit.

Automated fixes to production, secret rotation and server privilege changes require separate explicit Owner approval and verified rollback.

## Exact trusted inventory / version 3

An arbitrary set of 30 valid-looking reports is not the authoritative fleet. The caller must supply the separately verified list of 30 `owner/repo` names as `expectedRepoNames` to obtain a full-fleet policy PASS. The result records `membershipVerified` and a deterministic `inventorySha256` fingerprint. That fingerprint is **not a digital signature**, and this library cannot prove who collected or signed the inventory. Keep the owner-maintained private repository list and any signed manifest outside the public code.

The v3 change does not expand audit coverage, run Strix, verify third-party alerts, or imply enterprise production readiness. Maintain owner-held manifests, real identity/approval controls, and private Audit Ledger.

## Sprint 005 — Fail-closed collection evidence

The `auditRepo(...)` input `inventoryComplete` **defaults to false**. An omitted, null, string, or other nonboolean collection-completeness claim is not accepted as `true`. To inspect a subset, omit `inventoryComplete` and expect `INCOMPLETE`; supply `inventoryComplete:true` only after the caller independently confirms that the listed file-tree inventory is exhaustive. A caller's assertion is still not cryptographic proof of coverage.

This prevents accidental omission of the inventory completeness flag from creating `POLICY_GATE_PASS`. The runtime remains a read-only metadata audit, not a Strix execution. All old unconditional PASS statements should be reassessed under the new default.
