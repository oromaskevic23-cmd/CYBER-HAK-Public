# CYBER HAK Fleet Audit — Defensive Reference

**Not an exploit scanner.** `src/fleet-security-audit.mjs` is a pure, deterministic policy engine for repository file-tree metadata and explicitly provided GitHub Actions text.

It identifies mutable action references, missing explicit token permissions, write tokens on externally influenced events, dangerous shell interpolations, remote pipe-to-shell patterns, tracked credential-like paths, and missing workflow evidence. It cannot prove absence of vulnerabilities, inspect unprovided private source or test an external service.

`auditRepo({name,visibility,paths,workflows,alertCoverage,inventoryComplete})` returns a SHA-256 evidence digest for the precise observed inputs and a fail-closed decision. `auditFleet(reports,{expectedRepos:29})` refuses a full-coverage claim unless exactly 29 distinct repository reports exist **and** their tree and GitHub Security alerts coverage are complete.

An upstream scanner missing permissions must report `INCOMPLETE` or `ACCESS_DENIED`; an empty alert response is only meaningful when the appropriate API returned an authorized 200 with all pages accounted for.

## Architecture

The public CYBER HAK repository hosts the scanner and self-contained unit tests. **Private** repo inventory, read-only access token, internal server findings and evidence are handled only in IMPERIAL Core's existing private governance repository. Do not copy the private manifest into this public repository.

The scanner does not run remote code, log raw secrets, create issues, alter repositories, grant permissions or deploy. It supports security operations under Architect → HANTER → federated orchestrators → professional NCA/CYBER HAK teams, with AI Passport, Guardian Core, Approval Gateway, Audit Ledger, Owner Kill Switch, Zero Trust and Public/Private/CRYPTO IMPERIAL boundaries.

## Local test

```sh
npm run verify
```

Run negative cases with `node --test test/fleet-security-audit.test.mjs`. A green unit test establishes only that the policies behave as tested. It does not establish that 29/29 repositories are clean. Automated fixes to production, secret rotation and server privilege changes require separate explicit Owner approval and verified rollback.
