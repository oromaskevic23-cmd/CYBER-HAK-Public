# CYBER HAK — Executable Source Security Audit Skill

**Implementation state:** real, bounded source analysis implemented in original CYBER HAK code. GitHub Actions is the CI execution surface; per-run evidence must be checked in the actual job logs. This is **not** a complete penetration test, production EDR, live Cloudflare integration, or a guaranteed vulnerability detector.

**Founding architect:** Alexander Nikolaevich Romaskevich (RomaskevicH).
**Module:** [source-security-gate.mjs](../../tools/source-security-gate.mjs)
**CI:** [executable-source-security-gate.yml](../../.github/workflows/executable-source-security-gate.yml)
**Tests:** [source-security-gate.test.mjs](../../test/source-security-gate.test.mjs)

## What the working mechanism does

1. Uses the current local Git index to enumerate only **tracked source and configuration files**. It never downloads, executes or builds the target repository and does not access production infrastructure.
2. Reads tracked source without following symlinks, enforcing per-file and total size limits. Rejects unsafe paths and unreadable in-scope files.
3. Applies **six explicit static policy checks**: private-key material patterns, likely token patterns, overbroad GitHub Actions permissions, mutable/unpinned action references, pull_request_target trust-boundary review, and pipe-to-shell from an external downloader in workflow scripts.
4. Emits a deterministic JSON report with source commit, file hashes, skipped-scope list, policy signals and report SHA-256 **without recording matched credential bytes or raw sensitive source lines**.
5. Runs in GitHub Actions on every PR and change to main. It scans the full tracked source in **report-only** mode (historical debt is visible), then scans files changed relative to the PR/push base and **exits 3 on introduced policy signals**. Exit 2 indicates incomplete audit or invalid input, which must never be reported as PASS.
6. Runs an independent collection of local regression scenarios as part of CI, including altered workflow fixtures, secret patterns, scope/commit changes, symlink denial, deterministic results and required no-production claims.

## Run it (Node.js 22+, Git checkout)

Full read-only static scan (report-only, may report historical signals):

    npm run security:scan

Full report written outside the repository (fails if output already exists):

    node tools/source-security-gate.mjs --root . --report /absolute/private/path/report.json

PR-style enforcement for an **exact existing Git commit** (exit 0 when no scoped policy violations; exit 3 on matches; exit 2 on incomplete):

    node tools/source-security-gate.mjs --root . --base <40-character-existing-base-commit> --enforce

Unit tests:

    npm run security:test

## Evidence and limitations

A match is **STATIC_POLICY_SIGNAL**, not a confirmed exploitable vulnerability. Severity cannot be assigned without demonstrating a relevant trust boundary and observed outcome. This is a source-level CI policy gate with a fixed limited rule set, not comprehensive secure-code review, dependency SCA, authorization review, DAST or dynamic Strix assessment.

No target code is executed, no real site or customer is scanned, no secret values are printed, and no paid service is used. Reports carry `coverage_complete:false`, `no_vulnerabilities_claimed:false`, `independent_qa_verified:false`, and `production_authorized:false` by design. Raw findings, even when source paths are public, should be reviewed by the project owner before external disclosure.

### Security operating model

Architect → HANTER → **Federated Security Orchestrator** → CYBER HAK → source audit and, separately, scoped Strix lab → **independent QA** → ProofGraph → Audit Ledger → Approval Gateway → authorized remediation PR.

Maintain AI Passport, Enterprise Skills, Guardian Core, Zero Trust, IntentLock, Owner Kill Switch, Public/Private Boundary and **CRYPTO IMPERIAL Ecosystem Boundary**. No scanner result grants execution or financial privileges. The owner controls final architectural decisions.

### Relation to Cloudflare security-audit-skill

The [Cloudflare security-audit-skill](https://github.com/cloudflare/security-audit-skill) describes an extensive, human/agent-guided security audit methodology with isolation, coverage accounting and independent verification. **We did not copy the source, install its repository in IMPERIAL Core, or imply Cloudflare endorsement.** This original CYBER HAK gate supplies a narrower runnable static source-policy mechanism and can become one evidence input to a future broader audit workflow. Its success cannot be equated to completing the Cloudflare multi-phase audit.

## Extension without false security claims

Before extending to all 30 repositories, independently review a pinned reusable workflow, evidence retention in a private store, exact per-repository ownership and branch-protection enforcement. A successful scanning job alone does **not** prove it is a required branch check or block merges unless an active GitHub ruleset actually requires it. Do not use noisy scanner findings as "confirmed vulnerabilities" without separate reproduction and QA.

**Copyright / provenance:** Original IMPERIAL Core source contributions only, subject to applicable creator and contributor rights. Upstream third-party names, code and licenses remain separate.
