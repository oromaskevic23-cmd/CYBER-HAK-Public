# CYBER HAK AuditShield v0.2

Mission: `IC-ASTRA-CYBER-HAK-GITHUB-AUDIT-20261024-002`  
Owner: Alexander Romaskevich — RomaskevicH  
Classification: PUBLIC implementation and sanitized audit evidence  
Scope: owner-authorized, read-only inspection of three exact public GitHub revisions. No production activation.

This increment extends the defensive reference at `52241cf70ae5e9b8abd55c854b6aaedd52a6864d`. Its Artifact Guard, policy gate, registry validator and 44 baseline tests are preserved. The new reader must inspect `.github` and other dotfiles; the v0.1 artifact publication gate's blanket hidden-path rejection is deliberately not used as an audit severity rule. A readable file is not an approved executable or publication.

## Implemented behavior

- `src/github-reader.mjs`: exact repository + commit allowlist, public-repository check, anonymous GET requests to fixed GitHub API/raw hosts, redirects rejected, commit/tree binding, per-file Git blob SHA-1 verification and SHA-256 receipts. Source remains in memory and is never executed, installed or included in reports.
- `src/audit-rules.mjs`: provider-shaped credential candidates, credential-like high-entropy assignments, complete private-key blocks, sensitive/disguised filenames, hidden Unicode and explicitly disabled TLS in selected configuration files. No provider authentication or validity tests are made with candidates.
- `src/workflow-audit.mjs`: strict YAML parsing, effective job permissions, mutable action/reusable-workflow/image references, persisted checkout credentials, selected untrusted-context script interpolation, `pull_request_target` + untrusted checkout, simple download-to-shell forms, untrusted self-hosted runners and privileged container configuration.
- `src/auditshield.mjs`: reports contain repository, exact revision, file, line, rule, severity, confidence, fixed evidence description and remediation. Original source excerpts and candidate values are never copied. Credential-shaped paths are redacted and lose their source URL.
- `tools/audit-github.mjs`: live reader + scanner + JSON/Markdown reports and a receipt summary with report hashes and scanner source fingerprint. The caller-supplied `AUDITSHIELD_SOURCE_COMMIT` is traceability metadata, not a signature; compare the code fingerprint and CI revision when verifying it.

## Reproduce

Requires Node.js 22 or newer and network access to GitHub for the live audit. Unit tests themselves are offline. Installation uses the single locked parser dependency with lifecycle scripts disabled.

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm run verify
node tools/audit-github.mjs --targets config/audit-targets.json --out audit-output/run-001
```

Use a new output directory on each run: existing reports are never overwritten. `--help` describes options. `--fail-on-high` optionally gives exit 1 for a HIGH static indicator. Default exit 0 means **complete scanning**, including scans with findings; exit 2 means incomplete coverage or an error. A clean security bill is never inferred from exit 0.

`config/audit-targets.json` pins the three owner-authorized targets. Changing this file requires a new scope decision by the authorized operator. The allowlist is an execution constraint, not cryptographic approval or authority to inspect arbitrary private resources. This version never reads a GitHub token, API key or password from the environment. It cannot access private repositories.

## Boundaries and resource limits

- Maximum 500 non-directory tree entries, 256 KiB per blob, 8 MiB declared total blob size and 2 MiB per API JSON response. Response bodies are bounded while streaming. Requests time out after 12 seconds; no automatic retry loop or rate-limit bypass.
- Truncated trees, mismatched revision/tree/blob identities, invalid paths, limit breaches or denied responses fail closed. Failed targets receive `INCOMPLETE`, never a fabricated empty finding set.
- Symlinks and submodules are not followed. Binary/non-UTF-8 files and Git LFS pointers are explicit coverage gaps. No archives are unpacked. No detected file is launched.
- YAML aliases/anchors, unknown tags, duplicate keys, malformed syntax and unsupported root shapes make semantic coverage incomplete. This is a documented strict subset, not full GitHub workflow validation.
- The text-rule finding cap is 200 plus a limit indicator per file. Reaching it marks the report incomplete.
- No commit-history scan, other-branch scan, dependency CVE service, GitHub administration audit, full data-flow analysis, anti-malware engine or dynamic exploit validation. A revision with no configured indicators may still have vulnerabilities.
- No network access to a credential's provider, no target mutation, login automation, wallet access, deployment, scheduled/background worker or new global orchestrator. Canonical AI Passport, Enterprise Skills, Guardian Core, Approval Gateway, Audit Ledger and CRYPTO IMPERIAL Ecosystem Boundary remain external governance boundaries; this package does not impersonate them.

## False positives and verification

Provider-shaped values are candidates, not proven leaks. Comments and test files are not blanket-exempt: real secrets can occur there. Short placeholders, explicit placeholder forms and repeated synthetic suffixes are excluded, with negative tests. Credential markers without an encoded key body do not trigger the full-key rule. Ordinary Cyrillic and emoji are allowed; security-relevant invisible controls are separately reviewed.

Workflow comments do not become executable settings; explicit job permissions override global defaults. Untrusted values passed as environment data do not trigger the direct script-interpolation rule. Numeric PR identifiers and the trusted event name do not trigger that rule. These tests constrain common false positives; they are not a population-level accuracy benchmark.

The first local integrated run passed 94/95 tests. The failure was a test fixture that placed a shell comment in an unquoted YAML scalar, yielding null; the fixture was corrected to a literal script block. No production failure or security finding was concealed by deleting a test. Final counts and exact CI links are recorded in the sprint evidence document after actual execution.

## CI and rollback

The workflow installs the integrity-locked YAML dependency with `--ignore-scripts`, runs the complete baseline and extension suites, validates public registries, then actually audits the three pinned public revisions. Read-only `contents: read`, pinned checkout/setup-node SHAs and `persist-credentials: false` are retained. No target code is run by the live-audit step. Findings are rendered in the GitHub job summary. Success of this workflow proves only these checks and these revisions.

Work is proposed in a reversible feature branch. Rollback is an ordinary reviewed revert of the added audit files and associated package/workflow changes; preserve the v0.1 modules, history and original authorship. No force push or production migration is required.

## Dependency and primary references

`yaml@2.9.1`, ISC license, official project `eemeli/yaml`; package integrity is recorded in `package-lock.json`. No upstream source is rebranded as IMPERIAL-authored code. The scanner and tests are an IMPERIAL Core engineering change prepared with LLM assistance.

- [GitHub secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub workflow permission semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#permissions)
- [GitHub REST Git trees](https://docs.github.com/en/rest/git/trees)
- [GitHub REST Git blobs](https://docs.github.com/en/rest/git/blobs)
- [Official YAML parser API and security options](https://eemeli.org/yaml/)

This is a static defensive audit tool. No independent security certification, production monitoring or autonomous 24/7 service is claimed.
