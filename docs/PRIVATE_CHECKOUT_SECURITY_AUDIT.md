# AuditShield v0.2 — Private Git Checkout Reader (Security Plugin)

Purpose: allow an externally pinned CYBER HAK scanner to examine selected source files from a private NCA repository **inside its own authorized CI runner**. Never fetch or publish private repositories through the public scanner, and never upload the private contents to CYBER HAK.

### Trust model

- CYBER HAK scanner source and scanner SHA must be pinned by the private consumer.
- The caller supplies `--root` (authorized checkout), `--commit` (exact checked-out git SHA), `--scanner` (exact independent scanner SHA) and `--out` (outside source checkout).
- Tool checks nine security-critical files are tracked, non-symlinks, UTF-8, below per-file size limits, and validates the source SHA against `git rev-parse HEAD`.
- Defensively scans secret patterns, hidden Unicode, workflow permissions and third-party CI pinning; outputs only file paths, digests, rule IDs and constant recommendations. No raw source or candidate secret values are copied into artifacts.
- `HIGH > 0`: nonzero exit code, no acceptance. Any file coverage or parser gap: nonzero exit code.

### Security acceptance boundary

This is an **independent-source automated static assessment**, not a second human reviewer or a container pen test. Existing CYBER HAK rules and tests are reused, but the execution runner is the NCA GitHub Actions environment. A clean report cannot certify hostile-code container escape resistance or approve release. The Owner Approval Gateway requires a real independently provisioned public trust root and an explicit signed review for the exact source commit; CI tests use ephemeral test keys only.

### Invocation

```
node /auditor/tools/audit-private-checkout.mjs --root /private/nca-checkout --out /tmp/cyber-report --commit <40-hex-NCA-sha> --scanner <40-hex-CYBER-sha>
```

No API tokens or administrative privileges are needed for the scanner itself. Both source and report remain inside the private consumer CI. Owner and human CYBER HAK release approval are NOT claimed.
