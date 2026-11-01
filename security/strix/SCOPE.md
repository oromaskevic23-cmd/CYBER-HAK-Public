# CYBER HAK / Strix — Strict Authorized Lab Scope

Security classification: PUBLIC SYNTHETIC SOURCE COPY ONLY.
Project Architect / Owner: Alexander Nikolaevich Romaskevich (RomaskevicH).

## Allowed target

- The disposable `public-source` directory prepared by `tools/strix-lab-runner.mjs`.
- Its copied `src/`, `test/`, `tools/` and `package.json` contents.
- Local source review and harmless proofs using synthetic fixtures only.
- Focus: broken authorization, signed-report/evidence tampering, missing deny-by-default,
  unsafe serialization, path traversal, workflow/supply-chain checks, fake security
  claims and other OWASP-relevant issues within the copied code.

## Explicitly forbidden

- Any third-party websites, production websites, IP networks, cloud services or GitHub API.
- Internet discovery, exploitation, credentials, remote requests, malware or persistence.
- Real HANTER, Supabase, CRYPTO IMPERIAL, wallets, exchanges, payments, tenant/customer data.
- Changing the real repository, private source code, live policy, database or deployments.
- Fetching scripts or dependencies from the internet during the test.
- Treating security tool output as higher authority than Owner approval or Guardian Core.

## Test environment requirements

Use only a disposable, independently egress-restricted VM, offline/local capable
Ollama model, preinstalled reviewed Strix and Docker images, no production credentials,
and a non-privileged local test account. The code-level runner deliberately does not
pretend to enforce the VM firewall or constrain Strix's sandbox network egress.

Strix may edit the disposable copy. Never give it the original working tree or
a secret-bearing home directory. No raw exploitation report may be published to the
public repository; hand findings to independent QA and a private Audit Ledger.

## Outcome protocol

Only a real completed Strix invocation with a retained run ID, tool version,
model identifier, scoped target digest, finding reproduction and independent QA
may be called `STRIX_VALIDATED`. A dry-run, static analyzer, or this instruction
file is not evidence that Strix was run.
