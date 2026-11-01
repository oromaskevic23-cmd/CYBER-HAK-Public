# CYBER HAK × Strix — Enterprise Defensive Integration (v0.2)

**Status: LOCAL STRIX RUNNER PREPARED — NO STRIX PENTEST EXECUTED OR VERIFIED.**

Strix is a third-party open-source AI penetration-testing tool; upstream source:
https://github.com/usestrix/strix. Strix is not part of IMPERIAL Core proprietary code.
Respect its Apache-2.0 license and independent trademarks; do not imply a partnership.

Official setup and CLI:
- https://docs.strix.ai/quickstart
- https://docs.strix.ai/usage/cli
- https://docs.strix.ai/llm-providers/local

## Why the integration is deliberately isolated

Strix dynamically explores code and can use offensive testing tools. Upstream
documentation says a local target directory is writable from the Strix sandbox.
CYBER HAK therefore never points Strix at the original GitHub working tree,
live Supabase services, production wallets, or third-party infrastructure.

A real egress-filtered disposable VM is required **outside** this script: an
instruction prompt and an environment-variable acknowledgment are NOT
a kernel-enforced sandbox policy or a network firewall.

## Current verified development environment limitations

- Current execution sandbox: no Strix CLI and no Docker daemon found.
- All connected remote Desktop Commander devices were offline at inspection.
- No local tool-calling Ollama model accessible in the current sandbox was established.
- Therefore **zero real Strix scans** and **zero Strix-verified vulnerabilities**.
- Existing CYBER HAK security policy and new tests are separate from Strix results.

## Zero-cost / local-only workflow

On an Owner-approved, disposable, isolated host with Docker and Strix installed,
and reviewed images already cached locally:

1. Review the exact released Strix version, dependencies, upstream license and
   host firewall. Do not use `curl | bash` to install a security-critical tool.
2. Install via an independently verified versioned package in that host only,
   using official installation instructions. Keep Strix outside production NCA
   workloads. Confirm `strix --version` and `docker info` work.
3. Run preflight, which **does not execute Strix**:

   ```sh
   node tools/strix-lab-runner.mjs --preflight
   ```

   For actual read-only checks of Docker, the Strix executable, Ollama and the
   preinstalled local model, use:

   ```sh
   npm run strix:doctor
   ```

   The doctor performs local binary and model checks only. It cannot prove
   firewall isolation, AI Passport validity or successful pentesting, even when
   every binary is found. It refuses known secret-bearing and remote Docker
   environments and does not pull models, Docker images or dependencies.

4. Configure a capable locally hosted **tool-calling** model, e.g. an Ollama
   model you have tested for structured `tool_calls`, and only the loopback base:

   ```sh
   export STRIX_LLM="ollama/qwen3-vl"
   export LLM_API_BASE="http://127.0.0.1:11434"
   export CYBER_HAK_STRIX_EXPECTED_VERSION="REPLACE_WITH_VERIFIED_RELEASE_VERSION"
   ```

5. After verifying the disposable VM is egress-filtered, explicitly authorize
   the bounded lab run **only**:

   ```sh
   export CYBER_HAK_STRIX_LOCAL_RUN="EXPLICITLY_APPROVED"
   export CYBER_HAK_STRIX_ISOLATED_HOST="CONFIRMED"
   node tools/strix-lab-runner.mjs --run
   ```

The runner:
- rejects cloud LLM model and remote LLM base configuration;
- refuses known privileged API secrets passed as environment variables;
- checks Docker and Strix CLI availability and requires an independently confirmed exact Strix version;
- records a deterministic SHA-256 fingerprint of the disposable source tree before and after the scan;
- applies a local-defense budget of USD 0.01 (a secondary cap, **not** a paid-model authorization);
- checks for symlinked source and scans a **temporary public-code copy**;
- requests a quick scan with max 80 model turns and external-scope-denial instructions;
- writes private `source-provenance.json`, `receipt.json` and raw Strix logs to the disposable host's protected temporary directory;
- rejects a clean claim when Strix reports an incomplete/stopped scan, missing `run.json`, missing `vulnerabilities.json`, missing completed timestamp, missing recorded model usage, a target different from the copied public source, a cost near the budget cap, or inconsistent findings/exit status;
- never streams raw security scanner output into public CI logs;
- does not claim a success when Strix fails or finds vulnerabilities.

**Caveats:** The two `CONFIRMED` variables are Owner/operator assertions, not proof
of firewall protection. For real isolation, implement and independently test
kernel/container and host egress restrictions, secrets exclusion and filesystem
mount policy. Protect the host Docker daemon; Strix agents are not trusted
workload identities. Local models below 70B may struggle with Strix agentic
tool use, per upstream docs, so a successful *launch* is not evidence of a
complete security assessment.


## Version lock and validated evidence protocol (v0.2)

The `CYBER_HAK_STRIX_EXPECTED_VERSION` value is not a placeholder you may use
literally: replace it with the exact SEMVER obtained from a separately verified
Strix upstream release, and confirm the installed CLI reports the same release.
No particular Strix version is asserted as verified by this repository.

The scanner is never automatically invoked by CI; only `--preflight` runs.
A real scan requires the separately approved disposable offline/egress-filtered
host, Docker, correct local model, and version lock.

An actual run produces:
- `source-provenance.json` — hashed files copied to the temporary target, scan
  instruction hash, intended Strix version and local model;
- `strix-private.log` — untrusted scanner output on the private lab host;
- `strix_runs/<run-id>/run.json` and `vulnerabilities.json` — actual Strix
  artifacts (schema varies across versions; unfamiliar formats fail closed);
- `receipt.json` — scoped result and hashes, always
  `independentQA:false` and `productionAuthorized:false`.

The CLI exit code is NOT enough to claim a clean result. Version v0.3 also
requires the reported Strix target to match the disposable source directory,
run.json end_time and llm_usage.cost; a scan close to its budget is marked
coverage-unverified even when the CLI exits zero. Run status
`stopped` or missing artifacts is treated as incomplete, and exit 2
means candidate vulnerabilities requiring independent QA, not automatic
exploitation authority. Even the `STRIX_REPORTED_NO_FINDINGS_QA_PENDING`
status does not prove the absence of vulnerabilities or comprehensive coverage.

The source SHA-256 is a tamper indicator, not a trusted digital signature.
Real evidence attestation requires an independently authorized signer,
private Audit Ledger and separate source inventory verification.

## Mandatory vulnerability handling

```
Architect / Owner
    ↓ scope and authorization
HANTER (Command Center)
    ↓ federated security orchestrator (not a global singleton)
CYBER HAK scoped skill + Guardian Core + Approval Gateway
    ↓ isolated authorized Strix lab
Validated finding → Independent QA → ProofGraph → Audit Ledger
    ↓
Owned-repository remediation PR → CI + regression test → Owner-approved release
```

Findings are never permitted to mutate production automatically. Each finding
requires source revision, original report hash, reproduction proof in a
separate staging fixture, a minimal fix, an independent negative regression
test and rerun of the existing enterprise quality gate.

All production activity remains denied until real Owner-backed Ed25519
authorization, AI Passport, valid Enterprise Skills, an isolated authenticated
worker, and explicit release-specific approval exist. HANTER remains the
command center; multiple domain orchestrators maintain autonomous bounded
responsibility. Preserve Zero Trust, Owner Kill Switch, Public/Private
Boundary and CRYPTO IMPERIAL Ecosystem Boundary.

## Evidence vs claims

The audit engine `src/fleet-security-audit.mjs` is a deterministic **static
metadata** checker. Its `evidenceSha256` is a checksum, not a digital
signature or trusted report provenance; aggregation rejects malformed
evidence and prevents missing alerts from becoming a PASS. It does not prove
source-of-truth completeness or replace Strix dynamic testing.

A `STRIX_VALIDATED` result must come from an actual executed Strix run and
independently observed traces. Never label the static-engine findings as
“Strix found” merely because a Strix wrapper exists.

**Current next blocker:** a dedicated egress-restricted host with working
Strix, Docker and a sufficiently capable local LLM. Do not spend on cloud
LLM/API calls until the Architect separately authorizes such expenditure.

## Sprint 006 — Mandatory Owner-signed lab permit (Ed25519, zero network)

**Unsigned environment-variable approval is no longer sufficient to start Strix.**
The actual `--run` path now requires an independently trusted Owner Ed25519
public-key fingerprint and a signed, time-limited, one-use permit. Nothing in
this public repository provisions the Owner private key, signs a permit,
confirms the signing authority, or performs a real Strix scan.

1. Run `node tools/strix-lab-runner.mjs --preflight` on the approved source
   checkout. This creates only an ephemeral local copy and reports
   `sourceSha256` plus `scopeSha256` in its output. It does not run Docker,
   Strix or Ollama. The digests become invalid if the source or policy changes.
2. Using a **separate, trusted Owner-controlled signing workflow** (outside
   the Strix sandbox and GitHub), construct the 12-field permit payload:
   `schema=cyber-hak.strix.owner-lab-permit.v1`,
   `missionId=IC-STRIX-...`, exact `targetSha256`, `scopeSha256`,
   `model`, `strixVersion`, fresh one-use `nonce`,
   `issuedAt`, `expiresAt` in Unix epoch milliseconds, both
   `productionAuthorized=false` and `externalTargetsAuthorized=false`,
   and `maxBudgetUsd="0.01"`. Maximum signed TTL is five minutes.
3. Canonical signing material is
   `CYBER_HAK_STRIX_LAB_AUTH_V1\n` followed by compact JSON of those fields
   in the order defined in `security/strix/signed-permit.mjs`.
   Sign that byte sequence using Owner Ed25519. Set permit JSON object
   `{ "payload": ..., "signature": "<canonical-base64url-ed25519-signature>" }`.
   A real enrollment service must establish and hold the Owner public-key
   fingerprint independently, never from the untrusted permit itself.
4. On an **egress-filtered disposable, Owner-controlled VM only**, configure
   the following *local environment paths*. Paths refer to secure files
   outside the Strix target and outside GitHub:

   ```sh
   export CYBER_HAK_STRIX_SIGNED_PERMIT_PATH="/secure/owner-lab-permit.json"
   export CYBER_HAK_STRIX_OWNER_PUBLIC_KEY_PATH="/secure/owner-public-spki.pem"
   export CYBER_HAK_STRIX_OWNER_SPKI_SHA256="REPLACE_WITH_PINNED_64_HEX_SHA256"
   export CYBER_HAK_STRIX_NONCE_STORE="/secure/durable-nonces"
   ```

   These placeholders are not real credentials or current IMPERIAL Core
   Owner enrollment. Never copy a private signing key, recovery phrase or
   production API token into the test environment.
5. The scanner verifies the Ed25519 signature, pinned Owner SPKI hash, exact
   code and scope SHA-256, model, installed Strix version and max budget.
   It atomically consumes the nonce in a `0700` local directory before the
   scanner runs. A replay or scope mismatch is blocked. Scanning is capped
   by remaining permit lifetime and results produced after expiry are denied.

**Trust limitation:** Local files and environment strings are not a
hardware-backed or server-validated enrollment mechanism. A privileged
administrator of the test VM can alter that VM. The durable nonce store
blocks replay on one host, not across independently cloned VMs. Before
production or repeatable distributed use, bind the trusted Owner public
key and nonce consumption to the protected HANTER Approval Gateway and
Audit Ledger. No real Owner grants have been minted by this implementation.

**Status:** the published tests use ephemeral, synthetic Ed25519 keys.
The actual Strix runtime remains unexecuted until the Owner trust root,
isolated host and local tool-calling LLM are available.
