# CYBER HAK Public — Defensive Reference v0.1

**Status:** E2 code present; E3 pending exact-commit GitHub Actions validation  
**Classification:** PUBLIC reference only; not an activated antivirus product, SOC or production runtime  
**Owner:** IMPERIAL Core Founder / RomaskevicH

## Engineering implementation

- `src/artifact-guard.mjs`: read-only text artifact review. Reject sensitive paths, traversal, hidden/control Unicode, text payloads larger than 256 KiB and common secret-like patterns; return SHA-256 digest without the original content.
- `src/policy-gate.mjs`: restricted T0/T1/T2 reference policy decision, T3 denied unconditionally, HMAC-signed short-lived scoped permit verification, in-process nonce replay protection. **A human-approved issuer is only declared in token metadata; this reference cannot independently authenticate a human or sign permits securely.** Do not use as a production approval service.
- `src/registry-validation.mjs`: fail-closed checks for PUBLIC manifest, 59 declared capability families, 30 documented threat categories, 5 severity levels and governance default-deny properties.
- `test/*.test.mjs`: positive and negative unit tests for the above contracts.
- `.github/workflows/cyber-hak-ci.yml`: no third-party runtime dependencies; Node.js 22; read-only token; pinned checkout/setup-node action commit SHAs; no credentials persisted.

### Reproduce offline

```sh
npm run verify
```

Node 22 standard library; no npm install, API keys, production deployment, target scanning or unauthorized network connections required.

## Threat model and critical limitations

This is **not** anti-malware signature scanning, memory protection, ransomware prevention, an EDR agent, live incident response, sandboxing, forensic chain-of-custody, an actual enterprise Access Control Service, antivirus efficacy certification, distributed replay prevention, persistent storage or autonomous execution. It cannot establish whether arbitrary files are malware-free. Pattern heuristics generate false positives and negatives. All execution/release results remain `NOT_RUN` / `DENIED`.

Do not accept untrusted objects/large cyclic structures from external processes without separate strict JSON boundary validation and size limits. A real signer must verify the human's identity, capture exact task scope and never expose signing keys to the worker. Production use requires key rotation, independent approval authority, revocation, durable anti-replay store, short-lived worker rights, rate limits, audit logs, sandbox isolation, formal penetration testing and incident exercises.

## Next acceptance gates

1. Confirm exact source HEAD and passing GitHub Actions link; E3 is bounded to reference module unit tests.
2. Build independent adversarial test suite for malformed tokens/duplicate properties, serialized untrusted inputs, Unicode confusables, dangerous path edge cases and exhausted resources.
3. Introduce a separate signing authority (not self-signing agents) and durable nonce store, first in isolated test environment.
4. Produce measurable scanner correctness benchmarks against legally distributable nonmalicious/malicious test corpus, explicit false-positive/false-negative rates and independent QA.
5. Integrate under Guardian Core / Approval Gateway with explicit authorized scope; no production writes or scans without separately verified human approval.

**No tests → no test claims. GitHub workflows must actually complete on this exact SHA before E3 status can be recorded.**
