# IMPERIAL EYE — Defensive Evidence Fusion Security Gate (2026-11-10)

**Program:** IMPERIAL Core / CYBER HAK / IMPERIAL EYE  
**Founder and final architectural authority:** Alexander Nikolaevich Romaskevich (RomaskevicH), Founder • Owner • CEO • Chief Systems Architect  
**Engineering state:** PR candidate. This is **not** a production deployment, independent audit, or 24/7 monitoring system.  
**Budget:** FREE_ONLY — USD 0. **No external requests or agents are started by this change.**

## Verified existing baseline

- Existing source atlas indexes two official publisher portals and a dated, bounded sample of twelve Fintraffic station metadata records. It cannot truthfully claim live camera availability.
- Existing local WebAuthn verification checks ES256 device assertions, but real Owner key enrollment and protected server authentication endpoints are not deployed.
- The official API adapter restricts outbound reads to a fixed publisher endpoint with response-size limits. Review identified a **parser hardening gap**: the gzip decoder previously accepted trailing compressed members/trailing data without rejecting the envelope.
- Multiple service OOM/restart incidents may require operational review; a later healthy event is not sufficient evidence of a stable production service. This PR does not imply access to live Render telemetry.

## Changes in this PR

1. **Official API envelope guard.** The gzip decoder now refuses an extra gzip member or arbitrary trailing bytes. Regression tests exercise both cases with synthetic payloads. The adapter still has no camera probing or image downloading capability.
2. **Evidence Fusion v0.1.** `evidence_fusion.py` accepts a bounded batch of `imperial.eye.system-event.v1` objects supplied by an *external authorized collector* and converts them to deterministically grouped infrastructure incidents.
3. **Multi-orchestrator separation.** Events have an explicit tenant ID, orchestrator ID and component ID. Cross-tenant records, invalid event/component combinations, stale/future observations, conflicting event IDs, and unsupported extra fields fail closed.
4. **Operator review before action.** A repeated OOM produces a critical incident candidate. The code cannot restart servers, approve jobs, grant an Owner session, control cameras, or trigger NCA execution.
5. **Evidence semantics.** SHA-256 hashes bind the supplied payload for comparison only. They do **not** establish signed origin, device identity, operator authorization, live service status, legal rights, or independent QA.

### Reproducible test command

```bash
python3 -m unittest discover -s security/imperial_eye/tests -p 'test_*.py' -v
```

The existing lightweight [IMPERIAL EYE policy workflow](../../.github/workflows/imperial-eye.yml) is responsible for testing changed source in CI. Workflow success is evidence for that commit only. Full passkey tests require the repository's pinned WebAuthn dependencies; no dependency installations on production hosts are approved here.

## Security boundaries

- **No person lookup:** no personal contact discovery, face identification, plate tracking, phone/email search, hidden location tracing or personal dossier generation.
- **No unlawful camera collection:** only publisher-authorized public links, and separately operator-enrolled feeds with verified rights under a future private architecture.
- **No public infrastructure map:** tenant topology, credentials, source IPs, trust roots, user identities, live incident logs and signing keys must not be put into public documents, client JS, public repositories, or static Netlify assets.
- **Owner authority:** architecture retains HANTER, federated domain orchestrators, NCA AI Passport, Enterprise Skills, Guardian Core, Approval Gateway, Audit Ledger, independent QA, Owner Kill Switch, Zero Trust, and the Public / Private and CRYPTO IMPERIAL Ecosystem Boundaries.

## Fail-closed operator acceptance criteria

| Gate | Requirement | Current status |
|---|---|---|
| P0 Input parsing | No extra gzip members/trailing bytes or unconstrained JSON batches | Source change + regression tests in this PR; CI required |
| P0 Event provenance | Private collector authentication and cryptographic source attestations | NOT IMPLEMENTED |
| P0 Owner login | Actual Owner enrollment, protected WebAuthn origin and server sessions | NOT DEPLOYED |
| P0 Incident isolation | Independently tested authorization by tenant and orchestrator | Laboratory schema checks only |
| P0 Operational budget | Safe collector cadence, memory ceiling, rate-limit backoff, kill switch | NOT DEPLOYED |
| P1 Audit | Tamper-resistant server-side ledger and independent QA | NOT VERIFIED |
| P1 Production UI | Private, authenticated control center with redacted data | NOT DEPLOYED |
| P1 External sources | Each publisher's usage rights and timestamp checked independently | Existing dated sample only |

## Deployment decision

**NO-GO for production.** Merge only after CI review, then separately enroll the Owner and conduct a permitted independent security assessment. The existence of a Netlify site or a Figma/Lovable design does not verify a protected backend, camera access, or production integration. Public Netlify properties must not expose incident telemetry or Owner endpoints without validated authentication and authorization.

**Positioning:** an enterprise defensive situational-intelligence platform with provenance and governed response, distinct from personal-data lookup services. It is not claimed to be more accurate, broader, or more commercially successful than any named competitor without independent comparative testing.
