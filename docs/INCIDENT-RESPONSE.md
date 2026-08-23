# CYBER HAK Incident Response

## IR-01 - Detection

Purpose:
Identify a potential security event using telemetry, alerts, reports, anomaly signals or trusted evidence.

Required evidence:
- timestamp
- source
- affected asset
- initial severity
- confidence
- classification

## IR-02 - Triage

Purpose:
Determine whether the event is benign, suspicious or a confirmed security incident.

Required checks:
- scope
- affected systems
- data classification
- potential impact
- confidence
- containment status

## IR-03 - Containment

Purpose:
Reduce risk without uncontrolled destructive action.

Controls:
- least-disruptive containment first
- bounded scope
- explicit authorization for active changes
- record every material action

## IR-04 - Evidence Preservation

Purpose:
Preserve trustworthy evidence before remediation changes the environment.

Requirements:
- integrity-protected evidence
- timestamps
- provenance
- chain-of-custody
- hashes when applicable
- classification marking

## IR-05 - Analysis

Purpose:
Reconstruct what happened, why it happened and which boundaries were affected.

Analyze:
- identity
- authorization
- runtime
- data
- audit
- supply chain
- external integrations
- policy controls

## IR-06 - Remediation

Purpose:
Remove or reduce the defensive root cause.

Allowed defensive remediation examples:
- revoke access
- rotate compromised credentials through approved process
- patch vulnerable software
- harden configuration
- repair policy
- isolate compromised components
- update detection logic

Do not include offensive retaliation.

## IR-07 - Verification

Purpose:
Prove that remediation worked.

Require:
- regression verification
- control re-check
- evidence
- no unresolved critical findings

## IR-08 - Closure

Closure requires:
- incident status documented
- evidence complete
- affected boundaries identified
- remediation status recorded
- remaining risk documented
- audit evidence present

## IR-09 - Post-Incident Review

Document:
- root cause
- contributing factors
- control failures
- detection gaps
- lessons learned
- prevention actions
- evidence references
