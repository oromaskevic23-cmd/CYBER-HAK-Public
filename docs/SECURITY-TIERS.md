# CYBER HAK Security Activity Tiers

## T0 - Defensive / Passive

Defensive, passive activities that do not require active interaction with external targets. Examples include:

- inventory and discovery that do not affect targets
- static analysis
- configuration review
- telemetry and log analysis
- evidence review
- defensive research
- detection and analytics development

No active target interaction is permitted under T0.

## T1 - Authorized Active Validation

Authorized, actively scoped validation activities require ALL the following preconditions before execution:

- valid AI Passport
- appropriate Enterprise IMPERIAL Skills (EIS) capability
- Guardian Core ALLOW
- explicit Approval Gateway authorization
- exact target scope
- Runtime Domain binding
- Audit Ledger evidence

Authorization for T1 activities must be explicit, bounded, and recorded. T1 continues to honor deny-by-default policy and governance controls.

## T2 - Isolated Lab / CTF / Sandbox

T2 allows active experimentation only in isolated environments with strict boundaries. Requirements include:

- isolated and instrumented environment
- explicit scope and non-production targets
- sandbox containment with no uncontrolled external effects
- instrumented telemetry and evidence capture

T2 may be used for research, red-team exercises and training where no production targets are affected.

## T3 - Prohibited Autonomous Activity

T3 = ALWAYS DENY

T3 includes autonomous or unauthorized activities such as:

- real-world compromise or exploitation of third-party targets
- credential theft or unauthorized credential use
- destructive execution or data deletion in production
- unauthorized persistence mechanisms
- uncontrolled target expansion beyond approved scope
- governance or approval bypass
- autonomous financial or wallet operations

T3 activities are prohibited by policy and must not be executed under any circumstances without explicit and auditable governance exceptions.
