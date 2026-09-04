# M2.6 — Program Runtime Gates & Field-Ready Compilation

M2.6 bridges reviewed bug-bounty policy into permit-gated execution without weakening program-level
operational rules.

## Program binding

`compile-program` now carries a `program` binding into the executable `Engagement`:

- stable program ID and platform;
- source-policy SHA-256 revision binding;
- whether the program must be online;
- the program-recommended User-Agent, when present;
- excluded finding types extracted from source policy;
- maximum age for a program-status attestation (default: 300 seconds).

The reviewed request-rate limit and semantic deny guardrails continue to live in engagement
constraints and therefore remain part of the permit policy digest.

## Operational-status attestation

A policy such as "testing is prohibited while the program is offline" is a runtime condition, not
merely intake metadata. M2.6 therefore requires a fresh `ProgramOperationalAttestation` whenever the
compiled program has `requires_online: true`.

Create one only after actually checking the current program state:

```powershell
astp attest-program-status .\programs\smartfit.yaml `
  --status online `
  --source operator `
  --note "Verified on the authenticated BugHunt program page" `
  -o .\.astp\smartfit-online.yaml
```

The attestation is bound to the exact normalized program revision using the source content SHA-256.
It is intentionally short-lived. An old attestation cannot silently authorize a later policy
revision.

Authorization behavior:

- no attestation -> `INSUFFICIENT_CONTEXT`;
- stale attestation -> `INSUFFICIENT_CONTEXT`;
- unknown status -> `INSUFFICIENT_CONTEXT`;
- attestation for another program/policy revision -> `INSUFFICIENT_CONTEXT`;
- `OFFLINE` -> `DENY`;
- fresh matching `ONLINE` -> continue through semantic, scope, context, risk, and rate gates.

## Permit lifetime cap

A permit issued under an ONLINE attestation can never outlive that attestation. If the operator asks
for a 300-second permit but the attestation has only 60 seconds remaining, the permit expires in 60
seconds.

Permit schema v3 records the operational attestation ID. Verification remains backward compatible
with schema-v1/v2 permit signatures.

## Program User-Agent

The bounded HTTP observation worker now uses the program-recommended User-Agent from the compiled
engagement when one exists. Otherwise it uses the ASTP observation-worker User-Agent.

This means Smart Fit's reviewed engagement can send `Bughunt - Security Research` without a worker
hard-code or a manual header override.

## Safety boundary

M2.6 does not add crawling, exploitation, mutation, credential attacks, scanners, or arbitrary
browser automation against targets. Network execution remains the existing one-request GET/HEAD
worker behind authorization and a signed single-use permit.

The current status attestation can be operator-sourced. A later control-plane enhancement may
produce the same artifact from an authenticated Browser Companion observation, without exporting
site credentials or cookies.
