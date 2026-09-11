# M53 local master completion checkpoints

## M1 — real ProgramOperationalLease lifecycle

Status: `M53_HIGH_1_REAL_LEASE_PASS`

The authorization path now requires a durable `OperationalLeaseStore` before
a stale operational attestation can be extended by a lease. The store provides
atomic issuance, recovery, renewal/supersession and revocation state. Recovery
revalidates content integrity, revision and attestation binding, freshness,
activation and expiry; it cannot revive superseded, revoked, expired or
revision-invalid leases. Execution permits remain capped by the authoritative
lease validity boundary. `DetectorExecutionService` no longer trusts a
`lease_current` boolean: operationally bound programs must provide the real
engagement, attestation, durable lease authority and upstream signed execution
permit. Both authorities are revalidated before launch, and the detector-run
permit is capped by the lease boundary. All acceptance is local and performs
zero target I/O.

## M2 — full local intake to authorization and execution chain

Status: `M53_HIGH_2_AUTH_CHAIN_PASS`

`derive_local_authorized_detector_request` starts from fake browser listing and
detail captures, persists the capture and normalized program, compiles policy,
builds the target-bound semantic plan and fair queue, issues a durable real
operational lease, brokers an upstream signed execution permit, and constructs
the detector request only from those artifacts. `DetectorExecutionService`
revalidates the lease and permit before worker launch. The physical acceptance
ran the qualified Nuclei worker through the qualified counting proxy to the
isolated `astp-m52-lab` container with a one-request ceiling: attempted=1,
forwarded=1, responses=1, evidence=1, proof=`reproduced`. Missing permit and
revision drift both block before adapter invocation; the broader suite covers
offline/policy/scope/semantic/budget/method/runtime negative gates.

Remaining roadmap: M3–M8. The legacy full-night driver is intentionally handled
in M4, where lease and scheduler state must be produced by the nightly engine.
