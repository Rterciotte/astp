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

Remaining roadmap: M2–M8.
