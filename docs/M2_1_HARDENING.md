# Milestone 2.1 — Observation hardening and Evidence Store v0.1

M2.1 strengthens the first network worker without widening its offensive capability. The worker is
still restricted to one permit-gated HTTP `GET` or `HEAD` and still follows no redirects.

## Added in 2.1

### Canonical action identity

ASTP now derives a SHA-256 action ID from method, identity, and a conservative HTTP target
canonicalization. Scheme and host are lower-cased, default ports are removed, an empty path becomes
`/`, and URL fragments are excluded because they are not sent to HTTP servers. Path and query text
are deliberately not decoded, reordered, collapsed, or otherwise normalized.

### Durable rate state

A local, lock-protected rate-state file enforces spacing between observations across independently
issued permits. The rate key is based on the canonical target rather than identity or HTTP method,
so changing those fields cannot bypass the target budget. This is a conservative local primitive;
distributed workers will require transactional shared state.

### Evidence Store v0.1

Every HTTP observation now has an explicit evidence ID, action ID, and sensitivity label. After the
artifact is written, ASTP appends an entry to a hash-linked evidence manifest. Each entry contains
the artifact SHA-256, previous entry hash, and its own canonical entry hash.

Verify the complete local evidence set with:

```powershell
astp verify-evidence-manifest .\.astp\evidence-manifest.jsonl
```

By default verification checks both the manifest chain and every referenced artifact. Use
`--skip-artifacts` only when intentionally checking the chain without local artifacts.

### Sensitivity labels

Observation evidence supports `public`, `internal`, and `sensitive`. The default is `internal`.
This is metadata for downstream handling and reporting; M2.1 does not claim that a label itself
provides encryption or access control.

## Security properties

M2.1 keeps the existing permit verification, policy digest, exact action binding, single-use permit
consumption, redirect refusal, bounded body capture, secret redaction, lifecycle audit, and local
file locking. It also fixes the M2 rejected-observation audit call so rejection paths use the audit
API correctly.

## Deliberately deferred

Encrypted raw artifacts, configurable redaction profiles, explicit DNS/connection evidence,
authorized same-origin redirect chains, asymmetric permit signatures, and transactional distributed
state remain later hardening work. None is silently simulated by M2.1.
