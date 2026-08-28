# Execution Permits

Milestone 1.3 introduces a signed, short-lived authorization artifact between policy evaluation
and any future worker. ASTP still performs no network execution in this milestone.

## Invariant

```text
Planner -> Policy evaluation -> Signed execution permit -> Worker -> Evidence
```

A future worker must never accept only a target URL or a planner instruction. It must receive and
verify a permit that is bound to the exact authorized action.

## Permit contents

Each permit binds:

- engagement ID;
- test ID and risk class;
- exact target;
- HTTP method when supplied;
- logical identity when supplied;
- effective maximum request rate;
- approval artifact IDs used by authorization;
- current engagement/test policy digest;
- issue and expiry timestamps;
- a unique permit ID.

The default lifetime is 300 seconds and the current hard maximum is 900 seconds.

## Signature

Milestone 1.3 uses HMAC-SHA256 with a key supplied through `ASTP_PERMIT_KEY`. The key must contain
at least 32 bytes and is never written into the permit file.

HMAC is appropriate for this local foundation, but it is not the final trust model for distributed
workers because any verifier holding the shared secret could also mint permits. Before workers are
split across trust boundaries, ASTP should migrate permit signing to an asymmetric scheme so only
the policy service owns the private signing key and workers receive verification keys only.

## Policy freshness

A SHA-256 digest of the complete current `Engagement` and `TestDefinition` is embedded in the
signed payload. Verification recomputes that digest. A policy or test-definition change therefore
invalidates an already-issued permit rather than silently preserving old authorization.

## Non-goals in this milestone

There is no scanner, HTTP worker, replay cache, centralized permit registry, key rotation service,
or remote execution. Replay prevention requires state and will be introduced with the worker
boundary. Until then, expiry and exact action binding reduce but do not eliminate replay risk.
