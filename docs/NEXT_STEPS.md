# ASTP next steps

## Completed foundation

Milestones 0 through 1.4 establish conservative scope compilation, granular authorization, bounded
approvals, signed execution permits, replay protection, revocation, key IDs for rotation, and a
hash-linked local audit trail.

Milestone 2 adds the first permit-gated network component: a one-request HTTP observation worker for
`GET` and `HEAD`. It consumes a valid permit before connecting, never follows redirects, bounds
network timeout and captured body size, redacts common secrets, writes hashed evidence, and records
execution outcomes in the audit chain.

## Milestone 2.1 — Observation hardening and Evidence Store v0.1

Before adding scanners or a browser worker, strengthen the observation contract:

1. canonical action identifiers without unsafe path/query normalization;
2. durable per-target rate limiting across multiple permits;
3. explicit evidence IDs and an indexed evidence manifest;
4. evidence integrity verification over manifests and artifacts;
5. configurable redaction policy and sensitivity labels;
6. optional encrypted raw artifact storage for engagements that explicitly require it;
7. deterministic DNS/connection metadata capture without expanding scope;
8. explicit redirect authorization model if same-origin redirects become necessary;
9. failure evidence for timeout/TLS/DNS cases without leaking secrets;
10. interface boundary separating policy service, verifier, worker, and evidence store.

## Later milestones

After the worker/evidence contract is stable: browser observation, context graph, external scanner
adapters, unified finding schema, finding correlation, proof validation, CVSS 4 + EPSS + KEV risk
prioritization, reporting, retest, white-box analysis, mobile analysis, and planner/LLM orchestration
behind the same policy and permit boundary.

Before distributed workers, replace shared-secret HMAC permits with asymmetric signatures and move
lifecycle state/audit to transactional and independently protected storage.
