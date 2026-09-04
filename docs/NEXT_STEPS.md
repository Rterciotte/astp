# ASTP next steps

## Completed foundation

Milestones 0 through 1.4 establish conservative scope compilation, granular authorization, bounded
approvals, signed execution permits, replay protection, revocation, key IDs for rotation, and a
hash-linked local audit trail.

## Milestone 2 — First non-offensive HTTP observation worker

The next milestone can introduce the first network-capable component, but only for observation. The
worker contract is:

```text
receive exact action + permit
    -> verify permit signature/key ID/freshness/current policy
    -> check revocation and atomically consume permit
    -> enforce exact target + HTTP method + identity + rate
    -> perform one observation-only HTTP request
    -> normalize response metadata
    -> store evidence
    -> append execution outcome to audit trail
```

The first worker must not perform exploitation, state-changing mutations, credential attacks,
fuzzing, crawling, scanner orchestration, or arbitrary shell execution.

### Milestone 2 hard requirements

1. explicit `ObservationRequest` and `ObservationResult` schemas;
2. strict URL canonicalization and redirect policy;
3. deny redirects that escape the authorized target boundary;
4. request timeout and response-size caps;
5. rate limiter enforced by the worker, not trusted from the caller;
6. sensitive-header/body redaction before evidence persistence;
7. evidence IDs and content hashes;
8. deterministic mock-server integration tests;
9. no direct Planner/LLM-to-network path;
10. permit is consumed before the network side effect.

## Later milestones

After the worker contract is stable: browser observation, context graph, evidence store, external
scanner adapters, finding correlation, risk prioritization, proof validation, reporting, retest,
white-box analysis, mobile analysis, and planner/LLM orchestration behind the same policy and permit
boundary.

Before distributed workers, replace HMAC with asymmetric signatures and move lifecycle state/audit
to transactional and independently protected storage.
