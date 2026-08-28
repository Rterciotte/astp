# ASTP next steps

## Completed foundation

Milestones 0 through 1.3 now establish conservative scope compilation, granular authorization,
bounded approvals, and signed short-lived execution permits.

## Milestone 1.4 — Permit lifecycle hardening

Before adding network execution:

1. introduce permit consumption state and replay protection;
2. define revocation and key-rotation interfaces;
3. separate signer and verifier trust boundaries;
4. prepare migration from shared-secret HMAC to asymmetric signatures;
5. add an append-only authorization/permit audit log;
6. normalize action bindings so canonical URLs cannot create accidental mismatches;
7. add deterministic clock injection throughout policy and permit tests.

## Milestone 2 — First non-offensive worker

Only after the permit lifecycle is hardened, add an isolated HTTP observation worker. It should:

```text
receive permit
    -> verify signature and freshness
    -> atomically consume permit/replay token
    -> enforce exact target + method + rate
    -> perform observation-only request
    -> store evidence
```

The first worker must not perform exploitation, state-changing mutations, credential attacks, or
scanner orchestration.

## Later milestones

After the worker contract is stable: browser observation, context graph, evidence store, external
scanner adapters, finding correlation, risk prioritization, proof validation, reporting, retest,
white-box analysis, mobile analysis, and finally planner/LLM orchestration behind the same policy
and permit boundary.
