# ASTP Next Steps

Current cumulative release: **v0.23.0 / M3.6**.

Completed control-plane progression:

```text
M2.6 program runtime gates
M2.7 redirect-safe target candidates
M2.8 evidence-derived link discovery
M2.9 target registry + provenance
M3.0 deterministic observation planner
M3.1 fair multi-program work queue
M3.2 Security Test DSL v0.1
M3.3 security graph v0.1
M3.4 hypothesis graph v0.1
M3.5 proof states + finding correlation
M3.6 evidence report + retest plan
```

Recommended next implementation block:

1. **M3.7 Permit Broker** — convert selected `authorizable` plan items into explicit operator-reviewed permit issuance requests; never bulk-sign silently.
2. **M3.8 Durable Planner State** — persist plan/hypothesis transitions transactionally and make crash recovery deterministic.
3. **M3.9 Observation Result Interpreter** — feed status/headers/content metadata back into the graph without vulnerability claims.
4. **M3.10 Bounded Surface Mapper** — configurable breadth/depth budgets, still one permit per network action and respecting program rate limits.
5. **M3.11 Adapter Registry v0.1** — declarative external-tool capabilities before any scanner integration.
6. **M3.12 Proof Verifier Contracts** — test-specific proof requirements and reproducibility checks.

The invariant remains:

```text
Planner -> Policy evaluation -> Execution permit -> Adapter/worker -> Evidence
```

No planner, hypothesis, queue, DSL, graph, or report object is an execution capability.
