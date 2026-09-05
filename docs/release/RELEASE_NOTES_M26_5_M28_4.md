# ASTP M26.5-M28.4 — Qualification and Adaptive Coordinator Closure

This block closes another set of trust-boundary gaps without claiming full pentest readiness prematurely.

- Runtime qualification bundles are hashable, artifact-bound, and require explicit negative tests.
- Runtime qualification is exact-runtime-ID bound and requires a real sha256 artifact identity.
- Worker supervisor plans remain shell-free, signing-key-free, and require permit consumption before launch/network enablement.
- Worker receipts can be normalized and registered into the existing hash-linked Evidence Store.
- Verification actions are deduplicated and bounded before they return to policy evaluation.
- The adaptive coordinator now has explicit CONTINUE / REPLAN / STOP decisions with policy-drift, attestation, error, and action-budget stop conditions.
- A strict full-pentest acceptance gate requires runtime qualification, broad active verification, an adaptive-loop field test, an operator-gated state-change field test, and an authorized end-to-end field test.

No new command in this block performs network I/O.
