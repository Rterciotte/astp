# ASTP M38.5-M40.4 — Multi-runtime physical qualification

This block extends the first successful permit-gated security-tools field execution to Playwright and ZAP, and adds explicit physical qualification probes.

## Milestones

- M38.5 — Multi-runtime authorized-lab runner
- M38.6 — Playwright permit-gated physical observation
- M38.7 — ZAP passive-baseline permit-gated execution
- M38.8 — Exact URL target binding for browser/tool workers
- M38.9 — Worker protocol/runtime operation alignment
- M39.0 — Request-specific bounded-output enforcement
- M39.1 — Deterministic oversized local-lab fixture
- M39.2 — Physical bounded-output probe
- M39.3 — Signing-key image-configuration absence probe
- M39.4 — Fresh permit per physical runtime execution
- M39.5 — Cross-target consumption-proof rejection
- M39.6 — Runtime-specific receipt/evidence ingestion
- M39.7 — Runtime-specific qualification journal entries
- M39.8 — Physical probe evidence model
- M39.9 — Complete-probe qualification decision
- M40.0 — No partial-probe self-qualification
- M40.1 — Low-resource serial execution preserved
- M40.2 — Authorized-lab-only network path preserved
- M40.3 — Operator qualification scripts
- M40.4 — Regression + offline field harness

## Important

Passing the offline harness does not field-qualify a runtime. Physical qualification requires recorded evidence for every required probe plus an authorized local-lab execution. The runner never accepts an arbitrary Docker network or arbitrary target.
