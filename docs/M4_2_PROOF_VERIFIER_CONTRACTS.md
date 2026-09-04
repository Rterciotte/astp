# M4.2 — Proof Verifier Contracts

Adds proof-state guardrails. Generic observation evidence cannot silently establish VERIFIED or IMPACT_CONFIRMED.

## Invariant

`Planner -> Policy -> Execution Permit -> Adapter/Worker -> Evidence` remains mandatory.
