# Milestone 3.0 — Deterministic Observation Planner

M3.0 is the first adaptive-planning bridge. It converts safe discovery candidates into proposed GET observations and runs the normal authorization engine against each proposal.

Planner states:

- `authorizable`: current policy returns ALLOW, but no permit exists yet.
- `blocked_context`: operational attestation, semantic review, approval or other context is missing.
- `blocked_policy`: policy denies the action.
- `rejected_discovery`: deterministic discovery guardrails rejected the target.

Even `authorizable` items contain `permit_id: null` and `requires_new_permit: true`.

```powershell
astp plan-observations .\.astp\target-registry.yaml .\engagements\program.yaml `
  .\examples\test-observation.yaml `
  --program-status-attestation .\.astp\program-online.yaml `
  --semantic-clear RULE_ID `
  --rps 1 `
  --output .\.astp\observation-plan.yaml
```

Planning performs no network action and issues no permits.
