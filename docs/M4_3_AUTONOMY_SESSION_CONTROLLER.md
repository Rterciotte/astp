# M4.3 — Autonomy Session Controller

Prepares bounded work for future autonomous execution while keeping execution disabled and each action permit-gated.

## Invariant

`Planner -> Policy -> Execution Permit -> Adapter/Worker -> Evidence` remains mandatory.
