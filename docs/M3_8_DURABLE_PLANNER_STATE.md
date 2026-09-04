# M3.8 — Durable Planner State

Adds SQLite-backed planner lifecycle state with explicit transitions and retry accounting.

## Invariant

`Planner -> Policy -> Execution Permit -> Adapter/Worker -> Evidence` remains mandatory.
