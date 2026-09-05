# M4.7 — Controlled Autonomous Observation Loop

The loop consumes only an existing `WorkQueue`. It does not invent target actions. Before every action it verifies the policy snapshot, operational status, per-origin budget, and atomic session budget. The injected executor boundary is responsible for obtaining a fresh permit and invoking a compatible worker.

The CLI implementation requires `--execute` and uses the existing Permit Broker plus `observe_http`. Redirects are still never followed automatically.
