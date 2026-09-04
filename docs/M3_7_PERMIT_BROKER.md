# M3.7 — Permit Broker

Adds an exact-action broker that re-runs authorization before issuing one short-lived signed permit for one work-queue item. It never performs network I/O.

## Invariant

`Planner -> Policy -> Execution Permit -> Adapter/Worker -> Evidence` remains mandatory.
