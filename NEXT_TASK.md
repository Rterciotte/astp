# ASTP master completion continuation

Authoritative completed local checkpoints:

- M1 `cdc1a99` — real durable operational lease lifecycle.
- M1 closure `ab0e702` — detector execution requires real lease authority and
  an upstream signed permit for program-bound engagements.
- M2 `2c9dc0d` — fake intake through physical worker/proxy/local-lab execution.

M2 validation: Ruff/Black/compile/CLI PASS; pytest 782 passed. Physical ledger:
attempted=1, forwarded=1, responses=1, evidence=1, proof=reproduced. No external
target traffic, push, deploy, or tag.

Current milestone: M3, not complete. Root cause confirmed in
`src/astp/m53_chaos.py`: `_physical_request` writes `ProxyAccounting` manually
and opens a direct socket, while worker scenarios use sleeping containers and
auxiliary requests. This is the forbidden false-pass described by the master
prompt.

Next exact implementation step: add acceptance-only typed lifecycle fault hooks
to `DockerDetectorAdapter` around worker launch, first proxy I/O/result ledger,
evidence normalization, and persistence. Run each I/O-bearing chaos case using
the actual pinned worker -> qualified counting proxy -> isolated
`astp-m52-lab` chain. Recovery must read only the proxy ledger and durable run
artifacts; remove `_physical_request` and all manual accounting. Add regression
tests proving no direct socket path, no auxiliary request, UNKNOWN_OUTCOME/no
blind replay, fresh permit on safe retry, orphan cleanup, and idempotent report
reconstruction. Then full validation and local M3 commit.

Local Docker state available for M3: daemon running, network `astp-m2-local`,
container `astp-m52-lab`, qualified worker/proxy images present. These are local
synthetic resources only.
