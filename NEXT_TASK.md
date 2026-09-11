# ASTP master completion continuation

Authoritative completed local checkpoints:

- M1 `cdc1a99` — real durable operational lease lifecycle.
- M1 closure `ab0e702` — detector execution requires real lease authority and
  an upstream signed permit for program-bound engagements.
- M2 `2c9dc0d` — fake intake through physical worker/proxy/local-lab execution.

M2 validation: Ruff/Black/compile/CLI PASS; pytest 782 passed. Physical ledger:
attempted=1, forwarded=1, responses=1, evidence=1, proof=reproduced. No external
target traffic, push, deploy, or tag.

Current milestone: M3, not complete. The legacy `_physical_request`, direct
socket, manual physical accounting, sleeping worker, and auxiliary requests
have been removed/disabled. Typed local-only lifecycle faults now exist in the
Docker adapter and counting proxy. Five physical boundaries passed against the
isolated lab: before launch 0/0; after launch before I/O 0/0; after first
forward 1/0/UNKNOWN=1; after proxy result 1/1; after normalization 1/1 with
idempotent evidence recovery. Both zero-I/O cases used a fresh detector run ID
and permit on safe retry. No worker/proxy/network orphan remained.

Next exact implementation step: finish the remaining M3 scenarios without
shortcuts: a true worker crash mid-run (named worker + deterministic kill after
the proxy ledger records first forward), process restart/reopen, and report/
proof reconstruction from a completed physical run. Add aggregate physical
reporting and independent Docker/container assertions for direct-network
isolation/orphan cleanup. Re-run proxy qualification for digest
`sha256:359f7b593714ccbe692f16b9127b771cd5d6e272f52037e8e5663aa0b98f0589`,
then full validation and the final M3 commit.

Local Docker state available for M3: daemon running, network `astp-m2-local`,
container `astp-m52-lab`, qualified worker/proxy images present. These are local
synthetic resources only.
