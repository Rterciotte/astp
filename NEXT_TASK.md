# ASTP master completion continuation

Authoritative completed local checkpoints:

- M1 `cdc1a99` — real durable operational lease lifecycle.
- M1 closure `ab0e702` — detector execution requires real lease authority and
  an upstream signed permit for program-bound engagements.
- M2 `2c9dc0d` — fake intake through physical worker/proxy/local-lab execution.

M2 validation: Ruff/Black/compile/CLI PASS; pytest 782 passed. Physical ledger:
attempted=1, forwarded=1, responses=1, evidence=1, proof=reproduced. No external
target traffic, push, deploy, or tag.

M3 implementation and physical acceptance are complete, pending only the local
checkpoint commit. Marker: `M53_HIGH_3_PHYSICAL_CHAOS_PASS`. The eight-point
matrix passed 8/8 against the isolated lab with nine unique permits, zero reuse,
two safe retries with fresh permits, six forwarded requests, four responses,
two UNKNOWN outcomes, durable proof/evidence reconstruction, manifest PASS,
no blind replay, no direct worker target-network attachment and zero orphans.
Qualified overlay counting-proxy digest:
`sha256:c02a0835e263aae276ce6a05efc6a1cbbd835748f31765049ef1dc11c3bcf6d3`.

M3 commit: `ac4c387`.

M4 implementation, physical acceptance and full validation are complete,
pending the local checkpoint commit. Marker:
`M53_HIGH_4_SCHEDULER_NIGHT_PASS`. The scheduler directly controlled nine
physical dispatches across T+0/T+2/T+5/T+8. Each dispatch used a program-bound
real lease and upstream signed permit. H's target 429/Retry-After survived the
process restart and retried only in round 2; G likewise received a fresh
run/permit/lease after its physical failure; F launched only after revision
replan. Nine unique run IDs and detector permits, zero reuse/blind replay,
derived D exhaustion, derived deadline drain, manifest PASS and zero orphans.
Full validation: 798 passed. Qualified local proxy digest:
`sha256:b7e6656eab2b2902b9c2a1553fe74f28418e4347343af832091d8ffcb80fbea7`.

Next exact action after the M4 commit: start M5 complete local A–H acceptance
using only the M1–M4 authorization, lease, scheduler, worker, proxy, evidence
and recovery paths. Produce the required per-program fields and independent
global invariants; do not restore the legacy pass1 retry executor.

Local Docker state available for M3: daemon running, network `astp-m2-local`,
container `astp-m52-lab`, qualified worker/proxy images present. These are local
synthetic resources only.
