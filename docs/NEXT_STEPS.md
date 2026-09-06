# Next steps

M44.5-M46.4 closes the strict ASTP v1 technical readiness gate. Apply the overlay, run the normal validation, then run `qualification-status.ps1 -Runtime all` and `full-pentest-readiness.ps1`.

If the evaluator returns `full_pentest_ready=false`, its blocking requirements are authoritative; do not manually override them. If it returns true, ASTP may be treated as technically ready for one explicitly authorized engagement under a current compiled policy, fresh runtime attestation, bounded budgets, and permit-gated execution.

After the readiness gate is physically satisfied, the next major feature should be Bug Bounty Portfolio Orchestration: platform/catalog connectors, current policy snapshots, conservative scope compilation, per-program execution eligibility, isolated engagement state/evidence, bounded unattended scheduling, completion/stop semantics, and one operator-reviewable report package per program.

Discovered never means authorized. Authorization never means every action is permitted. Every network action must still pass policy and consume a fresh execution permit.
