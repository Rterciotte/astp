# ASTP M44.5-M46.4 — Full Pentest Readiness Closure

Version 0.451.0.

This overlay does not simply flip a boolean. It adds a fail-closed readiness evaluator that can set `full_pentest_ready=true` only when previously persisted physical evidence proves the required runtime and adaptive-assessment gates.

The evaluator requires all three isolated runtimes to remain physically qualified against their exact current image digests, the evidence manifest to validate with artifact hashes, a valid immutable physical adaptive trace, distinct fresh permits and evidence across physical stages, physical local-lab I/O, state-changing zero-launch without approval, policy-drift/stale-attestation/permit-reuse/cross-target hard stops, bounded unattended completion semantics, and separation between report readiness and operator-reviewed closure.

The readiness command performs no network I/O and launches no containers. It consumes the physical evidence already created by the qualification and adaptive local-lab runs.

`full_pentest_ready=true` means the ASTP v1 execution engine has satisfied its strict technical readiness gate for an explicitly authorized engagement. It does **not** mean that arbitrary public targets may be tested, that every vulnerability class is supported, or that bug-bounty program discovery implies authorization.
