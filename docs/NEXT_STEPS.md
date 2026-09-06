# ASTP completion plan

Current repository line: M48.0 acceptance gate implementation.

ASTP's core policy-first pentest engine is broad and already field-proven for bounded HTTP observation. M46.8–M46.9 close the immediate JavaScript artifact-consumer gap, M47.0 replaces the temporary overlay README with an operator guide, and M47.1 begins CTF mode with rules/artifact intake.

## Milestones to complete the intended ASTP product

### M47.2–M47.5 — COMPLETE

The unified stored-evidence assessment, generalized offline evidence consumers, conservative finding synthesis, and final verified assessment packaging are now exposed through the main CLI. See `docs/release/M47.2.md` through `M47.5.md`.

### M47.6–M47.8 — COMPLETE

Multi-program isolation/fair planning, permit-gated authenticated observation through secret references, and the active-verifier planning integration are now exposed through the main CLI. See `docs/release/M47.6.md` through `M47.8.md`.

### M47.9 — COMPLETE

Recovery acceptance now exercises the important interruption boundaries, rejects tampered checkpoints, requires replanning on policy drift, and forbids blind network replay. See `docs/release/M47.9.md`.

### M48.0 — ACCEPTANCE GATE READY

The complete Bug Bounty v1 chain can now be verified offline with `bug-bounty-v1-acceptance`. The gate requires reviewed-program provenance, engagement/registry binding, stored evidence, a non-empty valid evidence manifest, a valid audit chain, a valid final package, matching network/permit accounting, and at least one recorded authorized field action.

M48.0 is **not field-accepted merely because the command exists**. Run the gate against a real authorized assessment and record the PASS result before declaring Bug Bounty v1 field acceptance. See `docs/release/M48.0.md`.

### M48.1 — CTF artifact classifier and hypothesis graph
Classify local challenge artifacts and create category-specific hypotheses. No unrestricted shell and no implicit network.

### M48.2 — CTF isolated solver adapters
Add bounded local adapters for safe static/reversible operations first (encoding/crypto helpers, file metadata, strings, archive inspection, static binary metadata) with structured receipts.

### M48.3 — CTF web/API permit path
Allow challenge-network experiments only for explicitly declared endpoints, exact actions, bounded budgets, and permits. Competition rules remain a hard gate.

### M48.4 — CTF flag candidate verification and solve trace
Validate candidates against declared flag formats, bind candidates to evidence, and generate a reproducible hypothesis/action trace.

### M48.5 — CTF category expansion
Add reverse, forensics, crypto, web/API, and selected sandboxed pwn capabilities incrementally with per-family qualification suites.

### M48.6 — CTF acceptance suite
Evaluate on local synthetic and retired/public challenges where automation is permitted. Track solve rate, false flags, time, resource cost, and reproducibility.

### M49.0 — ASTP 1.0 release candidate
Consolidate CLI UX, configuration, installation, migration notes, security model, examples, release documentation, and full acceptance suites. Remove stale overlay-era documentation from the primary user path while preserving historical release records.

## Priority

The Bug Bounty v1 implementation path is now at its final field-acceptance gate. After one real `bug-bounty-v1-acceptance` PASS, the remaining implementation focus is M48.1–M48.6 CTF expansion and M49.0 release-candidate consolidation.
