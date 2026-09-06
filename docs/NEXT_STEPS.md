# ASTP completion plan

Current repository line: M47.5 completion push.

ASTP's core policy-first pentest engine is broad and already field-proven for bounded HTTP observation. M46.8–M46.9 close the immediate JavaScript artifact-consumer gap, M47.0 replaces the temporary overlay README with an operator guide, and M47.1 begins CTF mode with rules/artifact intake.

## Milestones to complete the intended ASTP product

### M47.2–M47.5 — COMPLETE

The unified stored-evidence assessment, generalized offline evidence consumers, conservative finding synthesis, and final verified assessment packaging are now exposed through the main CLI. See `docs/release/M47.2.md` through `M47.5.md`.

### M47.6 — Bug bounty portfolio orchestrator
Generalize program preflight across multiple programs with independent scope, policy digest, freshness, rate budget, queue fairness, evidence chain, and stop conditions.

### M47.7 — Authenticated/browser observation integration
Finish the operator-safe path for authorized authenticated observations while keeping browser sessions/secrets out of normal evidence and preserving exact action authorization.

### M47.8 — Active verifier integration pass
Expose the already-built verifier families through a coherent planner/dispatcher workflow, validate capability contracts, and ensure state-changing families remain explicitly operator-gated.

### M47.9 — Recovery, resume, and crash acceptance
Exercise interruption at each important boundary: before permit, after permit, after consumption, during worker failure, after evidence write, and during report assembly. Prove fail-closed resume behavior.

### M48.0 — Bug bounty v1 acceptance
Run a complete authorized assessment from program intake through final report using the unified workflow. Require clean audit/evidence verification and document the field acceptance in `docs/release/`.

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

The shortest path to a useful release is now M47.6 through M48.0. CTF expansion can proceed after bug bounty v1 acceptance without blocking the primary pentest workflow.
