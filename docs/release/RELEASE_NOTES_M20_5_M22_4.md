# Release notes — M20.5–M22.4

This block separates runtime contracts from field qualification and adds strict completion gates. It introduces version-pinned runtime specifications, qualification evidence, stage execution budgets, evidence acceptance, verifier-family readiness, planning-only verification batches, coordinator tickets/feedback, recovery checkpoints, and completion-readiness evaluation.

No command in this block performs network I/O. Existing permit-consumed worker boundaries remain unchanged. `full_pentest_ready` must not be inferred from runtime contracts alone.
