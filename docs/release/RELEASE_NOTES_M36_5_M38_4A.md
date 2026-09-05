# M36.5-M38.4a — Permit-gated physical qualification patch

This patch closes the operational gap between the local qualification lab and the physical worker boundary.

Changes:

- replaces the boolean `permit_consumed` network gate with a typed, exact-bound `PermitConsumptionProof`;
- adds a first executable local qualification runner for `security-tools.isolated.v1`;
- re-authorizes through the permit broker immediately before execution;
- consumes the signed permit exactly once before Docker network I/O;
- binds permit, engagement, action, target and worker request before enabling the fixed internal Docker network;
- stores command/output artifacts and a normalized worker receipt in the Evidence Store;
- appends qualification journal events;
- keeps the first field run limited to the ASTP-owned local Docker lab.

This patch does **not** mark any runtime fully field-qualified by itself. The observed run must pass and its evidence must be reviewed before readiness state changes.
