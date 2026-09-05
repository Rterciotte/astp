# ASTP M12.7-M14.4 — Authenticated Execution and Completion Controls

This block extends the permit-first execution model into authenticated HTTP observation and adds the control-plane structures needed for the remaining full-pentest gaps.

## Milestones

- M12.7 — Origin-bound authentication session profiles.
- M12.8 — Runtime-only secret resolution with redacted representations.
- M12.9 — Authentication injection at the transport boundary.
- M13.0 — Permit-gated authenticated HTTP observation entry point.
- M13.1 — Two-identity authorization differential plans.
- M13.2 — Browser observation worker contract.
- M13.3 — Bounded external adapter contracts.
- M13.4 — Reviewed verification execution envelope.
- M13.5 — Exact-action high-risk approval artifact.
- M13.6 — Durable assessment run state.
- M13.7 — Retest requests bound to current policy/attestation/permit requirements.
- M13.8 — Assessment coverage model.
- M13.9 — Maximum end-to-end assessment planning surface.
- M14.0 — Authenticated-session readiness promoted to implemented.
- M14.1 — Explicit pentest completion assessment.
- M14.2 — CLI surfaces for coverage, review, retest, and completion.
- M14.3 — Authenticated HTTP CLI execution path using the existing permit worker.
- M14.4 — Regression and offline field harness.

## Security invariants

Raw credentials remain outside persisted plans/evidence. Secret references are origin- and identity-bound, credentials are resolved only at execution time, redirects are not granted new authority, and authenticated requests still require the same signed execution permit lifecycle as unauthenticated HTTP observations.

Browser and external-tool capabilities remain contracts only and are not marked runtime-ready. State-changing or intrusive actions remain human-reviewed and are never automatically enabled by an approval artifact.
