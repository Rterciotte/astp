# Release notes — M11.1 to M12.6

This block moves ASTP from HTTP-only execution toward a multi-capability, policy-first
observation runtime while preserving the execution invariant.

## Milestones

- **M11.1** Canonical `CapabilityAction` and deterministic action IDs.
- **M11.2** Exact signed `CapabilityGrant` bound to an existing execution permit.
- **M11.3** Underlying permit verification before capability-grant issuance.
- **M11.4** Permit replay prevention before DNS/TLS network I/O.
- **M11.5** Permit-gated DNS observation worker with typed evidence.
- **M11.6** Permit-gated TLS handshake worker with typed evidence.
- **M11.7** Capability dispatcher constrained to registered DNS/TLS operations.
- **M11.8** Evidence-manifest registration for capability observations.
- **M11.9** Explicit CLI execution opt-in (`--execute`) for one exact action.
- **M12.0** `ExecutionIntent` model for control-plane to worker handoff.
- **M12.1** Bounded `AssessmentExecutionPlan` with disabled-by-default execution.
- **M12.2** Safe autonomous assessment profile and capability ceiling.
- **M12.3** Conservative initial DNS/TLS/HTTP surface planner.
- **M12.4** Machine-readable pentest readiness model.
- **M12.5** CLI commands for action/grant/plan/readiness workflows.
- **M12.6** Offline field harness and regression coverage.

## Safety boundary

No exploit payload, brute-force, credential attack, state-changing HTTP method, or
intrusive verifier is added by this block. DNS/TLS workers require both a valid policy
permit and an exact capability grant, and the permit is consumed before network I/O.
