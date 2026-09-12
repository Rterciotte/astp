# M53 M1-M5 pre-push audit

Audit boundary: `f0a8e24..a1f2241`, plus the M7 remediation in the current
checkpoint. This is a local-only audit; it did not push, deploy, tag, contact a
real target, or install network dependencies.

## Methods

- reviewed all 33 changed files and the 3,281-line net implementation delta;
- traced program binding through intake, policy, semantic review, operational
  attestation, durable lease, execution permit and detector-run permit;
- traced retries from scheduler eligibility through fresh run/permit creation;
- searched production changes for alternate network paths, external URLs,
  shell execution, embedded credentials, synthetic lease callbacks and
  hardcoded acceptance values;
- reconciled the M5 physical report against detector results, proxy SQLite
  ledgers, scheduler state, lease store, revision invalidation artifact and
  Docker lifecycle state;
- ran `pip check`, `git fsck --no-dangling`, Ruff, Black, compilation, pytest
  and the CLI smoke test. Optional third-party audit packages were not present,
  so no dependency vulnerability claim is made beyond local package integrity.

## Finding and remediation

### HIGH-01 — reachable legacy local physical executor

The non-accelerated `local-bughunt --execute` CLI branch still routed to
`run_m53_pass1_execution`. That retired harness used a synthetic lease callback
and predated the real program-bound upstream permit chain. The environment gate
limited it to local acceptance, but it remained an alternate physical execution
route and therefore violated the single-authority invariant.

M7 remediation fails closed in both layers:

- CLI local physical execution now requires `--accelerated-night` before any
  campaign or Docker work begins;
- direct calls to the legacy pass1 entry point fail immediately without writing
  campaign state or invoking an adapter;
- regression tests prove both boundaries.

## Residual classification

- CRITICAL: 0
- HIGH: 0 after M7 remediation
- MEDIUM: 0
- LOW: 1 — the unreachable retired implementation remains temporarily in
  `m53_pass1.py` because shared report/chaos types still live in that module.
  Both its public and migration-reference entry points fail closed. Moving the
  shared types and deleting the dead body is cleanup, not a release blocker.

Audit result: `M53_PRE_PUSH_AUDIT_PASS`.
