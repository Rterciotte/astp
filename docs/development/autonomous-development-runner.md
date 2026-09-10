# Autonomous Development Runner V1

## Boundary

The runner advances one explicitly authorized local-development milestone at a
time and is separate from ASTP scanning. M1–M8 and all M53 work remain
unauthorized placeholders; M9 requires a human gate. Real targets, push,
deploy, tags, credential acquisition, scope expansion, and weakening policy,
permit, lease, provenance, semantic review, counting proxy, or budgets are
permanently disallowed.

## Durability and recovery

Versioned code is under `scripts/autonomous-dev/`; ignored runtime is under
`.astp/autonomous-dev/`. State is atomically replaced, history is append-only,
and per-run logs are redacted. A directory lock records PID plus process-start
identity. Live ownership rejects overlap; stale ownership is conservatively
recovered. Orphaned `RUNNING` passes through `RECOVERING` to `READY` without a
completion claim.

Persisted and current Git HEAD must match before invocation. Codex completion
is provisional: validation runs outside Codex, and only a pass records the
resulting HEAD and `COMPLETE`. Failure returns to `READY` for repair.

## CLI and result protocol

The verified independent CLI is `codex-cli 0.154.0` at
`C:\Program Files\nodejs\codex.cmd`; the inaccessible WindowsApps executable is
not used. Execution uses stdin, explicit cwd, captured stdout/stderr/exit,
timeout, and stateless ephemeral sessions.

Exactly one final marker is accepted:

`ASTP_AUTODEV_RESULT=MILESTONE_COMPLETE|CONTINUE|USAGE_LIMIT|HUMAN_GATE|BLOCKED|FAILED`

Missing, duplicate, unknown, or ordinary success markers paired with nonzero
exit fail closed. No trustworthy reset timestamp is exposed, so usage limits
set `resume_after` to null. The scheduler may try once on its next hourly wake;
there is no polling loop.

## Scheduler and verification

The installer refuses replacement, enforces at least one hour, prevents
overlap, uses limited privileges, and immediately disables the named task.
Installation never authorizes enabling. Inspect with `status.ps1`; remove only
`ASTP-Autonomous-Development` with `remove-task.ps1`.

Unit tests cover state, transitions, locks, recovery, redaction, protocol,
terminal behavior, HEAD divergence, safety flags, and scheduler policy.
`acceptance.py` runs CASE 1–10 with fake Codex and temporary local Git repos.
Finish with `scripts/validate.ps1`, `git diff --check`, and tree review. No real
scheduler, external target, push, or deploy is required.
