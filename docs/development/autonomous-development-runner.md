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
For operator-authorized M1–M8, a validation pass advances atomically to the
next milestone. M8 advances only to `M9 / HUMAN_GATE` with reason
`PRE_PUSH_REVIEW_REQUIRED`; later scheduler wakes are no-ops.

## CLI and result protocol

The verified independent CLI is `codex-cli 0.154.0` at
`C:\Program Files\nodejs\codex.cmd`; the inaccessible WindowsApps executable is
not used. Execution uses stdin, explicit cwd, captured stdout/stderr/exit,
timeout, and stateless ephemeral sessions. In this CLI version the approval
option is global and therefore precedes `exec`; a regression test protects this
ordering.

Exactly one final marker is accepted:

`ASTP_AUTODEV_RESULT=MILESTONE_COMPLETE|CONTINUE|USAGE_LIMIT|HUMAN_GATE|BLOCKED|FAILED`

Missing, duplicate, unknown, or ordinary success markers paired with nonzero
exit fail closed. No trustworthy reset timestamp is exposed, so usage limits
set `resume_after` to null. The scheduler may try once on its next hourly wake;
there is no polling loop.

Only stdout is the authoritative result channel. Diagnostic stderr may contain
an echoed prompt or transcript and cannot supply, duplicate, or spoof a result
marker. `CONTINUE` with exit zero returns to `READY` on the same milestone and
preserves partial work. `FAILED` remains blocked because V1 has no structured
safe-repair subtype; ambiguity fails closed.

Structured V1.2 results may add one `ASTP_AUTODEV_REASON=<STABLE_CODE>` and one
`ASTP_AUTODEV_RESUMABLE=true|false` line. Only explicitly allowlisted local
repair reasons can return a structured `BLOCKED` result to `READY`; missing,
unknown, duplicate, malformed, human, safety, policy, Git-integrity, and network
reasons remain stopped. The runner fingerprints the tracked binary Git diff,
path set, baseline HEAD, milestone, and producing run in ignored
`owned-work.json`. A later wake resumes only an exact match; new tracked changes
or HEAD divergence block. Untracked files are never adopted or modified.

## Scheduler and verification

The installer refuses replacement, enforces at least one hour, prevents
overlap, uses limited privileges, and immediately disables the named task.
Installation never authorizes enabling. Inspect with `status.ps1`; remove only
`ASTP-Autonomous-Development` with `remove-task.ps1`.
Use `run.ps1 -ValidateEnvironmentOnly` to verify the repository, Git, venv,
fixed Codex path, runtime write access, and lock lifecycle without invoking a
model.

Unit tests cover state, transitions, locks, recovery, redaction, protocol,
terminal behavior, HEAD divergence, safety flags, and scheduler policy.
`acceptance.py` runs CASE 1–10 with fake Codex and temporary local Git repos.
Finish with `scripts/validate.ps1`, `git diff --check`, and tree review. No real
scheduler, external target, push, or deploy is required.

## Continuous sessions

V1.3 treats Task Scheduler as an hourly wake/recovery mechanism. One process
holds `session.lock` and invokes successive ephemeral Codex iterations after
meaningful `CONTINUE` progress or a validated milestone advance. Defaults are
285 minutes, 64 invocations, and three consecutive no-progress results. The
progress fingerprint covers Git HEAD, milestone, owned tracked paths/diff, and
NEXT_TASK content; logs and timestamps do not count. Usage limit, human gate,
unsafe result, M9, ownership/HEAD failure, no-progress, or a session ceiling
ends the loop. Recoverable BLOCKED exits for the scheduler rather than spinning.
