# M4.7–M5.8 Field Test — Smart Fit

Run the normal quality suite first:

```powershell
ruff check . --fix
black .
ruff check .
pytest
```

The expected test count for this overlay is 148 before any formatter-only changes.

## Control-plane checks — zero network requests

```powershell
astp snapshot-policy `
  .\engagements\smartfit.yaml `
  .\examples\test-observation.yaml `
  --output .\.astp\smartfit-policy-snapshot.yaml

astp init-session-ledger smartfit-m56 `
  --ledger-db .\.astp\session-ledger.db

astp build-frontier `
  .\.astp\smartfit-target-registry.yaml `
  --max-depth 2 `
  --output .\.astp\smartfit-frontier.yaml

astp choose-observation-method

astp feedback-evidence `
  .\.astp\smartfit-first-observation.json `
  .\engagements\smartfit.yaml `
  .\.astp\smartfit-target-registry.yaml `
  --no-links `
  --output .\.astp\smartfit-target-registry-feedback.yaml
```

All five commands above must report `Network execution: NOT PERFORMED` where applicable.

## Real bounded observation session

Before this step, confirm on the authenticated BugHunt page that the Smart Fit program is still ONLINE and create a fresh operational attestation.

Use a **new session id** for each field trial so durable budgets are not inherited from an old session.

```powershell
astp run-observation-session `
  .\.astp\smartfit-work-queue.yaml `
  .\engagements\smartfit.yaml `
  .\examples\test-observation.yaml `
  --program-status-attestation .\.astp\smartfit-online.yaml `
  --semantic-clear semex-8a8bf1181d0a `
  --semantic-clear semex-99c27802d859 `
  --semantic-clear semex-999be0c07598 `
  --rps 1 `
  --max-actions 1 `
  --max-requests 1 `
  --max-errors 1 `
  --max-actions-per-origin 1 `
  --session-id smartfit-m56-field-1 `
  --execute
```

For the current one-item Smart Fit queue, the expected behavior is exactly one fresh permit and at most one GET/HEAD request. A stale attestation, policy drift, budget exhaustion, permit denial, replay, rate rejection, or worker failure must stop the session rather than continue.

Then verify:

```powershell
astp verify-execution-trace .\.astp\execution-trace.jsonl

astp session-ledger-status smartfit-m56-field-1 `
  --ledger-db .\.astp\session-ledger.db

astp session-report smartfit-m56-field-1 `
  --ledger-db .\.astp\session-ledger.db `
  --trace .\.astp\execution-trace.jsonl `
  --output .\.astp\smartfit-m56-session-report.yaml
```

Do not use a larger action/request budget in the first field trial.
