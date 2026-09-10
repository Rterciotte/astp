# ASTP Autonomous Development Runner V1

Local-only resumable engineering runner. Versioned code lives here; durable
state lives in ignored `.astp/autonomous-dev/`. It never authorizes push,
deploy, tags, external pentest traffic, credentials, or policy changes.
`HUMAN_GATE` and `COMPLETE` are terminal no-op states.

```powershell
.\scripts\autonomous-dev\initialize.ps1
.\scripts\autonomous-dev\status.ps1
.\scripts\autonomous-dev\run.ps1
.\.venv\Scripts\python.exe scripts\autonomous-dev\acceptance.py
```

The runner calls independent `C:\Program Files\nodejs\codex.cmd` through
`codex exec -`, an explicit working directory, workspace-write sandbox,
approvals `never`, ephemeral mode, and shell execution disabled. Exactly one
`ASTP_AUTODEV_RESULT=...` marker is required; malformed output fails closed.
Usage limits without a reliable reset timestamp use `WAITING_FOR_RESET` and
`resume_after: null`, with no retry loop.

`install-task.ps1` creates a disabled Windows task with minimum hourly cadence
and overlap prevention. Enabling is always a separate human action.
