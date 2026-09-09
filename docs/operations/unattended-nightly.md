# Unattended nightly operations

Current safe usage is a zero-network orchestration dry run:

```powershell
python -m astp.cli orchestrator-start --campaign-id nightly-plan --all-ready
python -m astp.cli orchestrator-status nightly-plan
python -m astp.cli orchestrator-report nightly-plan
python -m astp.cli verify-orchestrator-campaign .\.astp\orchestrator\nightly-plan
```

`--execute` is rejected until external detector runtimes are physically built, digest-pinned and field-qualified. Consequently this release must not be described as full zero-touch field-ready.
