# M42.5-M44.4 field test

## Offline regression

Run:

```powershell
.\scripts\field-tests\m42.5-m44.4.ps1
```

Expected: tests pass; no container/network execution.

## Explicit physical local-lab run

Prerequisites: the isolated qualification lab is running, Playwright and ZAP qualification images exist, and `ASTP_PERMIT_KEY` is set.

```powershell
.\scripts\runtime-qualification\run-physical-adaptive-assessment.ps1
```

Expected properties:
- two network actions are performed only against `astp-qualification-lab`;
- observation and verification use distinct permits;
- evidence IDs are distinct;
- trace is persisted under `.astp/qualification/evidence/adaptive-assessment/`;
- trace is registered in the evidence manifest;
- state-changing execution without exact approval remains zero-launch/zero-I/O;
- no vulnerability finding is fabricated when the local lab provides no vulnerability proof.
