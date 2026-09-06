# M44.5-M46.4 field test

Prerequisite: the M42.5-M44.4 physical adaptive assessment has already completed successfully and the qualification evidence for security-tools, Playwright, and ZAP remains valid for the exact current image digests.

Run normal validation first:

```powershell
ruff check . --fix
black .
ruff check .
pytest
.\scripts\validate.ps1 -CheckOnly
.\scripts\field-tests\m44.5-m46.4.ps1
```

Then evaluate the persisted physical evidence without starting the local lab:

```powershell
.\scripts\runtime-qualification\qualification-status.ps1 -Runtime all
.\scripts\runtime-qualification\full-pentest-readiness.ps1
```

The readiness evaluator performs no container or network execution. A successful result must print `FULL_PENTEST_READY: TRUE` and persist an immutable report under `.astp/readiness/`.

If it prints false, do not override the result. The `blocking_requirements` list is the work queue for the remaining gate(s). Re-run only the specific physical qualification needed to repair stale or missing evidence, then evaluate again.

Do not point qualification scripts at a public bug-bounty target. Qualification remains confined to the isolated ASTP local lab.
