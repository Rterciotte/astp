# M46.5 Field Test — Smart Fit Pre-flight

After applying the overlay, reload the unpacked ASTP browser companion extension so Chrome uses the updated capture code.

Run:

```powershell
ruff check . --fix
black .
ruff check .
pytest
.\scripts\validate.ps1 -CheckOnly
.\scripts\field-tests\m46.5.ps1

.\scripts\programs\run-program-preflight.ps1 `
  -ProgramId bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5
```

When the command prints the intake token:

1. paste it into the ASTP browser companion;
2. open the authenticated Smart Fit BugHunt program detail page requested by the command;
3. click **Capture current page** once.

Expected safe outcomes are either `EXECUTION_ELIGIBLE: TRUE`, or a concrete fail-closed blocker such as security-relevant policy drift, unresolved policy review, stale capture, unknown/offline operational status, or failed full-pentest readiness.

Do not begin the Smart Fit assessment until this pre-flight returns `EXECUTION_ELIGIBLE: TRUE`.
