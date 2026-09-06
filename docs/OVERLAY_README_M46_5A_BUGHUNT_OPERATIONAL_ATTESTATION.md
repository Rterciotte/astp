# ASTP M46.5a — BugHunt operational attestation fix

Apply over the validated M46.5 tree.

## Why

The first live Smart Fit pre-flight captured the current program page and current policy successfully, but BugHunt did not expose a literal ONLINE/OFFLINE badge in the captured DOM. M46.5 therefore correctly returned `operational_status=unknown` and blocked execution.

M46.5a adds bounded provider-aware evidence capture without treating ordinary policy text as runtime state.

## BugHunt ONLINE rule

ASTP may attest ONLINE from the authenticated BugHunt program-detail page only when all of the following are true:

1. the URL is a BugHunt `/program/detail` page;
2. a `Submeter Relatório` / `Submit Report` control is visible and enabled;
3. the page contains the BugHunt `Publicado há ...` publication marker;
4. no explicit structured OFFLINE or short visible offline/paused/closed banner was captured.

Explicit OFFLINE evidence overrides every positive affordance.

This rule is intentionally platform-specific and is not generalized to arbitrary sites.

## Validation

```powershell
ruff check . --fix
black .
ruff check .
pytest
.\scripts\validate.ps1 -CheckOnly
.\scripts\field-tests\m46.5a.ps1
```

Then reload the unpacked ASTP browser extension in Chrome and rerun the same live pre-flight command:

```powershell
.\scripts\programs\run-program-preflight.ps1 `
  -ProgramId bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5
```

Do not proceed to real assessment execution unless the live run returns `EXECUTION_ELIGIBLE: TRUE`.
