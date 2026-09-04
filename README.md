# ASTP — Autonomous Security Testing Platform

ASTP is a policy-first foundation for authorized security testing automation. Milestone 1.4 adds
single-use permit consumption, revocation, key rotation IDs, and a tamper-evident local audit chain.
No scanner, HTTP request engine, or offensive execution is implemented yet.

## Windows quick start

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
ruff check . --fix
black .
pytest
```

## Permit secret — existing setup still works

```powershell
$env:ASTP_PERMIT_KEY = [Environment]::GetEnvironmentVariable(
    "ASTP_PERMIT_KEY",
    "User"
)
```

Optionally identify this key explicitly:

```powershell
$env:ASTP_PERMIT_ACTIVE_KEY_ID = "local-v1"
```

See `docs/PERMIT_LIFECYCLE.md` before rotating keys.

## Issue a permit

```powershell
astp issue-permit `
    .\examples\engagement-granular.yaml `
    .\examples\test-idor.yaml `
    --target https://api.example.com/v1/users/123 `
    --context authenticated_identity `
    --context foreign_object_identifier `
    --http-method GET `
    --identity researcher `
    --rps 1 `
    --output .\examples\execution-permit.yaml
```

Issuance reruns authorization internally and records `permit.issued` in `.astp/audit.jsonl`.

## Verify without consuming

```powershell
astp verify-permit `
    .\examples\execution-permit.yaml `
    .\examples\engagement-granular.yaml `
    .\examples\test-idor.yaml `
    --target https://api.example.com/v1/users/123 `
    --http-method GET `
    --identity researcher `
    --rps 1
```

## Consume exactly once

```powershell
astp consume-permit `
    .\examples\execution-permit.yaml `
    .\examples\engagement-granular.yaml `
    .\examples\test-idor.yaml `
    --target https://api.example.com/v1/users/123 `
    --http-method GET `
    --identity researcher `
    --rps 1
```

The first call should succeed. Repeating it should be rejected as replay. This command still makes
no network request.

## Revoke and audit

```powershell
astp revoke-permit PERMIT_ID --reason "scope changed"
astp permit-status PERMIT_ID
astp verify-audit .\.astp\audit.jsonl
```

Local lifecycle data under `.astp/` is intentionally excluded from Git.

See `docs/PERMIT_LIFECYCLE.md`, `docs/EXECUTION_PERMITS.md`, and `docs/NEXT_STEPS.md`.
