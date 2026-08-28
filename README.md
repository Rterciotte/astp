# ASTP — Autonomous Security Testing Platform

ASTP is a policy-first foundation for authorized security testing automation. Milestone 1.3 adds
short-lived signed execution permits between authorization and future workers. No scanner, HTTP
request engine, or offensive execution is implemented yet.

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

## Granular authorization

```powershell
astp authorize-test `
    .\examples\engagement-granular.yaml `
    .\examples\test-idor.yaml `
    --target https://api.example.com/v1/users/123 `
    --context authenticated_identity `
    --context foreign_object_identifier `
    --http-method GET `
    --identity researcher `
    --rps 1
```

## Issue a signed execution permit

Use a development key with at least 32 bytes. Do not pass the key as a CLI argument because shell
history would retain it.

```powershell
$env:ASTP_PERMIT_KEY = "replace-with-a-local-secret-at-least-32-bytes"

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

Permit issuance reruns the policy engine internally. A caller cannot mint a permit by merely
supplying a fabricated `ALLOW` result.

## Verify the permit

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

The permit fails verification if its signature, validity window, engagement/test policy digest,
target, method, identity, or request rate does not match.

See `docs/EXECUTION_PERMITS.md` for the trust model and `docs/NEXT_STEPS.md` for the roadmap.
