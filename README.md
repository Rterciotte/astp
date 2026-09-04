# ASTP — Autonomous Security Testing Platform

ASTP is a policy-first platform for authorized security testing automation. Milestones 0 through 1.4
established conservative scope compilation, granular authorization, bounded approvals, signed
single-use execution permits, revocation, key rotation IDs, and a tamper-evident local audit chain.

**Milestone 2 added the first real network-capable component:** a tightly bounded HTTP observation
worker that can perform exactly one permit-gated `GET` or `HEAD` request and persist redacted,
hash-verifiable evidence.

**Milestone 2.1 hardens that worker** with canonical action IDs, durable per-target rate state, explicit evidence IDs and sensitivity labels, and a hash-linked evidence manifest that can verify both its own chain and artifact hashes.

It is not a scanner and does not perform exploitation, fuzzing, crawling, credential attacks, state
changes, arbitrary shell execution, or unrestricted autonomous networking.

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

The project config uses `.pytest-tmp` as pytest's base temp directory to avoid Windows `%TEMP%`
permission problems observed during M1.4 validation.

## Permit key

Your existing local configuration continues to work:

```powershell
$env:ASTP_PERMIT_KEY = [Environment]::GetEnvironmentVariable(
    "ASTP_PERMIT_KEY",
    "User"
)
```

Optionally identify the key explicitly:

```powershell
$env:ASTP_PERMIT_ACTIVE_KEY_ID = "local-v1"
```

See `docs/PERMIT_LIFECYCLE.md` before rotating keys.

## Safe local M2 demonstration

Use the included loopback-only HTTP server so the first network test does not touch an external
system.

Terminal 1:

```powershell
python .\examples\observation_server.py
```

It listens on:

```text
http://127.0.0.1:8765
```

Terminal 2 — issue a permit bound to one exact GET:

```powershell
astp issue-permit `
    .\examples\engagement-observation-local.yaml `
    .\examples\test-observation.yaml `
    --target http://127.0.0.1:8765/ `
    --http-method GET `
    --rps 1 `
    --output .\examples\observation-permit.yaml
```

Then execute the observation:

```powershell
astp observe-http `
    .\examples\observation-permit.yaml `
    .\examples\engagement-observation-local.yaml `
    .\examples\test-observation.yaml `
    --target http://127.0.0.1:8765/ `
    --http-method GET `
    --rps 1
```

Expected high-level result:

```text
status: 200
permit consumed: YES
evidence: .astp/evidence/<permit-id>.json
network execution: observation-only GET/HEAD
```

Run the exact same `observe-http` command again and replay protection should reject it before a
second network request is made.

## Verify evidence, manifest, and audit

M2.1 writes `.astp/evidence-manifest.jsonl` and `.astp/rate-state.json` by default.
The manifest is append-only and hash-linked; each entry also stores the SHA-256 of its artifact.


```powershell
astp verify-evidence .\.astp\evidence\PERMIT_ID.json
astp verify-evidence-manifest .\.astp\evidence-manifest.jsonl
astp verify-audit .\.astp\audit.jsonl
```

All should report `YES` for untampered data.

## Redirect behavior

Milestone 2 follows **zero redirects**. A `3xx` `Location` is recorded, resolved, redacted, and
classified as in-scope or out-of-scope, but no second request is sent. This deliberately prevents
redirect-driven scope escape.

To test this safely, issue a separate permit for:

```text
http://127.0.0.1:8765/redirect
```

The local server returns an external redirect, which ASTP records but never follows.

## Existing permit lifecycle commands

```powershell
astp verify-permit ...
astp consume-permit ...
astp revoke-permit PERMIT_ID --reason "scope changed"
astp permit-status PERMIT_ID
astp verify-audit .\.astp\audit.jsonl
```

Local lifecycle/evidence data under `.astp/` is intentionally excluded from Git.

See `docs/M2_1_HARDENING.md`, `docs/CTF_MODE_ROADMAP.md`, `docs/HTTP_OBSERVATION_WORKER.md`, `docs/PERMIT_LIFECYCLE.md`,
`docs/EXECUTION_PERMITS.md`, and `docs/NEXT_STEPS.md`.
