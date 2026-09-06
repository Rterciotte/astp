# ASTP M46.5 — Unified Program Pre-flight

Version: 0.461.0

This overlay joins the existing authenticated program intake, normalized policy review, semantic exclusion guardrails, policy drift detection, online/offline attestation, strict full-pentest readiness evaluation, engagement compilation, and immutable pre-flight artifacts into one operational flow.

## One command

```powershell
.\scripts\programs\run-program-preflight.ps1 `
  -ProgramId bughunt-grupo-smart-fit-bug-bounty-p-blico-400f88b1c5
```

The default `live` mode starts the existing loopback-only authenticated intake server and prints a short-lived token. Because BugHunt authentication remains isolated inside the user's browser, the operator performs one credential-preserving gesture: open the requested program detail page and click **Capture current page** in the ASTP browser companion. ASTP then performs every policy/readiness decision automatically.

No BugHunt password, cookie, or session token is copied into ASTP.

## Fail-closed decision

The command returns `EXECUTION_ELIGIBLE: TRUE` only when all of the following are proven from current evidence:

- the authenticated detail capture is fresh;
- the capture URL is exactly bound to the requested catalog program;
- the normalized policy is `READY`;
- no security-relevant policy fingerprint changed since the previous reviewed version;
- a structured DOM status signal proves the program is currently online when the policy requires it;
- the normalized program compiles into an engagement;
- the strict `FULL_PENTEST_READY` gate is still true.

Any ambiguity produces `EXECUTION_ELIGIBLE: FALSE`.

## Policy drift

The source page content hash may change for cosmetic/dynamic reasons. The pre-flight therefore maintains a second execution-relevant policy fingerprint over scope, constraints, excluded finding types, recommended user agent, and blocking issue semantics.

- page changed + security fingerprint unchanged → `non_security_text_only`, allowed to proceed if every other gate passes;
- security fingerprint changed → hard block for review;
- unresolved/new policy issue → hard block.

This prevents a newly expanded scope or changed restriction from silently becoming permission.

## Browser companion status signal

The browser companion now captures an optional `operational_status_hint` only from structured DOM status/badge elements or a `Status | Online/Offline` table row. It deliberately does **not** infer status from ordinary policy prose containing the word "offline".

If no unambiguous structured signal exists, status is `unknown` and execution remains blocked.

## Immutable output

The flow persists hash-named artifacts under:

```text
.astp/preflight/<program-id>/
├── artifacts/
│   ├── engagement-<sha256>.yaml
│   └── operational-attestation-<sha256>.yaml
└── preflight-<sha256>.json
```

This milestone performs no assessment against the target. It only determines whether the program is currently eligible to enter the existing execution engine.
