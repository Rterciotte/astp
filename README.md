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

## Milestone 2.5 — Bug Bounty Program Intake

ASTP can now normalize bug bounty rules into a first-class `BugBountyProgram` before
compiling an executable engagement. The preferred workflow is an explicit capture from a
page already authenticated in the user's browser through the local `browser-companion/`.
No third-party credentials or cookies are required by ASTP.

Key commands:

```powershell
astp browser-intake-server --output .\.astp\browser-capture.json
astp import-program .\.astp\browser-capture.json --browser-capture --name "Program" --platform bughunt -o program.yaml
astp compile-program program.yaml --rps 1 -o engagement.yaml
```

See `docs/M2_5_PROGRAM_INTAKE.md` and `docs/BROWSER_COMPANION.md`.


## Milestone 2.6 — Program Runtime Gates

A reviewed program now compiles into an engagement that preserves its exact source-policy revision,
semantic deny guardrails, reviewed request rate, online-only requirement, recommended User-Agent,
and extracted excluded-finding metadata. Programs that prohibit testing while offline require a
fresh revision-bound operational-status attestation before authorization or permit issuance. Permit
lifetime is capped by the attestation lifetime.

```powershell
astp attest-program-status .\programs\program.yaml --status online --source operator -o .\.astp\program-online.yaml
astp compile-program .\programs\program.yaml -o .\engagements\program.yaml
```

See `docs/M2_6_PROGRAM_RUNTIME_GATES.md`.

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


## Milestone 2.2 — transport hardening

M2.2 introduces an injectable HTTP transport boundary, records DNS endpoint provenance, classifies
DNS/TLS/timeout/connection/I/O failures, and persists structured failure evidence in the hash-linked
evidence manifest. Redirects remain observation-only and are never followed. See
`docs/M2_2_TRANSPORT_HARDENING.md`.


## Milestone 2.3 — worker boundary completion

M2.3 binds network connections to addresses from the worker's own bounded DNS resolution while
preserving hostname-based TLS validation, adds engagement-specific evidence redaction profiles,
records redirects as distinct actions that always require a new permit, and adds portable evidence
bundles with cryptographic receipts. Redirects are still never followed automatically. See
`docs/M2_3_WORKER_BOUNDARY.md`.

Evidence bundles:

```powershell
astp export-evidence-bundle .\.astp\evidence-manifest.jsonl `
  --output .\.astp\evidence-bundle.zip

astp verify-evidence-bundle .\.astp\evidence-bundle.zip
```


## Milestone 2.4 — durable runtime and worker contracts

M2.4 makes `.astp/runtime.db` the default worker-admission state for HTTP observations. Permit replay
state and per-target rate admission are now decided in one SQLite transaction, so a rate-limit
rejection does not consume the permit. The HTTP worker also declares an explicit
`http.observation.v1` capability contract. See `docs/M2_4_DURABLE_RUNTIME.md`.

Runtime lifecycle commands:

```powershell
astp runtime-permit-status PERMIT_ID
astp revoke-runtime-permit PERMIT_ID --reason "scope changed"
```


## Authenticated bug bounty workspace

See `docs/M2_5_1_PROGRAM_DISCOVERY.md`.

### M2.5.2 integration hardening

The authenticated browser intake now exposes a versioned loopback protocol with a health check,
visible operational logs, JSON errors, a separate Chrome host-permission step, and real HTTP
integration tests. See `docs/M2_5_2_PROGRAM_PROTOCOL_FIX.md`.

### M2.5.3 policy review and parser correctness

Authenticated program intake now distinguishes ACTIVE from READY, fixes Portuguese DoS false
positives, deduplicates constraints with multi-source provenance, propagates capture timestamps,
uses the catalog ID as the stable program ID, extracts source-supported finding exclusions, and
adds `astp review-program` for explicit operator review. Broad semantic exclusions remain blocking
until mapped to explicit deny selectors. See `docs/M2_5_3_POLICY_REVIEW.md`.


## M2.5.4 — Semantic Exclusion Guardrails

Broad exclusions such as product families, organization-owned assets, and physical/totem
systems can no longer be marked resolved merely by adding one concrete hostname. Reviewers
record a semantic deny guardrail with `review-program --issue N --semantic-deny KIND=VALUE`.
The guardrail is compiled into the engagement. Authorization and permit issuance then require
an explicit per-target assessment for every semantic exclusion: `--semantic-clear RULE_ID` to
record that the target was reviewed and does not match, or `--semantic-match RULE_ID` to deny
the target. Missing or contradictory assessments produce `INSUFFICIENT_CONTEXT`; ambiguity
never becomes permission.

Example review commands for Smart Fit:

```powershell
astp review-program <PROGRAM_ID> --issue 1 --semantic-deny "product_family=Universidade Smart Fit"
astp review-program <PROGRAM_ID> --issue 2 --semantic-deny "organization_family=ASAP"
astp review-program <PROGRAM_ID> --issue 3 --semantic-deny "asset_family=Smart Fit gym totem systems"
```

## M2.7–M3.6 — Discovery, planning, graph, proof, and reporting control plane

The cumulative v0.23.0 build extends the existing permit-gated observation worker without adding a
network bypass. New capabilities are control-plane only until a separately signed permit reaches the
existing worker boundary.

```text
existing evidence
  -> redirect/link candidates (M2.7/M2.8)
  -> deduplicated target registry (M2.9)
  -> policy-evaluated observation plan (M3.0)
  -> fair multi-program queue (M3.1)
  -> Security Test DSL (M3.2)
  -> security graph (M3.3)
  -> hypothesis graph (M3.4)
  -> proof-state finding correlation (M3.5)
  -> evidence report + retest plan (M3.6)
```

The boundary remains:

```text
candidate/hypothesis/plan/queue -> policy -> fresh signed permit -> worker -> evidence
```

None of the new artifacts contains a reusable execution capability. A plan item may be marked
`authorizable`, but it still contains no permit and cannot cause a network request.

A typical post-observation workflow is:

```powershell
astp discover-targets .\.astp\observation.json .\engagements\program.yaml `
  --output .\.astp\discovery.yaml

astp merge-targets .\.astp\discovery.yaml .\engagements\program.yaml `
  --registry .\.astp\target-registry.yaml

astp plan-observations .\.astp\target-registry.yaml .\engagements\program.yaml `
  .\examples\test-observation.yaml `
  --program-status-attestation .\.astp\program-online.yaml `
  --rps 1 --output .\.astp\plan.yaml

astp build-security-graph .\.astp\target-registry.yaml `
  --output .\.astp\security-graph.yaml

astp build-hypotheses .\.astp\security-graph.yaml `
  --output .\.astp\hypotheses.yaml
```

See `docs/M2_7_REDIRECT_SAFE_TARGET_EXPANSION.md` through
`docs/M3_6_REPORTING_RETEST.md` and `docs/NEXT_STEPS.md`.


## M3.7–M4.6 control-plane expansion

See `RELEASE_NOTES_M3_7_M4_6.md` for the permit broker, durable planner state, result interpreter, bounded surface mapper, adapter registry, proof-verifier contracts, autonomy-session preparation, budgets, prioritization, and safe web-posture analysis.

## M4.7–M5.8 bounded autonomous observation

ASTP now includes its first bounded multi-action observation loop. It remains GET/HEAD-only and sequential, requires an explicit `--execute`, re-authorizes and signs every action independently, stops on policy drift or stale program status, reserves atomic session budgets, caps actions per origin, opens a circuit breaker on repeated failures, and writes a hash-linked execution trace. See `RELEASE_NOTES_M4_7_M5_8.md` and `docs/M4_7_M5_8_FIELD_TEST.md`.
## M5.9–M6.8 bounded evidence-driven iteration

ASTP can feed completed observations into a session-bound registry, re-plan only deterministically safe candidates, enforce discovery depth, and suppress duplicate actions durably. HEAD observations escalate to GET only when a declared evidence requirement needs a body, and the follow-up still requires a fresh permit.

The block also defines a non-state-changing web posture catalog, proof-specific verification plans, finding retest lifecycle, fair multi-program scheduling, and strict isolation contracts for future container workers. None of these control-plane objects authorizes or performs network execution.

## Offline assessment pipeline (M6.9–M7.9)

ASTP can now turn stored, integrity-checked HTTP evidence into a technology fingerprint, conservative protocol/posture signals, eligible finding candidates, correlated findings, and a Markdown assessment report without performing additional network requests.

```powershell
astp assess `
  .\engagements\smartfit.yaml `
  .\examples\test-observation.yaml `
  .\.astp\smartfit-target-registry.yaml `
  --evidence-dir .\.astp\evidence `
  --output .\reports\smartfit.md
```

This command is offline. Any future target-side action identified by the assessment still requires current policy authorization and a fresh execution permit.

## M8.0–M9.4 assessment integrity and review layer

ASTP can now fuse repeated signal confidence without changing proof state, inventory JavaScript
references from stored evidence, model permit-gated DNS/TLS worker capabilities, keep authenticated
secrets as non-exportable references, queue verification work for review, checkpoint assessment
progress, trace evidence-to-report lineage, calculate contextual non-CVSS ranking inputs, and
assemble integrity-bound review/portable assessment artifacts. These features do not introduce a
new target-network execution path.

## M9.5-M11.0

ASTP now includes offline DNS/TLS evidence derivation, static JavaScript analysis, reviewed verification brokering, durable worker job/receipt state, assessment resume/quarantine controls, risk fusion, publication integrity, readiness, and explicit closure gates.

## M11.1-M12.6 — Multi-capability execution boundary

ASTP now has an exact capability-action model and a second signed binding layer for
non-HTTP network observations. DNS and TLS observations can be executed only when an
existing policy-issued execution permit is still valid, a capability grant binds that
permit to the exact action, and the operator explicitly opts in to the single action.
The underlying execution permit is consumed exactly once before network I/O.

The current safe autonomous ceiling remains observational: HTTP GET/HEAD, DNS lookup,
and TLS handshake. Exploit payloads, brute force, credential attacks, state-changing
methods, and intrusive validation remain outside autonomous execution.

## Authenticated assessment boundary (M12.7-M14.4)

ASTP now supports origin-bound authenticated HTTP observation using runtime secret references. Credentials are injected only at the transport boundary and are not persisted in assessment plans or evidence. The same signed permit lifecycle remains mandatory.

Current full pentest status can be inspected with:

```powershell
astp pentest-completion
```

The safe and authenticated observation loops are end-to-end, but full pentest readiness remains false until isolated browser execution, broad vulnerability-specific verification, permit-gated external tool workers, and operator-gated high-risk workflows are complete.

## M14.5-M16.4 — operational verification bridge

ASTP now has an executable, read-only two-identity authorization differential path, a safe verification dispatcher contract with durable results and retest outcomes, runtime probes for browser and external adapters, and an explicit operator-only gate for state-changing actions. Browser and external tool execution remain capability-gated and are not considered bundled/ready until their isolated runtimes are available and permit consumption is enforced at the worker boundary.

### M16.5-M18.4
Adds permit-consumed browser/external worker boundaries, verifier/proof catalogs, runtime isolation declarations, and a bounded assessment coordinator. Full pentest readiness remains intentionally false.

## M18.5-M20.4 — Verification depth and coordinator gates

ASTP now derives conservative verifier signals from stored HTTP evidence, can propose bounded follow-up actions without bypassing policy, enforces sequential coordinator stage prerequisites, and distinguishes worker boundaries from real bundled/field-tested runtimes. Full pentest readiness remains false until broad active verification and physical browser/tool runtimes close.

### M24.5-M26.4 executable worker bridge

ASTP now has fixed-argument compilers for bounded Nmap/Nuclei/ZAP modes, shell-free bounded subprocess primitives, permit-before-I/O browser/tool worker bridges, hash-bound worker receipt evidence, and runtime qualification gates. These primitives do not by themselves make the physical runtimes field-ready.

### M26.5-M28.4

ASTP now includes runtime qualification bundles, a shell-free worker supervisor plan, worker-receipt registration into the hash-linked Evidence Store, bounded verification scheduling, and an adaptive CONTINUE/REPLAN/STOP coordinator loop. These controls remain policy-first and do not grant the coordinator direct network authority.
