# ASTP — Automated Security Testing Platform

ASTP is a security-testing assistant built around one simple rule: **nothing should touch a target unless the action is inside the authorized scope and has passed ASTP's safety gates**.

It is designed for bug bounty work, authorized pentests, security labs, and — beginning with the CTF foundation — challenge environments whose rules explicitly allow automation and AI assistance.

You do not need to be an experienced security professional to understand the workflow. ASTP separates the process into small steps and records what happened at each step. The tool can help beginners learn the order of a professional assessment while still giving experienced users detailed control over permits, evidence, budgets, workers, and reports.

> **Important:** ASTP does not give permission to test a system. You must already have authorization from the owner, a bug bounty program, a lab, or a CTF's rules. When in doubt, do not execute a network action.

## What ASTP does

In plain language, ASTP can:

- collect and normalize the rules of an authorized bug bounty program;
- turn those rules into a machine-checkable engagement;
- discover possible targets from evidence without automatically requesting them;
- rank and plan safe observations;
- require a fresh signed permit before a network action;
- perform bounded HTTP observations and preserve evidence;
- keep raw response bodies only when you explicitly request that retention;
- analyze stored headers and JavaScript **offline**;
- build graphs, hypotheses, finding candidates, retest plans, and reports;
- enforce request budgets, rate limits, policy freshness, audit chains, and resumability;
- inventory CTF challenge files locally while respecting rules about AI, automation, and network access.

ASTP deliberately distinguishes **a clue** from **a confirmed vulnerability**. A missing header, a JavaScript route, or an interesting URL is evidence to review — not proof of a security flaw.

## The basic idea

```text
Authorization / program rules
        ↓
Scope and policy review
        ↓
Targets and evidence
        ↓
Planning and prioritization
        ↓
Fresh signed permit
        ↓
Bounded worker action
        ↓
Evidence + integrity checks
        ↓
Offline analysis
        ↓
Findings / retest / report
```

A discovered URL never becomes permission by itself. If offline analysis discovers another endpoint, that endpoint must return to the normal scope → policy → permit process before ASTP may contact it.

# 1. Installation on Windows

ASTP currently targets Python 3.12 or newer. The normal development environment is Windows 11 with PowerShell.

Clone or extract the repository, open PowerShell in the repository root, and create a virtual environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

Check the local setup without making a network request:

```powershell
python -m astp.cli doctor
```

Run the full project validation suite:

```powershell
ruff check . --fix
black .
ruff check .
pytest
.\scripts\validate.ps1
```

For additional Windows notes, see `docs/WINDOWS_SETUP.md`.

# 2. The recommended workflow for bug bounty / authorized pentest

The commands below are intentionally shown in the order a new user should normally encounter them. You will not need every advanced command for every assessment.

## Step 1 — Check ASTP itself

### `doctor`

Checks the local Python/tool setup. It does not contact a target.

```powershell
python -m astp.cli doctor
```

## Step 2 — Bring authorization into ASTP

There are two common paths.

### Path A: bug bounty program already open in your browser

ASTP's Browser Companion is designed to read the program page that **you are already authenticated to view**. ASTP does not need to store the platform password.

### `browser-intake-server`

Starts the local loopback service used by the Browser Companion.

```powershell
python -m astp.cli browser-intake-server --help
```

### `programs`

Shows bug bounty programs discovered/synchronized into the local workspace.

```powershell
python -m astp.cli programs --help
```

### `select-programs`

Marks the program or programs you want to work with.

```powershell
python -m astp.cli select-programs --help
```

### `import-program`

Normalizes captured program rules into ASTP's program format while keeping their provenance.

```powershell
python -m astp.cli import-program --help
```

### `review-program`

Lets the operator resolve policy ambiguities explicitly. ASTP must not invent missing program rules.

```powershell
python -m astp.cli review-program --help
```

### `attest-program-status`

Records a short-lived statement that the program is currently online/available, bound to the reviewed program revision.

```powershell
python -m astp.cli attest-program-status --help
```

### `compile-program`

Turns the reviewed bug bounty program into an ASTP engagement that the policy engine can evaluate.

```powershell
python -m astp.cli compile-program --help
```

### `portfolio-plan`

If you work with more than one reviewed bug bounty program, this creates a fair local portfolio plan. Each program keeps its own policy, rate and evidence namespace. The command does not make requests.

```powershell
python -m astp.cli portfolio-plan .\programs\program-a.yaml .\programs\program-b.yaml `
    --output .\portfolio-plan.yaml
```

### Path B: a manually prepared engagement

### `compile-scope`

Compiles human-readable scope rules into a conservative structured engagement.

```powershell
python -m astp.cli compile-scope --help
```

### `show-engagement`

Validates and displays an engagement file.

```powershell
python -m astp.cli show-engagement .\engagements\your-engagement.yaml
```

## Step 3 — Define and check the intended security test

### `validate-test-dsl`

Checks a Security Test DSL definition. Validation alone does not execute anything.

```powershell
python -m astp.cli validate-test-dsl --help
```

### `evaluate-test`

Shows whether a test would be allowed for a target. It is policy evaluation only.

```powershell
python -m astp.cli evaluate-test --help
```

### `authorize-test`

Produces a more explicit auditable authorization decision, still without executing the test.

```powershell
python -m astp.cli authorize-test --help
```

## Step 4 — Work with known/discovered targets

### `discover-targets`

Reads existing evidence and extracts redirect/link candidates. It does **not** request those candidates.

```powershell
python -m astp.cli discover-targets --help
```

### `merge-targets`

Adds candidates to the provenance-preserving target registry and deduplicates them.

```powershell
python -m astp.cli merge-targets --help
```

### `prioritize-targets`

Ranks already-known targets using deterministic heuristics. A high score is not authorization.

```powershell
python -m astp.cli prioritize-targets --help
```

### `map-surface`

Builds a bounded map from targets ASTP already knows. It does not crawl the internet by itself.

```powershell
python -m astp.cli map-surface --help
```

### `build-frontier`

Creates a bounded crawl/observation frontier from known targets without requesting them.

```powershell
python -m astp.cli build-frontier --help
```

## Step 5 — Plan work before executing it

### `plan-observations`

Builds a deterministic policy-evaluated observation plan. It does not issue permits or make requests.

```powershell
python -m astp.cli plan-observations --help
```

### `choose-observation-method`

Chooses HEAD-first or GET according to the evidence requirement.

```powershell
python -m astp.cli choose-observation-method --help
```

### `build-work-queue`

Creates a fair control-plane queue from authorizable plan items. Queue entries still require fresh permits.

```powershell
python -m astp.cli build-work-queue --help
```

### `init-planner-state`

Creates durable planner state so interrupted work can be tracked safely.

```powershell
python -m astp.cli init-planner-state --help
```

### `planner-item-status`

Displays the durable state of one planned queue item.

```powershell
python -m astp.cli planner-item-status --help
```

## Step 6 — Issue a fresh permit

For normal queued work, prefer the broker.

### `broker-permit`

Re-evaluates one queued action against current policy and issues a short-lived signed permit. It does not execute the action.

```powershell
python -m astp.cli broker-permit --help
```

Lower-level permit commands are available for development and diagnostics:

### `issue-permit`
Issues a permit for an exact action after authorization.

### `verify-permit`
Checks signature, freshness, policy binding, and exact requested action.

### `consume-permit`
Consumes a permit once without performing the network action; useful for lifecycle testing.

### `revoke-permit`
Revokes an unconsumed local permit.

### `permit-status`
Shows local permit lifecycle state.

### `runtime-permit-status`
Shows permit state in the transactional worker database.

### `revoke-runtime-permit`
Revokes a permit in that runtime database.

Use `python -m astp.cli <command> --help` for the exact arguments.

## Step 7 — Perform a bounded observation

### `observe-http`

Performs exactly the permit-gated GET/HEAD observation described by the permit. Redirects are evidence, not automatic permission to continue.

```powershell
python -m astp.cli observe-http --help
```

By default ASTP keeps a redacted preview rather than the raw response body. If the engagement allows retention and you need exact bytes for offline analysis, explicitly add:

```text
--persist-body
```

The stored body becomes a manifest-registered `.body.bin` artifact.

### `observe-authenticated-http`

Use this only when the authorized test needs a logged-in identity. The session YAML stores **references** to secrets (for example an environment-variable name), not the password/token itself. The exact request still needs a fresh permit, and authenticated evidence is always marked sensitive.

```powershell
python -m astp.cli observe-authenticated-http --help
```

### `run-observation-session`

Runs a bounded sequential session with one fresh permit per request and durable budgets/stops.

```powershell
python -m astp.cli run-observation-session --help
```

Use this only after the plan, policy, operational-status, and budget inputs are ready.

## Step 8 — Verify the evidence

### `verify-evidence`
Checks the canonical integrity hash of an HTTP evidence record.

### `verify-evidence-manifest`
Checks the hash-linked manifest and, by default, the files registered in it.

### `verify-audit`
Checks the local hash-linked authorization/audit chain.

### `verify-execution-trace`
Checks the hash-linked autonomous/session execution trace.

### `export-evidence-bundle`
Exports verified evidence and its manifest as a portable bundle.

### `verify-evidence-bundle`
Verifies a portable evidence bundle after transfer.

These commands are offline integrity operations.

## Step 9 — Analyze what was already collected

If you want ASTP to summarize all stored HTTP/body evidence in one offline pass, start with:

### `consume-evidence`

Reads a directory of stored evidence, verifies what it can, recognizes HTML/JavaScript/JSON responses, and lists useful clues such as links, API paths, redirects, and JavaScript route hints. **It never requests the discovered targets.**

```powershell
python -m astp.cli consume-evidence `
    .\.astp\your-assessment\evidence `
    --output .\.astp\your-assessment\evidence-consumers.yaml
```

You can also inspect individual evidence records with the commands below.

### `interpret-observation`

Turns stored HTTP evidence into conservative signals. It makes no request.

### `analyze-web-posture`

Reviews headers already captured in evidence. Signals such as missing headers are not automatically vulnerabilities.

### `analyze-javascript`

Analyzes an already-retrieved JavaScript/body artifact **offline**. When the matching HTTP evidence is supplied with `--evidence`, ASTP verifies the artifact's size and SHA-256 before binding the analysis to the evidence ID, permit ID, and source target.

```powershell
python -m astp.cli analyze-javascript `
    .\.astp\path\evidence\app.body.bin `
    --evidence .\.astp\path\evidence\app.json `
    --output .\.astp\path\javascript-analysis.yaml
```

Discovered routes, URLs, source-map hints, frameworks, or network-call markers are **clues only**. The analyzer never requests them.

The older standalone bridge remains available:

```powershell
python -m astp.javascript_static_cli .\path\artifact.js --output .\analysis.yaml
```

Prefer `analyze-javascript` for new workflows because it can verify evidence binding.

### `plan-verification`

Looks at stored HTTP evidence and prepares conservative verifier proposals. It does not execute the proposals. Any active verification still goes through policy review and a fresh permit; state-changing verifier families remain operator-gated.

```powershell
python -m astp.cli plan-verification .\.astp\evidence `
    --output .\verification-plan.yaml
```

### `feedback-evidence`

Feeds stored evidence back into the registry. New targets still need normal policy evaluation and a new permit.

## Step 10 — Build reasoning structures

### `build-security-graph`
Builds a provenance graph from targets and evidence.

### `build-hypotheses`
Creates conservative hypotheses from the graph. A hypothesis is not a finding and is not authorization.

## Step 11 — Turn evidence into findings and an assessment

For most users, the easiest path is the consolidated offline command:

### `assess-stored-evidence`

Runs ASTP's stored-evidence assessment pipeline in one step: integrity checking, technology fingerprinting, signal normalization, conservative finding candidates, correlation, and a Markdown report. It performs no network request.

```powershell
python -m astp.cli assess-stored-evidence `
    .\.astp\your-assessment\evidence `
    .\.astp\your-assessment\target-registry.yaml `
    .\engagement.yaml `
    .\test.yaml `
    --session-id my-assessment-01 `
    --output-dir .\.astp\your-assessment\analysis
```

If you prefer to work stage by stage:

### `synthesize-findings`

Reads the output from `consume-evidence` and creates only evidence-eligible correlated findings. Informational clues are not promoted into vulnerabilities.

```powershell
python -m astp.cli synthesize-findings `
    .\.astp\your-assessment\evidence-consumers.yaml `
    --output .\.astp\your-assessment\findings.yaml
```

### `correlate-findings`
Deduplicates a manually prepared list of evidence-backed finding candidates without increasing their proof level.

### `render-report`
Creates a Markdown security report and retest checklist from correlated findings.

A retest item is only a plan. When you actually retest it, current policy and a fresh permit are required again.

## Step 12 — Finalize a portable assessment package

### `finalize-assessment`

Packages the report, findings, and evidence manifest, records SHA-256 hashes, checks that the declared number of network actions matches consumed permits, and immediately verifies the package. It is an offline finalization step.

```powershell
python -m astp.cli finalize-assessment `
    .\.astp\your-assessment\analysis\findings.yaml `
    .\engagement.yaml `
    .\.astp\your-assessment\analysis\report.md `
    .\.astp\your-assessment\evidence-manifest.jsonl `
    --output-dir .\.astp\your-assessment\final-package `
    --network-actions 1 `
    --permits-consumed 1
```

## Step 13 — Verify the whole Bug Bounty v1 assessment

### `bug-bounty-v1-acceptance`

Use this after you have a reviewed program, compiled engagement, populated target registry, stored evidence, evidence manifest, audit log, and final assessment package. It checks that they belong to one coherent assessment chain.

The command is offline. It does not contact the target. For a real Bug Bounty v1 field acceptance, it requires at least one recorded authorized network action and matching permit consumption.

```powershell
python -m astp.cli bug-bounty-v1-acceptance `
    .\programs\your-program.yaml `
    .\engagement.yaml `
    .\.astp\your-assessment\target-registry.yaml `
    .\.astp\your-assessment\evidence `
    .\.astp\your-assessment\evidence-manifest.jsonl `
    .\.astp\your-assessment\audit.jsonl `
    .\.astp\your-assessment\final-package `
    --output .\.astp\your-assessment\bug-bounty-v1-acceptance.yaml
```

A `PASS` means the stored chain is internally consistent. It does not make a new security claim and it does not replace the rules of the bug bounty program.

## Step 14 — Session status, interruption, and recovery

### `init-session-ledger`
Creates the durable request/action budget ledger.

### `session-ledger-status`
Shows current counters.

### `snapshot-policy`
Captures the policy digest used to detect policy drift.

### `session-report`
Summarizes counters and trace events without network access.

### `resume-session-check`
Determines which interrupted queue items may safely return to planning.

### `recovery-acceptance`

Runs ASTP's local recovery acceptance matrix. It checks checkpoint integrity, policy-drift behavior, tamper rejection, and the important interruption boundaries. It never replays a request and performs no network activity.

```powershell
python -m astp.cli recovery-acceptance `
    .\engagement.yaml `
    .\test.yaml `
    --output .\recovery-acceptance.yaml
```

For beginners, the important rule is simple: **after a crash or interruption, ASTP does not assume it may retry a network action**. A retry returns to planning and needs a fresh permit.

## Step 15 — Adapter and autonomy diagnostics

### `show-adapters`
Lists registered execution adapters and their safety contracts.

### `check-adapter`
Checks whether a test definition is compatible with an adapter. It does not execute it.

### `prepare-autonomy-session`
Prepares a bounded autonomy session plan. Preparation does not execute network actions.

# 3. CTF mode — foundation

CTF mode is now in its first implementation stage. The current command performs **intake and local artifact inventory only**; it is not yet a general autonomous solver.

### `ctf-intake`

Reads a challenge YAML, checks whether its rules allow AI/automation, validates its network policy, and hashes declared local files. It performs no network action.

Example `challenge.yaml`:

```yaml
schema_version: '1'
id: example-reverse-01
title: Example reverse challenge
category: reverse
artifacts:
  - challenge.bin
flag_pattern: 'FLAG\{.*\}'
allow_ai: true
allow_automation: true
network_policy: disabled
```

Run:

```powershell
python -m astp.cli ctf-intake .\challenge.yaml --output .\ctf-intake.yaml
```

If an event forbids AI or automation, ASTP records that as a blocker. Event rules always take precedence.

See `docs/CTF_MODE_ROADMAP.md` for the remaining solver architecture.

# 4. Specialized field/preflight entry points

ASTP also contains specialized module entry points used by later field-validation milestones. They are intentionally separate from the beginner workflow and should normally be used with their release documentation or field scripts:

```text
python -m astp.program_preflight
python -m astp.program_field_assessment
python -m astp.assessment_operational_lease
python -m astp.field_assessment_provenance
python -m astp.field_execution_status
python -m astp.field_redirect_continuation
python -m astp.full_pentest_readiness
python -m astp.priority_work_queue
python -m astp.physical_probe_evaluator
python -m astp.physical_qualification_runner
```

Before using one directly, run:

```powershell
python -m <module-name> --help
```

The repository's `scripts/field-tests/` and `scripts/programs/` directories contain controlled workflows built around these components.

# 5. Complete main CLI command reference

For convenience, every command currently exposed by `python -m astp.cli` is listed here. The recommended order is the workflow above; this alphabetical-style reference is for finding a command quickly.

| Command | What it does in simple terms |
|---|---|
| `doctor` | Checks the local ASTP setup; offline. |
| `browser-intake-server` | Receives authorized program information from the Browser Companion on loopback. |
| `programs` | Shows synchronized bug bounty programs. |
| `select-programs` | Chooses active programs. |
| `import-program` | Normalizes program rules with provenance. |
| `review-program` | Resolves explicit policy ambiguities. |
| `attest-program-status` | Records fresh online/offline program status. |
| `compile-program` | Converts a reviewed program to an engagement. |
| `portfolio-plan` | Creates an isolated fair plan for multiple reviewed programs; offline. |
| `compile-scope` | Compiles manually supplied scope rules. |
| `show-engagement` | Validates/displays an engagement. |
| `validate-test-dsl` | Validates a security test definition; offline. |
| `evaluate-test` | Evaluates policy without execution. |
| `authorize-test` | Produces an auditable authorization decision. |
| `discover-targets` | Extracts target candidates from stored evidence; offline. |
| `merge-targets` | Merges candidates into the registry; offline. |
| `prioritize-targets` | Ranks known targets; offline. |
| `map-surface` | Maps known surface; offline. |
| `build-frontier` | Builds bounded frontier; offline. |
| `plan-observations` | Builds policy-evaluated plan; offline. |
| `choose-observation-method` | Chooses HEAD/GET strategy; offline. |
| `build-work-queue` | Builds fair authorizable queue; offline. |
| `init-planner-state` | Initializes durable planner state. |
| `planner-item-status` | Shows one planner item's state. |
| `broker-permit` | Re-authorizes queued action and signs a permit; no execution. |
| `issue-permit` | Lower-level exact-action permit issuance. |
| `verify-permit` | Verifies a permit. |
| `consume-permit` | Consumes a permit without network execution. |
| `revoke-permit` | Revokes local permit. |
| `permit-status` | Shows local permit state. |
| `runtime-permit-status` | Shows transactional runtime permit state. |
| `revoke-runtime-permit` | Revokes transactional runtime permit. |
| `observe-http` | Performs one permit-gated bounded GET/HEAD. |
| `observe-authenticated-http` | Performs one permit-gated authenticated GET/HEAD using secret references; evidence is sensitive. |
| `run-observation-session` | Runs bounded sequential permit-gated observations. |
| `verify-evidence` | Verifies HTTP evidence integrity. |
| `verify-evidence-manifest` | Verifies manifest chain and artifacts. |
| `verify-audit` | Verifies audit chain. |
| `verify-execution-trace` | Verifies session execution trace. |
| `export-evidence-bundle` | Exports portable verified evidence. |
| `verify-evidence-bundle` | Verifies exported bundle. |
| `consume-evidence` | Consumes stored HTML/JS/JSON/redirect evidence and lists non-authorizing clues; offline. |
| `interpret-observation` | Interprets stored evidence; offline. |
| `analyze-web-posture` | Reviews captured HTTP headers; offline. |
| `analyze-javascript` | Reviews a local JS/body artifact; offline. |
| `plan-verification` | Builds non-executing verifier proposals from stored evidence; offline. |
| `feedback-evidence` | Returns stored evidence to discovery/planning; offline. |
| `build-security-graph` | Builds target/evidence graph; offline. |
| `build-hypotheses` | Builds conservative hypotheses; offline. |
| `assess-stored-evidence` | Runs the consolidated stored-evidence assessment and report pipeline; offline. |
| `synthesize-findings` | Turns eligible normalized signals into conservative findings; offline. |
| `correlate-findings` | Deduplicates finding candidates without proof inflation. |
| `render-report` | Renders evidence-oriented Markdown report. |
| `finalize-assessment` | Builds and verifies a portable final assessment package; offline. |
| `bug-bounty-v1-acceptance` | Checks the complete stored bug bounty assessment chain and field-action accounting; offline. |
| `init-session-ledger` | Creates durable session budget ledger. |
| `session-ledger-status` | Shows session counters. |
| `snapshot-policy` | Captures policy digest for drift checks. |
| `session-report` | Summarizes a session; offline. |
| `resume-session-check` | Checks safe resumption after interruption. |
| `recovery-acceptance` | Exercises fail-closed recovery rules and crash boundaries; offline. |
| `show-adapters` | Lists adapters and safety contracts. |
| `check-adapter` | Checks test/adapter compatibility; offline. |
| `prepare-autonomy-session` | Prepares bounded autonomy; no execution. |
| `ctf-intake` | Validates CTF rules and inventories local challenge files; offline. |

For exact options of any command:

```powershell
python -m astp.cli COMMAND --help
```

# 6. Files and folders you will see

- `.astp/` — local runtime state, evidence, manifests, ledgers, and assessment artifacts. Usually do not commit this folder.
- `programs/` — normalized/reviewed bug bounty program definitions.
- `engagements/` — engagement examples/definitions.
- `src/astp/` — ASTP source code.
- `tests/` — automated tests.
- `scripts/` — validation and controlled field workflows.
- `docs/` — architecture and historical engineering documentation.
- `docs/release/` — milestone/release change notes. **New milestone change READMEs belong here.**
- `browser-companion/` — browser-side intake component.
- `labs/` — controlled local lab material.
- `workers/` — worker/runtime support.

# 7. How ASTP describes confidence

ASTP avoids turning weak signals into strong claims. Findings progress through explicit proof states such as:

```text
SUSPECTED → LIKELY → VERIFIED → IMPACT_CONFIRMED
```

A tool result does not automatically move a finding forward. The required evidence must exist.

# 8. Safety rules worth remembering

1. **Authorization comes from the owner/program, not from ASTP.**
2. **Discovery is not execution.** A URL found in HTML or JavaScript is only a candidate.
3. **A plan is not a permit.**
4. **A permit is exact and short-lived.**
5. **A consumed/expired permit is not reused.**
6. **Redirects require their own authorization path.**
7. **Raw response retention is opt-in.** It may contain sensitive data.
8. **Offline analyzers never retrieve the URLs they discover.**
9. **Signals are not automatically vulnerabilities.**
10. **CTF/event rules override automation.** If AI or automation is prohibited, ASTP must not autonomously solve the challenge.

# 9. Project status

ASTP already contains a large policy-first pentest engine and has completed a real bounded bug-bounty HTTP field observation with permit consumption, exact response-body persistence, SHA-256 verification, and manifest registration.

The current completion push now also exposes isolated multi-program portfolio planning, permit-gated authenticated observation using secret references, and a unified non-executing active-verifier planning pass. The next work focuses on crash/recovery acceptance and the complete bug-bounty v1 acceptance run before deeper CTF solver expansion.

The authoritative forward plan is `docs/NEXT_STEPS.md`. Milestone-specific change notes are kept in `docs/release/`.
