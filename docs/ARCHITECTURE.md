# Architecture — policy-first foundation

## Principle

ASTP is not a wrapper around scanners. It is a policy, authorization, execution-boundary, and
evidence system that can use specialized tools as sensors.

The critical invariant is:

```text
Planner -> Policy evaluation -> Signed permit -> Lifecycle gate -> Adapter/worker -> Evidence
```

There must never be a supported path like:

```text
Planner / LLM -> shell, scanner, browser, or network directly
```

## Core domain

### Engagement

The authorized testing contract. It owns scope, method permissions, approvals, and constraints.

### ScopePolicy

Contains allowed, denied, and approval-required rules. Explicit denial wins.

### TestDefinition

Describes a security hypothesis independently of the tool that may eventually perform it. It
includes risk class, context requirements, and evidence requirements.

### AuthorizationResult

A deterministic gate-based decision:

- `ALLOW`
- `DENY`
- `APPROVAL_REQUIRED`
- `INSUFFICIENT_CONTEXT`

### Execution permit

A short-lived signed capability bound to the current engagement/test policy and an exact requested
action. M1.4 adds key IDs, revocation, replay protection, and hash-linked audit state.

### Worker

A worker receives a permit and independently verifies the action before performing anything with an
external side effect. M2 introduces the first worker: one observation-only HTTP `GET` or `HEAD`.

### Evidence

Workers persist bounded evidence rather than returning unstructured scanner output as truth. M2
creates redacted HTTP observation evidence with a canonical SHA-256 integrity hash.

## Local M2 execution boundary

```text
Operator / future planner
    -> authorize
    -> issue permit
    -> worker verifies signature + freshness + current policy
    -> capability compatibility check
    -> SQLite transaction checks lifecycle + rate admission
    -> transaction reserves rate slot and consumes permit atomically
    -> worker performs one bounded GET/HEAD
    -> worker writes redacted evidence
    -> audit append
```

A rate-limit rejection rolls back admission and leaves the permit available. Once admission commits,
the permit is consumed before the network connection opens. A later timeout or transport failure
therefore requires a newly issued permit.

Redirects are never followed in M2. They are recorded and classified only.

## Runtime split

The long-term architecture intentionally supports two execution environments:

1. native Windows services for developer-friendly core work;
2. isolated Linux workers through WSL2/Docker for Linux-centric security tooling.

Adapters must normalize tool input/output; tools must never become the system of record.

## Current trust limitations

M2.4's SQLite worker runtime and local audit storage are suitable for the single-host development
boundary, not a distributed trust boundary. Shared-secret HMAC also means any verifier with the secret can mint a
permit. Before distributed workers, migrate to asymmetric signatures and transactional shared
lifecycle/audit storage where workers receive verification capability but not signing authority.

## Program intake boundary (M2.5)

Program intake is separate from target execution. The browser companion may read only the
active page after an explicit user gesture and cannot execute a security test. Captured
program material is normalized into `BugBountyProgram`; only a reviewed program can compile
into `Engagement`, and execution still follows the existing permit-gated worker path.

```text
Browser Companion -> BrowserCapture -> BugBountyProgram -> Engagement
                                                     ↓
                                  authorization -> permit -> worker -> evidence
```


## Authenticated program discovery boundary (M2.5.1)

`Browser Companion -> authenticated platform pages -> Program Catalog` is a control-plane path.
It is intentionally separate from target Browser Workers. Program synchronization may reuse the
browser's existing login session but never exports session secrets to ASTP. Catalog selection may
contain multiple active programs, but future execution must keep a separate engagement, policy
digest, execution permit, rate budget, and evidence chain for every program.

## Browser intake protocol boundary (M2.5.2)

The Browser Companion and ASTP local intake service negotiate protocol version 2 over loopback.
The extension first validates the short-lived intake token through `/v1/health`, then uses explicit
`/v1/discover-programs` and `/v1/program-detail` contracts. Platform host access is granted by a
separate user gesture so a browser permission prompt cannot silently cancel discovery.

The companion may use the browser's existing authenticated session for navigation, but session
material is never exported to ASTP. Browser intake remains a control-plane operation and is kept
separate from target execution permits and workers.

## Policy readiness boundary (M2.5.3)

Program discovery selection is not execution authorization. An ACTIVE catalog program can remain
NEEDS_REVIEW. Only a normalized program with no unresolved blocking policy issues is READY for
engagement compilation. Operator-added numeric traffic limits and deny mappings are recorded as
review decisions with provenance and are never rewritten as platform-published rules.


## Program runtime gate (M2.6)

A READY bug-bounty program is compiled with an immutable binding to the source-policy SHA-256. If
policy requires the program to be online, authorization requires a fresh matching operational
attestation before semantic exclusion, risk, and rate gates may reach ALLOW. Signed permits are
bound to the resulting engagement policy digest and cannot outlive the operational attestation.
Program-recommended HTTP identity metadata is consumed by the bounded observation worker.

## Evidence-derived discovery boundary (M2.7–M2.9)

A worker response may reveal a redirect or link, but the response cannot authorize the destination.
ASTP converts discoveries into non-executable candidates. Deterministic safety checks run before the
candidate is stored in a provenance-preserving Target Registry.

```text
permit-gated evidence
    -> TargetCandidate(executable=false)
    -> deterministic target safety
    -> TargetRegistry
```

HTTPS downgrade, credentials in URLs, redacted targets and private/loopback/link-local literal
addresses are not auto-promotable. Out-of-scope targets may remain recorded as provenance but cannot
enter an authorizable observation plan.

## Planner and queue boundary (M3.0–M3.1)

The deterministic planner reuses the normal authorization engine. `ALLOW` means only that a proposed
action is *authorizable*. It does not create a permit and it does not call a worker. A multi-program
queue contains only authorizable proposals and preserves one fresh-permit requirement per item.

```text
Target Registry
    -> planner
    -> AuthorizationResult
    -> authorizable proposal
    -> work queue
    -> [future explicit permit broker]
    -> signed permit
    -> worker
```

Program boundaries are never merged. Queue fairness does not combine scope, rate, semantic-exclusion,
or operational-status authority across engagements.

## Test DSL boundary (M3.2)

Security Test DSL v0.1 describes intent independently of an execution adapter. It can be converted to
the existing runtime `TestDefinition`, but it never grants execution rights. Observation strategies
are restricted to passive or safe-active risk classes.

## Graph and hypothesis boundary (M3.3–M3.4)

The Security Graph stores relationships between assets, evidence and actions. Hypotheses are derived
control-plane objects. A hypothesis may suggest a next safe action, but explicitly records that policy
evaluation and a fresh permit are required.

```text
Evidence/Registry -> Security Graph -> Hypothesis Graph -> Planner -> Policy -> Permit
```

A hypothesis is neither a finding nor authorization.

## Evidence-driven iteration boundary (M5.9–M6.8)

Completed evidence may update only its engagement's registry. Newly discovered candidates pass deterministic safety and depth admission before the planner evaluates current policy. Durable action identities suppress repeats across sessions. A HEAD result may propose a GET only when declared proof needs body content; the proposal must still receive a fresh permit.

Safe-web catalog entries, verification plans, finding retests, and fair scheduling are control-plane descriptions. Container isolation contracts prohibit signing-key delivery and require permit verification for network-capable workers.

```text
Evidence -> session feedback -> safe/depth admission -> planner
       -> duplicate guard -> policy -> fresh permit -> isolated worker
```

## Proof and reporting boundary (M3.5–M3.6)

Findings use explicit proof states:

```text
SUSPECTED -> LIKELY -> VERIFIED -> IMPACT_CONFIRMED
```

Correlation deduplicates signals without promoting beyond the strongest supplied evidence state.
Reporting consumes correlated findings and emits a retest checklist. Retest entries are plans only;
each future retest must pass current policy and receive a fresh signed permit.

## M6.9–M7.9 assessment pipeline

The assessment layer consumes integrity-checked evidence and cannot bypass execution policy:

```text
permit-gated evidence
  -> fingerprint + protocol analyzers
  -> normalized signals
  -> finding-candidate eligibility gate
  -> proof-verifier registry
  -> durable finding/retest state
  -> assessment report
```

Evidence-driven replanning remains separate from execution. A newly discovered target or verification need is only a candidate action until it passes current policy and receives a fresh permit for a compatible worker.

## Assessment integrity and operator review (M8.0–M9.4)

The stored-evidence assessment path now has an integrity and review envelope:

```text
Evidence -> normalized signals -> confidence fusion -> candidate/proof pipeline
         -> lineage -> assessment manifest -> operator review -> portable artifact
```

Confidence fusion never upgrades a proof state. DNS/TLS capability definitions are contracts only
and still require execution permits before any future worker may use them. Secret material is modeled
as a non-exportable reference rather than embedded in plans or worker jobs. Worker job envelopes do
not carry signing keys, arbitrary mounts, or arbitrary network authority.

## M9.5-M11.0 integrity and closure layer

Stored transport evidence can be normalized into DNS/TLS provenance without new network access. Verification work must be reviewed before it becomes an authorization candidate. Worker jobs and result receipts are durably bound to action/permit identifiers. Assessment checkpoints, quarantine, session journals, finalization, publication, and closure all preserve explicit integrity gates.

## M11.1-M12.6: exact multi-capability execution

The execution chain for bounded DNS/TLS observation is now:

```text
Planner
  -> Policy authorization
  -> Signed execution permit
  -> Exact CapabilityAction
  -> Signed CapabilityGrant
  -> One-time permit consumption
  -> Capability worker
  -> Typed evidence
  -> Evidence manifest
```

`CapabilityGrant` is an additional exact-action binding, not a replacement for the
policy permit. A grant cannot extend the permit lifetime or target and a replayed permit
is rejected before a second network operation occurs.

The safe assessment profile exposes an explicit autonomous ceiling. It currently permits
only non-state-changing observation capabilities and requires a fresh permit for every
network action.

## M12.7-M14.4: authenticated execution boundary

Authenticated HTTP observation reuses the existing policy/permit/lifecycle/worker path. An `AuthSessionProfile` stores only `SecretReference` objects and exact allowed origins. Secret material is resolved at the transport boundary and is never serialized into plans or evidence.

```text
Engagement / Scope
       ↓
Policy authorization
       ↓
Signed execution permit
       ↓
AuthSessionProfile (references only)
       ↓
Runtime secret resolution
       ↓
Origin-bound authenticated transport
       ↓
HTTP observation worker
       ↓
Redacted evidence
```

Authorization differential tests now have a first-class plan requiring two distinct owned/permitted identities and a fresh permit per request. Browser and external scanner capabilities remain non-runtime-ready contracts until isolated workers are implemented. High-risk approvals bind to one exact action but never enable autonomous intrusive execution.

## M14.5-M16.4 operational verification bridge

The authorization workflow now supports two distinct owned identities with a fresh execution permit per request. Captured HTTP evidence is compared deterministically; equivalent successful responses are only a signal and never a verified authorization vulnerability without explicit foreign-object context. Even then, the initial verifier ceiling is `LIKELY`.

Safe verification execution is restricted to existing observation capabilities (`GET`, `HEAD`, DNS, and TLS) and must pass through an exact capability grant plus execution permit. Verification results are durable and retests remain human-resolved after new evidence is collected.

Browser and external adapter runtimes are deliberately separate from their contracts. Runtime discovery may report optional Playwright or adapter binaries as installed, but installation alone is not authority to execute. Redirects in browser observations require a new authorized action. External adapter jobs accept only named allowlisted modes and produce hash-bound receipts; arbitrary arguments are not accepted.

State-changing verification remains operator-controlled. An exact-action approval can permit an operator workflow, but `autonomous_execution_allowed` remains false.

## M16.5-M18.4 worker boundary
Browser and external adapter work now has an explicit permit-consumption-before-I/O boundary. Worker isolation forbids signing keys, arbitrary mounts/network, secret export, and shell execution by default. The coordinator is planning/state only unless execution is explicitly enabled by a higher-level reviewed workflow.

## M18.5-M20.4 — Verification depth and coordinator gates

ASTP now derives conservative verifier signals from stored HTTP evidence, can propose bounded follow-up actions without bypassing policy, enforces sequential coordinator stage prerequisites, and distinguishes worker boundaries from real bundled/field-tested runtimes. Full pentest readiness remains false until broad active verification and physical browser/tool runtimes close.

## M22.5-M24.4 — isolated runtime packaging boundary

ASTP now distinguishes an immutable runtime artifact, a launch envelope, a bounded worker protocol, and field qualification. A build blueprint or available binary does not make a runtime operational. Network-capable workers remain subordinate to exact-action permits, and coordinator feedback never grants network authority by itself.

## Executable worker bridge (M24.5-M26.4)

External tool execution is compiled from typed worker requests into fixed executable/argv pairs. Arbitrary CLI arguments and shell invocation are rejected. Permit consumption occurs before the injected worker executor or browser driver is called. Worker receipts are hash-normalized before entering downstream evidence processing. Runtime qualification remains a separate gate from code availability.

## M26.5-M28.4 — qualification and adaptive coordinator closure

The worker boundary now distinguishes executable code from field-qualified runtime evidence. Qualification bundles are exact-runtime-ID and artifact-digest bound and require negative-test evidence for permit-before-I/O, no-network-without-permit, shell rejection, signing-key isolation, bounded output, and an explicit field test.

Worker receipts may enter the Evidence Store only after permit consumption has been recorded. The adaptive coordinator may CONTINUE, REPLAN, or STOP, but never grants itself network authority; every network action still returns through policy and a fresh exact-action permit.

Full-pentest acceptance is a separate terminal gate and remains false until runtime qualification, broad active verification, adaptive-loop field validation, operator-gated state-changing validation, and a complete authorized end-to-end field test are all satisfied.

## Runtime enablement candidate (M28.5-M30.4)

The runtime boundary is now explicit: typed request -> policy/permit -> permit consumption -> bounded browser/tool I/O -> receipt -> Evidence Store -> coordinator. Browser redirects require a new authorization. Runtime bundling does not close readiness; field qualification remains a separate gate.

## M30.5–M32.4: field qualification and E2E rehearsal

Runtime installation, executable worker boundaries, and operational field qualification are
separate states. Worker receipts are accepted into assessment feedback only after engagement,
action, artifact digest, and permit-before-I/O checks pass. Active verifiers remain policy- and
permit-gated, and state-changing verifiers additionally require exact operator approval.

The offline end-to-end rehearsal covers intake through closure but never authorizes network
execution. Full v1 readiness remains gated on physical runtime field qualification, broad active
verification qualification, and an authorized end-to-end field test.
