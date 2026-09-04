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
