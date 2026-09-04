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
    -> lifecycle lock consumes permit exactly once
    -> worker performs one bounded GET/HEAD
    -> worker writes redacted evidence
    -> audit append under lock
```

The permit is consumed before the network connection opens. This intentionally favors safety over
retry convenience: a timeout or transport failure requires a newly issued permit.

Redirects are never followed in M2. They are recorded and classified only.

## Runtime split

The long-term architecture intentionally supports two execution environments:

1. native Windows services for developer-friendly core work;
2. isolated Linux workers through WSL2/Docker for Linux-centric security tooling.

Adapters must normalize tool input/output; tools must never become the system of record.

## Current trust limitations

M2's lifecycle and audit locks are suitable for the local single-host development boundary, not a
distributed trust boundary. Shared-secret HMAC also means any verifier with the secret can mint a
permit. Before distributed workers, migrate to asymmetric signatures and transactional shared
lifecycle/audit storage where workers receive verification capability but not signing authority.
