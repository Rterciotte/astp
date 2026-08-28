# Architecture — Milestone 0

## Principle

ASTP is not a wrapper around scanners. It is a policy and context engine that can use
scanners as sensors.

The critical invariant is:

```text
Planner -> Policy evaluation -> Execution permit -> Adapter/worker -> Evidence
```

There must never be a supported path like:

```text
Planner -> shell/tool directly
```

## Core domain

### Engagement

The authorized testing contract. It owns scope, method permissions and constraints.

### ScopePolicy

Contains allowed and denied rules. Denials override allows.

### TestDefinition

Describes a security hypothesis independently of the tool that may eventually perform it.
It includes risk class, preconditions/context and evidence requirements.

### EvaluationResult

A deterministic decision:

- `ALLOW`
- `DENY`
- `APPROVAL_REQUIRED`
- `INSUFFICIENT_CONTEXT`

## Runtime split

The long-term architecture intentionally supports two execution environments:

1. Native Windows services for developer-friendly core work.
2. Isolated Linux workers through WSL2/Docker for Linux-centric security tooling.

Adapters must normalize tool input/output; tools must never become the system of record.

## Safety boundary

Milestone 0 has no network execution component. This is intentional. Before network workers
exist, the project needs tests proving scope precedence, risk classification and context
requirements.
