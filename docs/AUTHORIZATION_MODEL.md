# Authorization Model — Milestone 1.2

ASTP does not treat authorization as a single boolean. A test is authorized only after a sequence
of explicit gates passes.

## Decision flow

```text
target scope
    -> asset constraints
    -> required test context
    -> risk policy
    -> effective rate limit
    -> ALLOW / DENY / APPROVAL_REQUIRED / INSUFFICIENT_CONTEXT
```

No gate may widen permission granted by another gate. Explicit deny rules always win.

## Bounded approval artifacts

The old development-only `--approved` boolean is no longer accepted by `authorize-test`.
Conditional scope and approval-gated risk classes require an `ApprovalArtifact` loaded from YAML.

An approval is bound to:

- one engagement;
- one or more target rules;
- an issue and expiry time;
- an actor;
- optional test IDs;
- optional risk classes;
- optional identities;
- an optional maximum request rate.

The model is frozen after validation. This provides in-process immutability, but the YAML file is not
yet cryptographically signed. Signing and content-addressed execution permits are later milestones.

## Asset-level constraints

An engagement may attach constraints to a target selector:

- allowed path prefixes;
- denied path prefixes;
- allowed ports;
- allowed HTTP methods;
- allowed logical identities;
- per-asset maximum requests per second.

When more than one matching asset constraint exists, every matching constraint is enforced. ASTP
therefore composes restrictions conservatively rather than selecting the most permissive rule.

## Rate limits

The effective request rate is the minimum of all applicable limits:

1. engagement-wide limit;
2. matching asset-level limits;
3. matching approval-artifact limits.

A requested rate above that effective limit is denied.

## Important invariant

An approval artifact can satisfy a condition, but it cannot override an explicit deny rule.
